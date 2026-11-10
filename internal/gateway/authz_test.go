package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/limiter"
)

func TestOriginal(t *testing.T) {
	cases := []struct {
		name    string
		p       proxy
		method  string
		target  string
		hdr     map[string]string
		want    string
		wantM   string
		wantErr bool
	}{
		{"envoy prefix stripped", envoy, "POST", "/authz/envoy/v1/generate", nil, "/v1/generate", "POST", false},
		{"envoy query dropped", envoy, "GET", "/authz/envoy/v1/generate/x?page=2", nil, "/v1/generate/x", "GET", false},
		{"envoy escapes decoded", envoy, "GET", "/authz/envoy/v1/%67enerate", nil, "/v1/generate", "GET", false},
		{"envoy ignores nginx header", envoy, "GET", "/authz/envoy/v1/generate", map[string]string{"X-Original-URI": "/v1/ping"}, "/v1/generate", "GET", false},
		{"nginx", nginx, "GET", "/authz/nginx", map[string]string{"X-Original-URI": "/v1/generate?x=1", "X-Original-Method": "POST"}, "/v1/generate", "POST", false},
		{"nginx raw escapes decoded", nginx, "GET", "/authz/nginx", map[string]string{"X-Original-URI": "/v1/%67enerate"}, "/v1/generate", "GET", false},
		{"nginx ignores traefik header", nginx, "GET", "/authz/nginx", map[string]string{"X-Original-URI": "/v1/generate", "X-Forwarded-Uri": "/v1/ping"}, "/v1/generate", "GET", false},
		{"nginx missing header", nginx, "GET", "/authz/nginx", nil, "", "", true},
		{"nginx bad escape", nginx, "GET", "/authz/nginx", map[string]string{"X-Original-URI": "/v1/%zz"}, "", "", true},
		{"nginx absolute uri", nginx, "GET", "/authz/nginx", map[string]string{"X-Original-URI": "http://x/v1"}, "", "", true},
		{"traefik", traefik, "GET", "/authz/traefik", map[string]string{"X-Forwarded-Uri": "/v1/generate?q=1", "X-Forwarded-Method": "DELETE"}, "/v1/generate", "DELETE", false},
		{"traefik ignores client X-Original-URI", traefik, "GET", "/authz/traefik", map[string]string{"X-Forwarded-Uri": "/v1/generate", "X-Original-URI": "/v1/ping"}, "/v1/generate", "GET", false},
		{"envoy doubled slash", envoy, "GET", "/authz/envoy/v1//generate", nil, "/v1/generate", "GET", false},
		{"envoy dot segment", envoy, "GET", "/authz/envoy/./v1/generate", nil, "/v1/generate", "GET", false},
		{"envoy encoded slash", envoy, "GET", "/authz/envoy/v1%2Fgenerate", nil, "/v1/generate", "GET", false},
		{"nginx doubled slash", nginx, "GET", "/authz/nginx", map[string]string{"X-Original-URI": "/v1//generate"}, "/v1/generate", "GET", false},
		{"nginx dot segment", nginx, "GET", "/authz/nginx", map[string]string{"X-Original-URI": "/./v1/generate"}, "/v1/generate", "GET", false},
		{"nginx dot-dot", nginx, "GET", "/authz/nginx", map[string]string{"X-Original-URI": "/v1/ping/../generate?x"}, "/v1/generate", "GET", false},
		{"nginx encoded slash", nginx, "GET", "/authz/nginx", map[string]string{"X-Original-URI": "/v1%2Fgenerate"}, "/v1/generate", "GET", false},
		{"nginx encoded dot-dot", nginx, "GET", "/authz/nginx", map[string]string{"X-Original-URI": "/v1/ping/%2e%2e/generate"}, "/v1/generate", "GET", false},
		{"traefik keeps trailing slash", traefik, "GET", "/authz/traefik", map[string]string{"X-Forwarded-Uri": "//v1/generate/"}, "/v1/generate/", "GET", false},
		{"traefik dot segment", traefik, "GET", "/authz/traefik", map[string]string{"X-Forwarded-Uri": "/v1/./generate"}, "/v1/generate", "GET", false},
		{"traefik missing header", traefik, "GET", "/authz/traefik", map[string]string{"X-Original-URI": "/v1/ping"}, "", "", true},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.target, nil)
		for k, v := range c.hdr {
			r.Header.Set(k, v)
		}
		m, p, ok := original(r, c.p)
		if ok == c.wantErr || (ok && (p != c.want || m != c.wantM)) {
			t.Errorf("%s: got %s %q ok=%v, want %s %q", c.name, m, p, ok, c.wantM, c.want)
		}
	}
}

// Every spelling of /v1/generate costs 5 through every endpoint.
func TestAuthzPricesCleanPath(t *testing.T) {
	for _, p := range []proxy{envoy, nginx, traefik} {
		for _, path := range []string{"/v1//generate", "/./v1/generate", "/v1/ping/../generate", "/v1%2Fgenerate", "/v1/%67enerate"} {
			rg := newRig(nil)
			rg.check(p, path, "")
			if d := rg.decisions[0]; d.Cost != 5 || d.Path != "/v1/generate" {
				t.Errorf("proxy %d %s: priced %s at %d", p, path, d.Path, d.Cost)
			}
		}
	}
}

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"/v1/generate":            "/v1/generate",
		"/v1/ping/../generate":    "/v1/generate",
		"//v1//generate":          "/v1/generate",
		"/v1/./generate/":         "/v1/generate/",
		"/.well-known/x":          "/.well-known/x",
		"/../../etc":              "/etc",
		"/":                       "/",
		"/v1/generate/x/../../..": "/",
	} {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
}

// check sends one forward-auth request as proxy p would for the original GET path.
func (rg *rig) check(p proxy, path, xff string) *httptest.ResponseRecorder {
	target := map[proxy]string{envoy: AuthzEnvoy + path, nginx: AuthzNginx, traefik: AuthzTraefik}[p]
	r := httptest.NewRequest("GET", target, nil)
	r.RemoteAddr = "10.0.0.2:4000" // the proxy
	r.Header.Set(KeyHeader, "k1")
	r.Header.Set("X-Forwarded-For", xff)
	r.Header.Set("X-Original-URI", path)
	r.Header.Set("X-Forwarded-Uri", path)
	w := httptest.NewRecorder()
	rg.g.Authz().ServeHTTP(w, r)
	return w
}

func TestAuthz(t *testing.T) {
	for name, p := range map[string]proxy{"envoy": envoy, "nginx": nginx, "traefik": traefik} {
		t.Run(name, func(t *testing.T) {
			blocked := http.StatusTooManyRequests
			if p == nginx {
				blocked = http.StatusForbidden
			}
			rg := newRig(func(c *Config) { c.Policy = bigMonthPolicy(); c.TrustProxy = true })

			w := rg.check(p, "/v1/generate", "203.0.113.9")
			if w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("RateLimit-Remaining") != "5" ||
				w.Header().Get("X-Limitplane-Tenant") != "acme" || w.Header().Get("X-Limitplane-Tier") != "free" {
				t.Fatalf("allow: %d %v %q", w.Code, w.Header(), w.Body)
			}
			d := rg.decisions[0]
			if d.Client != "203.0.113.9" || d.Path != "/v1/generate" || d.Cost != 5 || !d.Allowed {
				t.Fatalf("decision %+v", d)
			}

			rg.check(p, "/v1/generate", "203.0.113.9")
			w = rg.check(p, "/v1/generate", "203.0.113.9") // 15 > burst 10
			if w.Code != blocked || w.Header().Get("Retry-After") != "5" || w.Header().Get("X-Limitplane-Reason") != ReasonBurst ||
				w.Header().Get("RateLimit-Remaining") != "0" || decode(t, w).Reason != ReasonBurst {
				t.Fatalf("burst: %d %v %s", w.Code, w.Header(), w.Body)
			}

			rg.mem.Ban(context.Background(), limiter.Ban{Client: "198.51.100.7", Until: time.Now().Add(time.Minute)})
			if w = rg.check(p, "/", "198.51.100.7"); w.Code != blocked || decode(t, w).Reason != ReasonBanned {
				t.Fatalf("ban: %d %s", w.Code, w.Body)
			}
			if len(rg.decisions) != 4 || rg.decisions[3].Reason != ReasonBanned {
				t.Fatalf("every check is reported: %+v", rg.decisions)
			}
			if len(rg.inner) != 0 {
				t.Fatal("authz never calls a next handler")
			}
		})
	}
}

func TestAuthzBackendDown(t *testing.T) {
	for name, p := range map[string]proxy{"envoy": envoy, "nginx": nginx, "traefik": traefik} {
		open := newRig(nil)
		open.meter.err = errors.New("redis down")
		if w := open.check(p, "/", ""); w.Code != 200 || !open.decisions[0].Degraded || w.Header().Get("RateLimit-Limit") != "10" {
			t.Errorf("%s fail-open: %d %+v", name, w.Code, open.decisions)
		}
		closed := newRig(func(c *Config) { c.FailClosed = true })
		closed.meter.err = errors.New("redis down")
		if w := closed.check(p, "/", ""); w.Code != 503 || decode(t, w).Reason != ReasonError || w.Header().Get("Retry-After") != "" {
			t.Errorf("%s fail-closed: %d %s", name, w.Code, w.Body)
		}
	}
}

func TestAuthzRouting(t *testing.T) {
	rg := newRig(nil)
	for target, want := range map[string]int{
		"/authz/envoy":       404, // Envoy always appends a path starting with /
		"/authz/envoy//v1//": 200, // no ServeMux redirect
		"/authz/nginx/x":     404,
		"/authz/traefik":     400, // no X-Forwarded-Uri
		"/v1/generate":       404,
	} {
		w := httptest.NewRecorder()
		rg.g.Authz().ServeHTTP(w, httptest.NewRequest("POST", target, nil))
		if w.Code != want {
			t.Errorf("%s: %d, want %d", target, w.Code, want)
		}
	}
	if len(rg.decisions) != 1 || rg.decisions[0].Path != "/v1/" || rg.decisions[0].Method != "POST" {
		t.Fatalf("decisions %+v", rg.decisions)
	}
}

func BenchmarkAuthzEnvoy(b *testing.B) {
	g := New(Config{Policy: testPolicy(), Meter: nopMeter{}, OnDecision: func(Decision) {}})
	h := g.Authz()
	r := httptest.NewRequest("GET", AuthzEnvoy+"/v1/generate", nil)
	r.Header.Set(KeyHeader, "k1")
	b.ReportAllocs()
	for b.Loop() {
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
}
