package server

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

const testPolicy = `{
 "tiers": {"free": {"rate": {"limit": 1, "period": "1h", "burst": 5}, "monthly": 1000},
           "pro":  {"rate": {"limit": 100, "period": "1s", "burst": 200}}},
 "routes": [{"prefix": "/v1/generate", "cost": 5}],
 "keys": {"free-key": {"id": "acme", "tier": "free"}},
 "anonymous": "free"
}`

func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	cfg, err := policy.Parse([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{
		Policy: policy.NewStore(cfg), Limiter: limiter.NewLocal(), Quota: limiter.NewLocalQuota(),
		AdminKey: "admin-key", Backend: "memory",
		Dashboard: fstest.MapFS{"index.html": {Data: []byte("<h1>dash</h1>")}},
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	ts := httptest.NewServer(s.Handler(nil))
	t.Cleanup(func() { cancel(); ts.Close() })
	return s, ts
}

func do(t *testing.T, method, url, tok, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

func login(t *testing.T, base string) string {
	t.Helper()
	res := do(t, "POST", base+"/api/login", "", `{"key":"admin-key"}`)
	var out struct{ Token string }
	if res.StatusCode != 200 || json.NewDecoder(res.Body).Decode(&out) != nil || out.Token == "" {
		t.Fatalf("login: %d", res.StatusCode)
	}
	return out.Token
}

func TestEndToEnd(t *testing.T) {
	_, ts := newTestServer(t)
	tok := login(t, ts.URL)

	// Subscribe before traffic so the first decision is seen.
	sse := do(t, "GET", ts.URL+"/api/events?token="+tok, "", "")
	if ct := sse.Header.Get("Content-Type"); sse.StatusCode != 200 || ct != "text/event-stream" {
		t.Fatalf("sse: %d %s", sse.StatusCode, ct)
	}

	ping := func() *http.Response {
		req, _ := http.NewRequest("GET", ts.URL+"/v1/ping", nil)
		req.Header.Set("X-API-Key", "free-key")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res
	}
	for i := range 5 {
		if res := ping(); res.StatusCode != 200 || res.Header.Get("RateLimit-Limit") == "" {
			t.Fatalf("ping %d: %d %v", i, res.StatusCode, res.Header)
		}
	}
	res := ping()
	if res.StatusCode != 429 || res.Header.Get("Retry-After") == "" || res.Header.Get("RateLimit-Remaining") != "0" {
		t.Fatalf("6th ping: %d %v", res.StatusCode, res.Header)
	}

	sc := bufio.NewScanner(sse.Body)
	got := make(chan string, 1)
	go func() {
		for sc.Scan() {
			if d, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				got <- d
				return
			}
		}
	}()
	select {
	case d := <-got:
		if !strings.Contains(d, `"tenant":"acme"`) {
			t.Fatalf("sse data %s", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no SSE decision")
	}

	var st stats
	deadline := time.Now().Add(2 * time.Second)
	for st.Total < 6 && time.Now().Before(deadline) {
		r := do(t, "GET", ts.URL+"/api/stats", tok, "")
		st = stats{}
		json.NewDecoder(r.Body).Decode(&st)
	}
	if st.Total != 6 || st.Blocked != 1 || st.ByReason["burst"] != 1 || st.Backend != "memory" || st.Kube || st.Leader {
		t.Fatalf("stats %+v", st)
	}
	if st.Tenants[0].Tenant != "acme" || st.Tenants[0].MonthlyUsed != 5 || st.Tenants[0].MonthlyLimit != 1000 {
		t.Fatalf("tenant stats %+v", st.Tenants)
	}
	if a := do(t, "GET", ts.URL+"/api/audit?limit=2", tok, ""); a.StatusCode != 200 {
		t.Fatalf("audit %d", a.StatusCode)
	}
	if m := do(t, "GET", ts.URL+"/metrics", "", ""); m.StatusCode != 200 {
		t.Fatalf("metrics %d", m.StatusCode)
	}
}

func TestAuthAndAdmin(t *testing.T) {
	_, ts := newTestServer(t)
	if r := do(t, "GET", ts.URL+"/api/stats", "", ""); r.StatusCode != 401 {
		t.Fatalf("no token: %d", r.StatusCode)
	}
	// Query tokens are only for SSE.
	tok := login(t, ts.URL)
	if r := do(t, "GET", ts.URL+"/api/stats?token="+tok, "", ""); r.StatusCode != 401 {
		t.Fatalf("query token on stats: %d", r.StatusCode)
	}
	if r := do(t, "PUT", ts.URL+"/api/policy", tok, `{"tiers":{}}`); r.StatusCode != 400 {
		t.Fatalf("invalid policy: %d", r.StatusCode)
	}
	if r := do(t, "PUT", ts.URL+"/api/policy", tok, strings.Replace(testPolicy, `"burst": 5`, `"burst": 7`, 1)); r.StatusCode != 200 {
		t.Fatalf("valid policy: %d", r.StatusCode)
	}
	if r := do(t, "POST", ts.URL+"/api/bans", tok, `{"client":"1.2.3.4","minutes":5}`); r.StatusCode != 204 {
		t.Fatalf("ban: %d", r.StatusCode)
	}
	var bans []map[string]any
	json.NewDecoder(do(t, "GET", ts.URL+"/api/bans", tok, "").Body).Decode(&bans)
	if len(bans) != 1 || bans[0]["client"] != "1.2.3.4" {
		t.Fatalf("bans %v", bans)
	}
	if r := do(t, "DELETE", ts.URL+"/api/bans/1.2.3.4", tok, ""); r.StatusCode != 204 {
		t.Fatalf("unban: %d", r.StatusCode)
	}
	d := do(t, "GET", ts.URL+"/", "", "")
	if d.StatusCode != 200 || d.Header.Get("Content-Security-Policy") == "" || d.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("dashboard %d %v", d.StatusCode, d.Header)
	}
}

func TestLoginRateLimited(t *testing.T) {
	_, ts := newTestServer(t)
	codes := []int{}
	for range 7 {
		codes = append(codes, do(t, "POST", ts.URL+"/api/login", "", `{"key":"wrong"}`).StatusCode)
	}
	if codes[0] != 401 || codes[6] != 429 {
		t.Fatalf("codes %v", codes)
	}
	// Correct key is still limited once the bucket is empty: no free guesses.
	if r := do(t, "POST", ts.URL+"/api/login", "", `{"key":"admin-key"}`); r.StatusCode != 429 {
		t.Fatalf("correct key after lockout: %d", r.StatusCode)
	}
}

func TestCSPHashesInlineScript(t *testing.T) {
	// sha256 of "alert(1)", as browsers compute it.
	got := csp(fstest.MapFS{"index.html": {Data: []byte("<script>alert(1)</script><script src=a.js></script>")}})
	if !strings.Contains(got, "script-src 'self' 'sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI='") {
		t.Fatal(got)
	}
}

func TestProxyMount(t *testing.T) {
	s, _ := newTestServer(t)
	up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("upstream")) })
	ts := httptest.NewServer(s.Handler(up))
	defer ts.Close()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := c.Get(ts.URL + AdminPrefix)
	if err != nil || r.StatusCode != 301 || r.Header.Get("Location") != AdminPrefix+"/" {
		t.Fatalf("redirect: %v %v", err, r)
	}
	r.Body.Close()
	for path, want := range map[string]int{AdminPrefix + "/healthz": 200, AdminPrefix + "/api/stats": 401, "/anything": 200} {
		if r := do(t, "GET", ts.URL+path, "", ""); r.StatusCode != want {
			t.Errorf("%s: %d, want %d", path, r.StatusCode, want)
		}
	}
}

func TestMetricsKey(t *testing.T) {
	cfg, _ := policy.Parse([]byte(testPolicy))
	s := New(Config{Policy: policy.NewStore(cfg), Limiter: limiter.NewLocal(), Quota: limiter.NewLocalQuota(), AdminKey: "a", MetricsKey: "scrape"})
	ts := httptest.NewServer(s.Handler(nil))
	defer ts.Close()
	for tok, want := range map[string]int{"": 401, "nope": 401, "scrape": 200} {
		if r := do(t, "GET", ts.URL+"/metrics", tok, ""); r.StatusCode != want {
			t.Errorf("token %q: got %d, want %d", tok, r.StatusCode, want)
		}
	}
}
