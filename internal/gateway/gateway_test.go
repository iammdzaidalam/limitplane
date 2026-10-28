package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

// countingMeter wraps a real Meter, counts calls and can fail on demand.
type countingMeter struct {
	limiter.Meter
	calls int
	err   error
}

func (m *countingMeter) Check(ctx context.Context, q limiter.Request) (limiter.Result, error) {
	m.calls++
	if m.err != nil {
		return limiter.Result{}, m.err
	}
	return m.Meter.Check(ctx, q)
}

func testPolicy() *policy.Store {
	return policy.NewStore(policy.Config{
		Tiers: map[string]policy.Tier{
			"free": {Rate: limiter.Rate{Limit: 1, Period: time.Second, Burst: 10}, Monthly: 12},
		},
		Routes:    []policy.Route{{Prefix: "/v1/generate", Cost: 5}},
		Keys:      map[string]policy.Tenant{"k1": {ID: "acme", Tier: "free"}},
		Anonymous: "free",
	})
}

type rig struct {
	g         *Gateway
	mem       *limiter.Memory
	meter     *countingMeter
	decisions []Decision
	inner     []Decision
}

func newRig(mod func(*Config)) *rig {
	rg := &rig{mem: limiter.NewMemory()}
	rg.meter = &countingMeter{Meter: rg.mem}
	c := Config{Policy: testPolicy(), Meter: rg.meter, OnDecision: func(d Decision) { rg.decisions = append(rg.decisions, d) }}
	if mod != nil {
		mod(&c)
	}
	rg.g = New(c)
	return rg
}

func (rg *rig) do(path string) *httptest.ResponseRecorder {
	h := rg.g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, _ := DecisionFrom(r.Context())
		rg.inner = append(rg.inner, d)
	}))
	r := httptest.NewRequest("GET", path, nil)
	r.Header.Set(KeyHeader, "k1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

type body struct {
	Error, Reason, Message string
	RetryAfter             int64
}

func decode(t *testing.T, w *httptest.ResponseRecorder) body {
	t.Helper()
	var b body
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatalf("bad body %q: %v", w.Body, err)
	}
	return b
}

func TestAllowSetsHeadersAndContext(t *testing.T) {
	rg := newRig(nil)
	w := rg.do("/v1/generate")
	if w.Code != 200 || len(rg.inner) != 1 || rg.inner[0].Tenant != "acme" || rg.inner[0].Cost != 5 {
		t.Fatalf("code %d inner %+v", w.Code, rg.inner)
	}
	for k, v := range map[string]string{"RateLimit-Limit": "10", "RateLimit-Remaining": "5", "RateLimit-Reset": "5", "X-RateLimit-Remaining": "5"} {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if len(rg.decisions) != 1 || !rg.decisions[0].Allowed || rg.decisions[0].Reason != ReasonOK {
		t.Fatalf("decisions %+v", rg.decisions)
	}
}

// A burst-denied request must not bill the plan.
func TestBurstDenyDoesNotSpendMonthly(t *testing.T) {
	rg := newRig(func(c *Config) { c.Policy = bigMonthPolicy() })
	rg.do("/v1/generate")
	rg.do("/v1/generate")
	w := rg.do("/v1/generate") // 15 > burst 10
	if w.Code != 429 || w.Header().Get("Retry-After") != "5" {
		t.Fatalf("code %d retry-after %q", w.Code, w.Header().Get("Retry-After"))
	}
	b := decode(t, w)
	if b.Error != "rate_limited" || b.Reason != ReasonBurst || b.RetryAfter != 5 || b.Message == "" {
		t.Fatalf("body %+v", b)
	}
	if got, _ := rg.mem.Used(context.Background(), "acme"); got != 10 {
		t.Fatalf("monthly used = %d, want 10 (denied request billed)", got)
	}
}

// Burst is empty too here; monthly wins because it is the answer that holds until the 1st.
// (That a monthly reject keeps burst is tested in the limiter package.)
func TestMonthlyDeny(t *testing.T) {
	rg := newRig(nil)
	rg.do("/v1/generate")
	rg.do("/v1/generate")      // 10 of 12 monthly used
	w := rg.do("/v1/generate") // 10+5 > 12
	if w.Code != 429 || decode(t, w).Reason != ReasonMonthly {
		t.Fatalf("code %d body %s", w.Code, w.Body)
	}
	d := rg.decisions[2]
	if d.Limit != 12 || d.Remaining != 2 || d.RetryAfter <= 0 || d.RetryAfter > 32*24*time.Hour {
		t.Fatalf("decision %+v", d)
	}
	if len(rg.inner) != 2 {
		t.Fatal("next called on deny")
	}
}

func TestBanned(t *testing.T) {
	rg := newRig(nil)
	rg.mem.Ban(context.Background(), limiter.Ban{Client: "192.0.2.0/24", Until: time.Now().Add(90 * time.Second)})
	w := rg.do("/")
	if w.Code != 429 || decode(t, w).Reason != ReasonBanned || rg.meter.calls != 1 {
		t.Fatalf("code %d body %s calls %d", w.Code, w.Body, rg.meter.calls)
	}
	if ra := w.Header().Get("Retry-After"); ra != "90" {
		t.Fatalf("Retry-After %q", ra)
	}
	if got, _ := rg.mem.Used(context.Background(), "acme"); got != 0 {
		t.Fatalf("banned request billed %d", got)
	}
}

func bigMonthPolicy() *policy.Store {
	s := testPolicy()
	c := s.Config()
	c.Tiers["free"] = policy.Tier{Rate: c.Tiers["free"].Rate, Monthly: 1000}
	s.Swap(c)
	return s
}

func TestBackendError(t *testing.T) {
	boom := errors.New("redis down")
	closed := newRig(func(c *Config) { c.FailClosed = true })
	closed.meter.err = boom
	if w := closed.do("/"); w.Code != 503 || decode(t, w).Reason != ReasonError {
		t.Fatalf("fail-closed: code %d body %s", w.Code, w.Body)
	}
	open := newRig(nil)
	open.meter.err = boom
	if w := open.do("/"); w.Code != 200 || !open.decisions[0].Degraded {
		t.Fatalf("fail-open: code %d decision %+v", w.Code, open.decisions)
	}
}

func TestOnQuotaNamedTenantsOnly(t *testing.T) {
	var got []string
	rg := newRig(func(c *Config) { c.OnQuota = func(t string, used, lim int64) { got = append(got, t) } })
	rg.do("/")
	r := httptest.NewRequest("GET", "/", nil) // anonymous
	rg.g.Middleware(http.NotFoundHandler()).ServeHTTP(httptest.NewRecorder(), r)
	if len(got) != 1 || got[0] != "acme" {
		t.Fatalf("OnQuota calls %v", got)
	}
	if rg.decisions[1].Tenant != policy.AnonTenant {
		t.Fatalf("anon decision %+v", rg.decisions[1])
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name  string
		xff   []string
		trust bool
		want  string
	}{
		{"no trust ignores xff", []string{"1.1.1.1"}, false, "10.0.0.9"},
		{"no xff", nil, true, "10.0.0.9"},
		{"right-most untrusted", []string{"6.6.6.6, 203.0.113.7, 10.0.0.2"}, true, "203.0.113.7"},
		{"spoofed left ignored", []string{"1.2.3.4", "203.0.113.7"}, true, "203.0.113.7"},
		{"all internal", []string{"192.168.1.5, 10.0.0.2"}, true, "192.168.1.5"},
		{"garbage stops scan", []string{"203.0.113.7, junk, 10.0.0.2"}, true, "10.0.0.2"},
		{"ipv6", []string{"2001:db8::1"}, true, "2001:db8::1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "10.0.0.9:5555"
		for _, x := range c.xff {
			r.Header.Add("X-Forwarded-For", x)
		}
		if got := ClientIP(r, c.trust); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

type nopMeter struct{}

func (nopMeter) Check(context.Context, limiter.Request) (limiter.Result, error) {
	return limiter.Result{Allowed: true, Limit: 10, Remaining: 9, Used: 1}, nil
}
func (nopMeter) Used(context.Context, string) (int64, error) { return 1, nil }

func BenchmarkMiddleware(b *testing.B) {
	g := New(Config{Policy: testPolicy(), Meter: nopMeter{}, OnDecision: func(Decision) {}})
	h := g.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	r := httptest.NewRequest("GET", "/v1/generate", nil)
	r.Header.Set(KeyHeader, "k1")
	w := httptest.NewRecorder()
	b.ReportAllocs()
	for b.Loop() {
		h.ServeHTTP(w, r)
	}
}
