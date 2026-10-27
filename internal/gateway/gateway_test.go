package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

// fakeLimiter grants up to Burst units per key, then denies with a fixed RetryAfter.
type fakeLimiter struct {
	mu    sync.Mutex
	spent map[string]int64
	err   error
	calls int
}

func (f *fakeLimiter) Allow(_ context.Context, key string, r limiter.Rate, cost int64) (limiter.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return limiter.Result{}, f.err
	}
	if f.spent == nil {
		f.spent = map[string]int64{}
	}
	if f.spent[key]+cost > r.Burst {
		return limiter.Result{Limit: r.Burst, RetryAfter: 2100 * time.Millisecond, ResetAfter: 4 * time.Second}, nil
	}
	f.spent[key] += cost
	return limiter.Result{Allowed: true, Limit: r.Burst, Remaining: r.Burst - f.spent[key], ResetAfter: time.Second}, nil
}

type fakeQuota struct {
	mu   sync.Mutex
	used map[string]int64
	err  error
}

func (f *fakeQuota) Spend(_ context.Context, key string, limit, cost int64) (int64, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, false, f.err
	}
	if f.used == nil {
		f.used = map[string]int64{}
	}
	if f.used[key]+cost > limit {
		return f.used[key], false, nil
	}
	f.used[key] += cost
	return f.used[key], true, nil
}

type fakeBans map[string]time.Time

func (b fakeBans) Banned(c string) (time.Time, bool) { t, ok := b[c]; return t, ok }

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
	lim       *fakeLimiter
	quota     *fakeQuota
	decisions []Decision
	inner     []Decision
}

func newRig(mod func(*Config)) *rig {
	rg := &rig{lim: &fakeLimiter{}, quota: &fakeQuota{}}
	c := Config{Policy: testPolicy(), Limiter: rg.lim, Quota: rg.quota, OnDecision: func(d Decision) { rg.decisions = append(rg.decisions, d) }}
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
	for k, v := range map[string]string{"RateLimit-Limit": "10", "RateLimit-Remaining": "5", "RateLimit-Reset": "1", "X-RateLimit-Remaining": "5"} {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if len(rg.decisions) != 1 || !rg.decisions[0].Allowed || rg.decisions[0].Reason != ReasonOK {
		t.Fatalf("decisions %+v", rg.decisions)
	}
}

// Burst runs before monthly, so a burst-denied request must not bill the plan.
func TestBurstDenyDoesNotSpendMonthly(t *testing.T) {
	rg := newRig(nil)
	rg.do("/v1/generate")
	rg.do("/v1/generate")
	w := rg.do("/v1/generate") // 15 > burst 10
	if w.Code != 429 || w.Header().Get("Retry-After") != "3" {
		t.Fatalf("code %d retry-after %q", w.Code, w.Header().Get("Retry-After"))
	}
	b := decode(t, w)
	if b.Error != "rate_limited" || b.Reason != ReasonBurst || b.RetryAfter != 3 || b.Message == "" {
		t.Fatalf("body %+v", b)
	}
	if got := rg.quota.used[limiter.MonthKey("acme", time.Now())]; got != 10 {
		t.Fatalf("monthly used = %d, want 10 (denied request billed)", got)
	}
}

func TestMonthlyDeny(t *testing.T) {
	rg := newRig(nil)
	rg.quota.used = map[string]int64{limiter.MonthKey("acme", time.Now()): 10}
	w := rg.do("/v1/generate") // 10+5 > 12
	if w.Code != 429 || decode(t, w).Reason != ReasonMonthly {
		t.Fatalf("code %d body %s", w.Code, w.Body)
	}
	d := rg.decisions[0]
	if d.Limit != 12 || d.Remaining != 2 || d.RetryAfter <= 0 || d.RetryAfter > 32*24*time.Hour {
		t.Fatalf("decision %+v", d)
	}
	if len(rg.inner) != 0 {
		t.Fatal("next called on deny")
	}
}

func TestBannedSkipsLimiter(t *testing.T) {
	rg := newRig(func(c *Config) { c.Bans = fakeBans{"192.0.2.1": time.Now().Add(90 * time.Second)} })
	w := rg.do("/")
	if w.Code != 429 || decode(t, w).Reason != ReasonBanned || rg.lim.calls != 0 {
		t.Fatalf("code %d body %s calls %d", w.Code, w.Body, rg.lim.calls)
	}
	if ra := w.Header().Get("Retry-After"); ra != "90" {
		t.Fatalf("Retry-After %q", ra)
	}
}

func TestBackendError(t *testing.T) {
	boom := errors.New("redis down")
	closed := newRig(func(c *Config) { c.FailClosed = true })
	closed.lim.err = boom
	if w := closed.do("/"); w.Code != 503 || decode(t, w).Reason != ReasonError {
		t.Fatalf("fail-closed: code %d body %s", w.Code, w.Body)
	}
	open := newRig(nil)
	open.lim.err = boom
	if w := open.do("/"); w.Code != 200 || !open.decisions[0].Degraded {
		t.Fatalf("fail-open: code %d decision %+v", w.Code, open.decisions)
	}
	q := newRig(func(c *Config) { c.FailClosed = true })
	q.quota.err = boom
	if w := q.do("/"); w.Code != 503 {
		t.Fatalf("quota fail-closed: code %d", w.Code)
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

type nopLimiter struct{}

func (nopLimiter) Allow(context.Context, string, limiter.Rate, int64) (limiter.Result, error) {
	return limiter.Result{Allowed: true, Limit: 10, Remaining: 9}, nil
}

type nopQuota struct{}

func (nopQuota) Spend(context.Context, string, int64, int64) (int64, bool, error) {
	return 1, true, nil
}

func BenchmarkMiddleware(b *testing.B) {
	g := New(Config{Policy: testPolicy(), Limiter: nopLimiter{}, Quota: nopQuota{}, OnDecision: func(Decision) {}})
	h := g.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	r := httptest.NewRequest("GET", "/v1/generate", nil)
	r.Header.Set(KeyHeader, "k1")
	w := httptest.NewRecorder()
	b.ReportAllocs()
	for b.Loop() {
		h.ServeHTTP(w, r)
	}
}
