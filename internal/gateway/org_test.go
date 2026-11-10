package gateway

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

// Two tenants of one org share its budget: past it, either one gets org_monthly with the same
// headers and body a monthly reject has, and a tenant outside the org is unaffected.
func TestOrgBudgetDeny(t *testing.T) {
	s := policy.NewStore(policy.Config{
		Tiers:     map[string]policy.Tier{"pro": {Rate: limiter.Rate{Limit: 1000, Period: time.Second, Burst: 1000}, Monthly: 1000}},
		Routes:    []policy.Route{{Prefix: "/v1/generate", Cost: 5}},
		Keys:      map[string]policy.Tenant{"ka": {ID: "a", Tier: "pro", Org: "corp"}, "kc": {ID: "c", Tier: "pro"}},
		Anonymous: "pro",
	})
	s.SetOrgs(policy.Orgs{
		Budgets: map[string]int64{"corp": 12},
		Tenants: map[string]policy.OrgTenant{"b": {Org: "corp", Tier: "pro"}},
		Keys:    map[[32]byte]string{policy.HashKey("kb"): "b"},
	})
	rg := newRig(func(c *Config) { c.Policy = s })
	do := func(key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/v1/generate", nil)
		r.Header.Set(KeyHeader, key)
		w := httptest.NewRecorder()
		rg.g.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, r)
		return w
	}
	if do("ka").Code != 200 || do("kb").Code != 200 {
		t.Fatal("10 of 12 should pass")
	}
	for _, k := range []string{"ka", "kb"} {
		w := do(k)
		b := decode(t, w)
		retry, _ := strconv.Atoi(w.Header().Get("Retry-After"))
		if w.Code != 429 || b.Reason != ReasonOrg || b.Error != "rate_limited" || w.Header().Get("RateLimit-Limit") != "12" ||
			w.Header().Get("RateLimit-Remaining") != "2" || time.Duration(retry)*time.Second < time.Until(nextMonth(time.Now()))-time.Second {
			t.Fatalf("%s: %d %v %+v", k, w.Code, w.Header(), b)
		}
	}
	if d := rg.decisions[len(rg.decisions)-1]; d.Org != "corp" || d.Tenant != "b" || d.Reason != ReasonOrg {
		t.Fatalf("decision %+v", d)
	}
	if do("kc").Code != 200 {
		t.Fatal("a tenant outside the org is not limited by it")
	}
}

// A key created in the dashboard: not in the policy's map, found by its hash.
func BenchmarkMiddlewareDashboardKey(b *testing.B) {
	s := testPolicy()
	s.SetOrgs(policy.Orgs{Tenants: map[string]policy.OrgTenant{"web": {Org: "corp", Tier: "free"}}, Keys: map[[32]byte]string{policy.HashKey("lp_0123456789abcdefghijklmnopqrstuvwxyzABCDEF"): "web"}})
	g := New(Config{Policy: s, Meter: nopMeter{}, OnDecision: func(Decision) {}})
	h := g.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	r := httptest.NewRequest("GET", "/v1/generate", nil)
	r.Header.Set(KeyHeader, "lp_0123456789abcdefghijklmnopqrstuvwxyzABCDEF")
	w := httptest.NewRecorder()
	b.ReportAllocs()
	for b.Loop() {
		h.ServeHTTP(w, r)
	}
}
