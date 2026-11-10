package ai

import (
	"strings"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/autopilot"
	"github.com/iammdzaidalam/limitplane/internal/gateway"
	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

var t0 = time.Date(2026, 11, 11, 14, 2, 0, 0, time.UTC)

func testPolicy() policy.Config {
	return policy.Config{
		Tiers: map[string]policy.Tier{
			"free": {Rate: limiter.Rate{Limit: 1, Period: time.Second, Burst: 20}, Monthly: 50000},
			"pro":  {Rate: limiter.Rate{Limit: 100, Period: time.Second, Burst: 200}, Lanes: map[string]float64{"human": 2}},
		},
		Routes:    []policy.Route{{Prefix: "/v1/generate", Cost: 5}, {Prefix: "/v1", Cost: 1}},
		Keys:      map[string]policy.Tenant{"sk-secret-1": {ID: "acme", Tier: "free"}, "sk-secret-2": {ID: "globex", Tier: "pro"}},
		Anonymous: "free",
	}
}

// burstRun is a client hammering every gap, ignoring Retry-After: n decisions newest first.
func burstRun(client string, n int, gap time.Duration) []gateway.Decision {
	out := make([]gateway.Decision, n)
	for i := range n {
		d := gateway.Decision{Time: t0.Add(-time.Duration(i) * gap), Tenant: "acme", Tier: "free", Client: client, Method: "GET", Path: "/v1/ping", Cost: 1, Limit: 20}
		if i < n-3 { // the oldest three passed
			d.Reason, d.RetryAfter = gateway.ReasonBurst, time.Second
		} else {
			d.Allowed, d.Reason, d.Remaining = true, gateway.ReasonOK, 5
		}
		out[i] = d
	}
	return out
}

func has(t *testing.T, ps []Point, sub string) Point {
	t.Helper()
	for _, p := range ps {
		if strings.Contains(p.Text, sub) {
			return p
		}
	}
	var all []string
	for _, p := range ps {
		all = append(all, p.Text)
	}
	t.Fatalf("no point containing %q in:\n%s", sub, strings.Join(all, "\n"))
	return Point{}
}

// checkRefs asserts every point cites only facts that exist.
func checkRefs(t *testing.T, e Explanation) {
	t.Helper()
	ids := map[string]bool{}
	for _, f := range e.Facts {
		ids[f.ID] = true
		if strings.Contains(f.Text, "sk-secret") {
			t.Fatalf("fact leaks an API key: %s", f.Text)
		}
	}
	for _, p := range append(e.Findings, e.Actions...) {
		for _, id := range p.Facts {
			if !ids[id] {
				t.Fatalf("%q cites unknown fact %s", p.Text, id)
			}
		}
	}
	if e.Summary == "" || len(e.Findings) == 0 || e.Summary != e.Findings[0].Text {
		t.Fatalf("summary %q, findings %d", e.Summary, len(e.Findings))
	}
}

func TestExplainRetryLoop(t *testing.T) {
	audit := burstRun("203.0.113.7", 50, 170*time.Millisecond)
	e := Explain(Input{Now: t0, Decision: &audit[0], Audit: audit, Policy: testPolicy(),
		Clients: []autopilot.Client{{Client: "203.0.113.7", Label: "retry_bug", RPS: 5.9, BlockRatio: .94}}})
	checkRefs(t, e)
	if e.Reason != "burst" || !strings.Contains(e.Summary, "burst limit") {
		t.Fatalf("summary: %s", e.Summary)
	}
	f := has(t, e.Findings, "Retry loop: 47 burst blocks in 8.3s with near-constant spacing")
	if len(f.Facts) < 3 {
		t.Fatalf("retry loop finding should rest on timing facts: %v", f.Facts)
	}
	has(t, e.Actions, "honour Retry-After")
	has(t, e.Actions, `"retry_bug": 0.25`)
}

func TestExplainScriptedAndHuman(t *testing.T) {
	audit := burstRun("198.51.100.1", 12, 500*time.Millisecond)
	for i := range audit { // a polite bot: waits out every 429, but never slows down
		audit[i].RetryAfter = 0
	}
	e := Explain(Input{Now: t0, Decision: &audit[0], Audit: audit, Policy: testPolicy()})
	checkRefs(t, e)
	has(t, e.Findings, "Scripted traffic: one request every 500ms")

	// human on a tier with no human lane: suggest one
	h := audit[0]
	e = Explain(Input{Now: t0, Decision: &h, Audit: []gateway.Decision{h, h, h}, Policy: testPolicy(),
		Clients: []autopilot.Client{{Client: h.Client, Label: "human"}}})
	has(t, e.Findings, "human-like")
	has(t, e.Actions, `"lanes": {"human": 2}`)
}

func TestExplainExpensiveRoute(t *testing.T) {
	d := gateway.Decision{Time: t0, Tenant: "acme", Tier: "free", Client: "10.0.0.1", Method: "POST", Path: "/v1/generate/x", Cost: 6, Reason: "burst", Limit: 20, RetryAfter: 6 * time.Second}
	e := Explain(Input{Now: t0, Decision: &d, Policy: testPolicy()})
	checkRefs(t, e)
	has(t, e.Findings, "one burst fits only 3 calls")
	route := e.Facts[2]
	if route.Kind != "route" || !strings.Contains(route.Text, "route /v1/generate at 6 units") {
		t.Fatalf("route fact: %+v", route)
	}
}

func TestExplainMonthly(t *testing.T) {
	d := gateway.Decision{Time: t0, Tenant: "acme", Tier: "free", Client: "10.0.0.1", Method: "GET", Path: "/v1/ping", Cost: 1, Reason: "monthly", Limit: 50000, RetryAfter: 20 * 24 * time.Hour}
	e := Explain(Input{Now: t0, Decision: &d, Policy: testPolicy(), Used: 50000, UsedOK: true})
	checkRefs(t, e)
	has(t, e.Findings, "used its whole monthly quota on the free tier; it resets in 20 days")
	has(t, e.Actions, "Move acme to a bigger tier")
	if !strings.Contains(e.Facts[len(e.Facts)-1].Text, "50,000 of 50,000 monthly units (100%)") {
		t.Fatalf("usage fact: %+v", e.Facts)
	}
}

func TestExplainBanned(t *testing.T) {
	audit := burstRun("203.0.113.7", 30, 100*time.Millisecond)
	d := gateway.Decision{Time: t0.Add(time.Second), Tenant: "acme", Tier: "free", Client: "203.0.113.7", Method: "GET", Path: "/v1/ping", Reason: "banned", RetryAfter: 4 * time.Minute}
	storm := limiter.Ban{Client: "203.0.113.7", Until: t0.Add(5 * time.Minute), Reason: "storm"}
	e := Explain(Input{Now: t0.Add(time.Second), Decision: &d, Audit: append([]gateway.Decision{d}, audit...), Policy: testPolicy(), Bans: []limiter.Ban{storm}, Rules: autopilot.DefaultRules})
	checkRefs(t, e)
	has(t, e.Findings, "Autopilot banned 203.0.113.7 for a storm: at least 20 burst blocks inside 10.0s")
	has(t, e.Findings, "retry loop rather than an attack")
	has(t, e.Actions, "unban it")

	// a CIDR ban covers the client; a manual reason gets the manual reading
	cidr := limiter.Ban{Client: "203.0.113.0/24", Until: t0.Add(time.Hour), Reason: "abuse report"}
	e = Explain(Input{Now: t0, Decision: &d, Policy: testPolicy(), Bans: []limiter.Ban{cidr}})
	checkRefs(t, e)
	has(t, e.Findings, `203.0.113.0/24 is banned (abuse report)`)

	// the ban has lifted since
	e = Explain(Input{Now: t0, Decision: &d, Policy: testPolicy()})
	has(t, e.Findings, "has since lifted")
}

func TestExplainErrorOKDegraded(t *testing.T) {
	d := gateway.Decision{Time: t0, Tenant: "acme", Tier: "free", Client: "10.0.0.1", Method: "GET", Path: "/v1/ping", Cost: 1, Reason: "error"}
	e := Explain(Input{Now: t0, Decision: &d, Policy: testPolicy()})
	checkRefs(t, e)
	has(t, e.Findings, "fail-closed")
	has(t, e.Actions, "Redis")

	d = gateway.Decision{Time: t0, Tenant: "acme", Tier: "free", Client: "10.0.0.1", Method: "GET", Path: "/v1/ping", Cost: 1, Allowed: true, Reason: "ok", Limit: 20, Remaining: 19, Degraded: true}
	e = Explain(Input{Now: t0, Decision: &d, Policy: testPolicy()})
	checkRefs(t, e)
	has(t, e.Findings, "Allowed: within limits, 19 of 20 left")
	has(t, e.Findings, "local fallback")
}

func TestExplainClientAndTenant(t *testing.T) {
	audit := burstRun("203.0.113.7", 30, 200*time.Millisecond)
	e := Explain(Input{Now: t0, Client: "203.0.113.7", Audit: audit, Policy: testPolicy()})
	checkRefs(t, e)
	if e.Reason != "burst" || e.Subject != "client 203.0.113.7" {
		t.Fatalf("%s / %s", e.Reason, e.Subject)
	}
	e = Explain(Input{Now: t0, Client: "192.0.2.99", Audit: audit, Policy: testPolicy()})
	if len(e.Facts) != 0 || !strings.Contains(e.Summary, "nothing to explain") {
		t.Fatalf("unknown client: %+v", e)
	}

	// tenant: one client dominates, and the month's pace runs out before the reset
	e = Explain(Input{Now: t0, Tenant: "acme", Audit: audit, Policy: testPolicy(), Used: 30000, UsedOK: true})
	checkRefs(t, e)
	has(t, e.Findings, "Most of acme's blocks come from one client, 203.0.113.7")
	has(t, e.Findings, "on pace to run out of its monthly quota on 2026-11-18")
	e = Explain(Input{Now: t0, Tenant: "globex", Policy: testPolicy()})
	has(t, e.Findings, "no decisions")
}

func TestExplainBudget(t *testing.T) {
	d := gateway.Decision{Time: t0, Tenant: "acme", Tier: "free", Client: "10.0.0.1", Method: "GET", Path: "/v1/ping", Cost: 1, Allowed: true, Reason: "ok", Limit: 20, Remaining: 3}
	e := Explain(Input{Now: t0, Decision: &d, Policy: testPolicy(), Budget: &Budget{Org: "initech", Used: 900, Limit: 1000}})
	checkRefs(t, e)
	has(t, e.Findings, "initech organisation is at 90%")
}

// A block by the org's shared budget names the org, not the tenant's own quota.
func TestExplainOrgBudget(t *testing.T) {
	d := gateway.Decision{Time: t0, Tenant: "acme", Tier: "free", Client: "10.0.0.1", Method: "GET", Path: "/v1/ping", Cost: 1, Reason: gateway.ReasonOrg}
	b := &Budget{Org: "initech", Used: 1000, Limit: 1000}
	e := Explain(Input{Now: t0, Decision: &d, Policy: testPolicy(), Budget: b})
	checkRefs(t, e)
	if e.Reason != gateway.ReasonOrg || !strings.HasPrefix(e.Summary, "Organisation initech has used its whole shared monthly budget") || len(e.Findings) != 1 {
		t.Fatalf("%+v", e)
	}
	d.Allowed, d.Reason = false, gateway.ReasonOrg
	e = Explain(Input{Now: t0, Tenant: "acme", Audit: []gateway.Decision{d}, Policy: testPolicy(), Budget: b})
	checkRefs(t, e)
	if e.Reason != gateway.ReasonOrg || !strings.HasPrefix(e.Summary, "Organisation initech has used its whole shared monthly budget") {
		t.Fatalf("tenant: %+v", e)
	}
}
