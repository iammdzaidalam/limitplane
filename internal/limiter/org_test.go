package limiter

import (
	"testing"
	"time"
)

// orgMeters runs f against every Meter that implements org budgets: memory, and Redis when set.
func orgMeters(t *testing.T, f func(t *testing.T, m Backend)) {
	t.Run("memory", func(t *testing.T) { f(t, NewMemory()) })
	t.Run("redis", func(t *testing.T) {
		forEachRedis(t, func(t *testing.T, addr string) { f(t, NewRedis(dialRedis(t, addr), nil)) })
	})
}

func inOrg(key, org string, cost, month, budget int64) Request {
	return Request{Key: key, Org: org, Rate: wide, Cost: cost, Month: month, OrgMonth: budget}
}

// Two tenants share one budget, and a reject spends nothing anywhere.
func TestOrgBudgetShared(t *testing.T) {
	orgMeters(t, func(t *testing.T, m Backend) {
		org, a, b := uniq("o"), uniq("a-"), uniq("b-")
		for range 3 {
			if res := mustCheck(t, m, inOrg(a, org, 2, 100, 10)); !res.Allowed {
				t.Fatalf("a: %+v", res)
			}
		}
		res := mustCheck(t, m, inOrg(b, org, 4, 100, 10))
		if !res.Allowed || res.OrgUsed != 10 || res.Used != 4 {
			t.Fatalf("b fills the budget: %+v", res)
		}
		for _, k := range []string{a, b} {
			if res := mustCheck(t, m, inOrg(k, org, 1, 100, 10)); res.Allowed || res.Reason != OrgMonthly || res.OrgUsed != 10 {
				t.Fatalf("%s past the budget: %+v", k, res)
			}
		}
		if n, _ := m.UsedIn(ctx, b, org); n != 4 {
			t.Fatalf("org reject billed the tenant: %d", n)
		}
		if n, _ := m.OrgUsed(ctx, org); n != 10 {
			t.Fatalf("org used %d", n)
		}
		// Another org, and a tenant without one, are untouched.
		if res := mustCheck(t, m, inOrg(uniq("c-"), uniq("o"), 5, 100, 10)); !res.Allowed || res.OrgUsed != 5 {
			t.Fatalf("other org: %+v", res)
		}
		if res := mustCheck(t, m, inOrg(uniq("d-"), "", 5, 100, 10)); !res.Allowed || res.OrgUsed != 0 {
			t.Fatalf("no org: %+v", res)
		}
	})
}

// Tenant monthly is checked first, then the org, then burst; each reject spends nothing.
func TestOrgBudgetOrder(t *testing.T) {
	orgMeters(t, func(t *testing.T, m Backend) {
		org, k := uniq("o"), uniq("k-")
		mustCheck(t, m, inOrg(k, org, 5, 5, 5))
		if res := mustCheck(t, m, inOrg(k, org, 1, 5, 5)); res.Reason != Monthly {
			t.Fatalf("both used up: monthly wins, got %+v", res)
		}
		tight := Request{Key: uniq("k2-"), Org: org, Rate: Rate{Limit: 1, Period: time.Hour, Burst: 1}, Cost: 1, Month: 100, OrgMonth: 6}
		if res := mustCheck(t, m, tight); !res.Allowed {
			t.Fatalf("%+v", res)
		}
		if res := mustCheck(t, m, tight); res.Reason != OrgMonthly {
			t.Fatalf("org and burst both fail: org wins, got %+v", res)
		}
		tight.OrgMonth = 100
		if res := mustCheck(t, m, tight); res.Reason != Burst || res.OrgUsed != 6 {
			t.Fatalf("want burst: %+v", res)
		}
		if n, _ := m.OrgUsed(ctx, org); n != 6 {
			t.Fatalf("a burst reject billed the org: %d", n)
		}
	})
}

// Spend is counted without a budget, so one set mid-month applies to all of it.
func TestOrgBudgetCountsWithoutBudget(t *testing.T) {
	orgMeters(t, func(t *testing.T, m Backend) {
		org, k := uniq("o"), uniq("k-")
		for range 4 {
			mustCheck(t, m, inOrg(k, org, 2, 0, 0))
		}
		if res := mustCheck(t, m, inOrg(k, org, 1, 0, 8)); res.Reason != OrgMonthly || res.OrgUsed != 8 {
			t.Fatalf("budget set after the spend: %+v", res)
		}
	})
}

// Joining an org carries the tenant's month over, once; leaving carries it back.
func TestOrgMove(t *testing.T) {
	orgMeters(t, func(t *testing.T, m Backend) {
		org, k := uniq("o"), uniq("k-")
		mustCheck(t, m, inOrg(k, "", 7, 10, 0))
		for range 2 { // a repeat (another replica) finds nothing left to move
			if err := m.Move(ctx, k, "", org); err != nil {
				t.Fatal(err)
			}
		}
		if n, _ := m.UsedIn(ctx, k, org); n != 7 {
			t.Fatalf("moved %d, want 7", n)
		}
		if n, _ := m.Used(ctx, k); n != 0 {
			t.Fatalf("left %d behind", n)
		}
		if res := mustCheck(t, m, inOrg(k, org, 4, 10, 0)); res.Reason != Monthly {
			t.Fatalf("the cap must still see the old spend: %+v", res)
		}
		if n, _ := m.OrgUsed(ctx, org); n != 0 {
			t.Fatalf("spend from before joining billed the org: %d", n)
		}
		m.Move(ctx, k, org, "")
		if n, _ := m.Used(ctx, k); n != 7 {
			t.Fatalf("moved back %d", n)
		}
	})
}

func TestOrgBudgetRollover(t *testing.T) {
	c := newClock(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC).Add(-time.Nanosecond))
	m := memAt(c)
	mustCheck(t, m, inOrg("a", "o", 10, 0, 10))
	if res := mustCheck(t, m, inOrg("b", "o", 1, 0, 10)); res.Reason != OrgMonthly {
		t.Fatalf("%+v", res)
	}
	c.add(time.Nanosecond)
	if res := mustCheck(t, m, inOrg("b", "o", 1, 0, 10)); !res.Allowed || res.OrgUsed != 1 {
		t.Fatalf("new month: %+v", res)
	}
}

// Racing tenants of one org admit exactly the budget.
func TestOrgBudgetExactUnderConcurrency(t *testing.T) {
	m := memAt(newClock(t0))
	got := hammer(func(g, _ int) bool {
		res, err := m.Check(ctx, inOrg([]string{"a", "b", "c"}[g%3], "o", 1, 0, 500))
		return err == nil && res.Allowed
	})
	if n, _ := m.OrgUsed(ctx, "o"); got != 500 || n != 500 {
		t.Fatalf("admitted %d, used %d, want 500", got, n)
	}
}

// Degraded, each replica gets its share of the org budget too.
func TestOrgBudgetFallbackShare(t *testing.T) {
	f := NewFallback(&failing{}, NewMemory(), func() int { return 2 })
	admitted := 0
	for range 20 {
		if res, _ := f.Check(ctx, inOrg("k", "o", 1, 0, 10)); res.Allowed {
			if !res.Degraded {
				t.Fatal("not degraded")
			}
			admitted++
		}
	}
	if admitted != 5 {
		t.Fatalf("admitted %d, want 5 (budget 10 over 2 replicas)", admitted)
	}
	if got := part(10, 3, 4); got != 4 {
		t.Fatalf("a share never drops below the cost: %d", got)
	}
}

// No org: still no allocations (the gateway's hot path); in an org, none either.
func TestCheckAllocs(t *testing.T) {
	m := NewMemory()
	q := Request{Client: "203.0.113.7", Key: "acme", Rate: wide, Cost: 1, Month: 1 << 60}
	if n := testing.AllocsPerRun(100, func() { m.Check(ctx, q) }); n != 0 {
		t.Fatalf("no org: %v allocs", n)
	}
	q.Org, q.OrgMonth = "corp", 1<<60
	if n := testing.AllocsPerRun(100, func() { m.Check(ctx, q) }); n != 0 {
		t.Fatalf("org: %v allocs", n)
	}
}

// BenchmarkMemoryCheck's path for tenants in an org: the org's shard, its budget checked and spent too.
func BenchmarkMemoryCheckOrg(b *testing.B) {
	m, ks := NewMemory(), keys512()
	q := Request{Client: "203.0.113.7", Rate: wide, Cost: 1, Month: 1 << 60, OrgMonth: 1 << 60}
	orgs := [8]string{"o0", "o1", "o2", "o3", "o4", "o5", "o6", "o7"}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		q.Key, q.Org = ks[i&511], orgs[i&7]
		m.Check(ctx, q)
		i++
	}
}
