package limiter

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var ctx = context.Background()

type clock struct{ t atomic.Int64 }

func (c *clock) now() time.Time      { return time.Unix(0, c.t.Load()) }
func (c *clock) add(d time.Duration) { c.t.Add(int64(d)) }
func newClock(t time.Time) *clock    { c := &clock{}; c.t.Store(t.UnixNano()); return c }
func localAt(c *clock) *Local        { l := NewLocal(); l.now = c.now; return l }
func mustAllow(t *testing.T, l Limiter, key string, r Rate, cost int64) Result {
	t.Helper()
	res, err := l.Allow(ctx, key, r, cost)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestGCRA(t *testing.T) {
	c := newClock(time.Unix(1_700_000_000, 0))
	l := localAt(c)
	r := Rate{Limit: 1, Period: time.Second, Burst: 3}
	for i, want := range []int64{2, 1, 0} {
		res := mustAllow(t, l, "k", r, 1)
		if !res.Allowed || res.Remaining != want || res.Limit != 3 {
			t.Fatalf("req %d: %+v", i, res)
		}
	}
	res := mustAllow(t, l, "k", r, 1)
	if res.Allowed || res.RetryAfter != time.Second || res.ResetAfter != 3*time.Second || res.Remaining != 0 {
		t.Fatalf("4th: %+v", res)
	}
	c.add(1500 * time.Millisecond) // one unit back, half of the next
	if res = mustAllow(t, l, "k", r, 2); res.Allowed || res.RetryAfter != 500*time.Millisecond || res.Remaining != 1 {
		t.Fatalf("cost 2 with 1 left: %+v", res)
	}
	if res = mustAllow(t, l, "k", r, 1); !res.Allowed || res.Remaining != 0 {
		t.Fatalf("cost 1 with 1 left: %+v", res)
	}
	if res = mustAllow(t, l, "big", r, 4); res.Allowed {
		t.Fatalf("cost > burst must never pass: %+v", res)
	}
	c.add(time.Hour)
	if res = mustAllow(t, l, "k", r, 3); !res.Allowed || res.Remaining != 0 || res.ResetAfter != 3*time.Second {
		t.Fatalf("full refill: %+v", res)
	}
	if _, err := l.Allow(ctx, "k", Rate{}, 1); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero rate must error")
	}
	if _, err := l.Allow(ctx, "k", r, 0); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero cost must error")
	}
}

func TestBurstDefaultsToLimit(t *testing.T) {
	l := localAt(newClock(time.Unix(0, 0)))
	r := Rate{Limit: 5, Period: time.Second}
	n := 0
	for range 10 {
		if mustAllow(t, l, "k", r, 1).Allowed {
			n++
		}
	}
	if n != 5 {
		t.Fatalf("admitted %d, want 5", n)
	}
}

func TestConcurrentNeverOverAdmits(t *testing.T) {
	l := localAt(newClock(time.Unix(1_700_000_000, 0))) // frozen: no refill during the test
	r := Rate{Limit: 10, Period: time.Second, Burst: 50}
	var admitted atomic.Int64
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			for range 100 {
				if res, _ := l.Allow(ctx, "hot", r, 1); res.Allowed {
					admitted.Add(1)
				}
			}
		})
	}
	wg.Wait()
	if admitted.Load() != 50 {
		t.Fatalf("admitted %d, want 50", admitted.Load())
	}
}

func TestSweep(t *testing.T) {
	c := newClock(time.Unix(1_700_000_000, 0))
	l := localAt(c)
	r := Rate{Limit: 10, Period: time.Second}
	for i := range 10_000 {
		mustAllow(t, l, "old"+strconv.Itoa(i), r, 1)
	}
	c.add(2 * time.Minute)
	for i := range 10_000 {
		mustAllow(t, l, "new"+strconv.Itoa(i), r, 1)
	}
	if n := l.size(); n != 10_000 {
		t.Fatalf("size %d after sweep, want 10000", n)
	}
}

func TestRateJSON(t *testing.T) {
	var r Rate
	if err := json.Unmarshal([]byte(`{"limit":10,"period":"1m30s","burst":20}`), &r); err != nil {
		t.Fatal(err)
	}
	if r != (Rate{10, 90 * time.Second, 20}) {
		t.Fatalf("%+v", r)
	}
	b, _ := json.Marshal(r)
	if string(b) != `{"limit":10,"period":"1m30s","burst":20}` {
		t.Fatal(string(b))
	}
	if json.Unmarshal([]byte(`{"limit":1,"period":"soon"}`), &r) == nil {
		t.Fatal("bad period must error")
	}
}

func memAt(c *clock) *Memory { m := NewMemory(); m.now = c.now; return m }

func mustCheck(t *testing.T, m Meter, q Request) Result {
	t.Helper()
	res, err := m.Check(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestLocalMonthly(t *testing.T) {
	c := newClock(time.Date(2026, 1, 31, 23, 0, 0, 0, time.UTC))
	m := memAt(c)
	q := Request{Client: "1.2.3.4", Key: "acme", Rate: Rate{Limit: 1000, Period: time.Second, Burst: 1000}, Month: 10}
	for i, want := range []struct {
		cost, used int64
		reason     Reason
	}{{4, 4, OK}, {4, 8, OK}, {4, 8, Monthly}, {2, 10, OK}, {1, 10, Monthly}} {
		q.Cost = want.cost
		res := mustCheck(t, m, q)
		if res.Used != want.used || res.Reason != want.reason || res.Allowed != (want.reason == OK) {
			t.Fatalf("step %d: %+v", i, res)
		}
	}
	if n, _ := m.Used(ctx, "acme"); n != 10 {
		t.Fatalf("Used %d", n)
	}
	q.Month, q.Cost = 0, 100
	if res := mustCheck(t, m, q); !res.Allowed {
		t.Fatal("month 0 means uncapped")
	}
	c.add(2 * time.Hour) // February
	q.Month, q.Cost = 10, 1
	if res := mustCheck(t, m, q); !res.Allowed || res.Used != 1 {
		t.Fatalf("new month should start at 0: %+v", res)
	}
}

// Nothing is spent unless every check passes.
func TestCheckSpendsOnlyWhenAllPass(t *testing.T) {
	m := memAt(newClock(time.Unix(1_700_000_000, 0))) // frozen: no refill
	q := Request{Key: "acme", Rate: Rate{Limit: 1, Period: time.Hour, Burst: 10}, Cost: 4, Month: 6}
	if res := mustCheck(t, m, q); !res.Allowed || res.Used != 4 || res.Remaining != 6 {
		t.Fatalf("first: %+v", res)
	}
	// Monthly reject (4+4 > 6) must not use burst: 6 units of burst are still there.
	if res := mustCheck(t, m, q); res.Reason != Monthly {
		t.Fatalf("want monthly: %+v", res)
	}
	q.Cost, q.Month = 6, 100
	if res := mustCheck(t, m, q); !res.Allowed || res.Remaining != 0 || res.Used != 10 {
		t.Fatalf("monthly reject spent burst: %+v", res)
	}
	// Burst reject must not bill the month.
	q.Cost = 1
	if res := mustCheck(t, m, q); res.Reason != Burst || res.Used != 10 {
		t.Fatalf("want burst: %+v", res)
	}
	if n, _ := m.Used(ctx, "acme"); n != 10 {
		t.Fatalf("burst reject billed the month: %d", n)
	}
}

func TestBanList(t *testing.T) {
	l := NewBanList()
	now := time.Now()
	for _, b := range []Ban{
		{Client: "192.0.2.1", Until: now.Add(time.Hour)},
		{Client: "10.99.0.3/30", Until: now.Add(time.Hour)}, // stored masked: 10.99.0.0/30
		{Client: "2001:db8::/32", Until: now.Add(time.Hour)},
		{Client: "198.51.100.9/32", Until: now.Add(time.Hour)}, // single IP: exact
		{Client: "203.0.113.0/24", Until: now.Add(-time.Second)},
		{Client: "::ffff:172.16.5.0/120", Until: now.Add(time.Hour)}, // mapped: becomes 172.16.5.0/24
	} {
		l.Ban(ctx, b)
	}
	if err := l.Ban(ctx, Ban{Client: "::ffff:0.0.0.0/95", Until: now.Add(time.Hour)}); !errors.Is(err, ErrBadBan) {
		t.Fatalf("mapped prefix under /96 must be refused: %v", err)
	}
	for client, want := range map[string]bool{
		"192.0.2.1": true, "192.0.2.2": false,
		"10.99.0.0": true, "10.99.0.3": true, "10.99.0.4": false, "::ffff:10.99.0.1": true,
		"2001:db8:1::7": true, "2001:db9::1": false,
		"198.51.100.9": true, "203.0.113.5": false, "not-an-ip": false,
		"172.16.5.200": true, "::ffff:172.16.5.1": true, "172.16.6.1": false,
	} {
		if _, got := l.Banned(client, now); got != want {
			t.Errorf("%s: banned %v, want %v", client, got, want)
		}
	}
	bs, _ := l.Bans(ctx)
	if len(bs) != 5 || l.snap.Load().byClient["10.99.0.0/30"].Client != "10.99.0.0/30" || l.snap.Load().byClient["172.16.5.0/24"].Client == "" {
		t.Fatalf("bans %+v", bs)
	}
	l.Unban(ctx, "10.99.0.1/30") // any spelling of the same prefix
	if _, ok := l.Banned("10.99.0.1", now); ok {
		t.Fatal("unban by prefix failed")
	}
}

type failing struct{ calls atomic.Int64 }

var errDown = errors.New("down")

func (f *failing) Allow(context.Context, string, Rate, int64) (Result, error) {
	f.calls.Add(1)
	return Result{}, errDown
}
func (f *failing) Check(context.Context, Request) (Result, error) {
	f.calls.Add(1)
	return Result{}, errDown
}
func (f *failing) Used(context.Context, string) (int64, error) { return 0, errDown }
func (f *failing) Ban(context.Context, Ban) error              { return errDown }
func (f *failing) Unban(context.Context, string) error         { return errDown }
func (f *failing) Bans(context.Context) ([]Ban, error)         { return nil, errDown }

func TestFallback(t *testing.T) {
	p := &failing{}
	f := NewFallback(p, NewMemory(), nil)
	r := Rate{Limit: 1, Period: time.Second, Burst: 2}
	for range 3 {
		res, err := f.Allow(ctx, "k", r, 1)
		if err != nil || !res.Degraded {
			t.Fatalf("%+v %v", res, err)
		}
	}
	if p.calls.Load() != 1 {
		t.Fatalf("breaker should skip primary, got %d calls", p.calls.Load())
	}
	f.(*fallback).openUntil.Store(0) // cooldown over
	if res, _ := f.Allow(ctx, "k", r, 1); res.Allowed || p.calls.Load() != 2 {
		t.Fatalf("should retry primary then use backup state: %+v", res)
	}
	if _, err := f.Allow(ctx, "k", Rate{}, 1); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}

	ok := NewFallback(NewMemory(), p, nil)
	if res, _ := ok.Check(ctx, Request{Key: "k", Rate: r, Cost: 1, Month: 5}); res.Degraded || !res.Allowed || res.Used != 1 {
		t.Fatalf("healthy primary: %+v", res)
	}

	// Bans, usage and checks all go to the backup while the primary is down.
	f = NewFallback(&failing{}, NewMemory(), nil)
	if err := f.Ban(ctx, Ban{Client: "10.0.0.0/8", Until: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if res, _ := f.Check(ctx, Request{Client: "10.1.2.3", Key: "k", Rate: r, Cost: 1}); res.Reason != Banned || !res.Degraded {
		t.Fatalf("backup ban: %+v", res)
	}
	if bs, err := f.Bans(ctx); err != nil || len(bs) != 1 {
		t.Fatalf("backup bans %v %v", bs, err)
	}
}

// While Redis is down each of n replicas gets 1/n of the budget, never below one request's cost.
func TestFallbackSharesBudget(t *testing.T) {
	r := Rate{Limit: 10, Period: time.Second, Burst: 30}
	for _, c := range []struct {
		n, cost   int64
		burst     int64
		perSecond float64
	}{{1, 1, 30, 10}, {3, 1, 10, 10.0 / 3}, {4, 1, 7, 2.5}, {100, 5, 5, 0.1}} {
		got := share(r, int(c.n), c.cost)
		if got.Burst != c.burst || float64(got.Limit)/got.Period.Seconds() != c.perSecond {
			t.Errorf("n=%d cost=%d: %+v", c.n, c.cost, got)
		}
	}

	n := 3
	f := NewFallback(&failing{}, memAt(newClock(time.Unix(1_700_000_000, 0))), func() int { return n })
	admitted := 0
	for range 50 {
		if res, _ := f.Check(ctx, Request{Key: "k", Rate: r, Cost: 1}); res.Allowed {
			admitted++
		}
	}
	if admitted != 10 { // burst 30 / 3 replicas
		t.Fatalf("admitted %d, want 10", admitted)
	}
}

func BenchmarkLocalSingleKey(b *testing.B) {
	l := NewLocal()
	r := Rate{Limit: 1e9, Period: time.Second, Burst: 1e9}
	b.ReportAllocs()
	for b.Loop() {
		l.Allow(ctx, "tenant-a", r, 1)
	}
}

func keys512() []string {
	k := make([]string, 512)
	for i := range k {
		k[i] = "tenant-" + strconv.Itoa(i)
	}
	return k
}

func Benchmark512Keys(b *testing.B) {
	l, ks := NewLocal(), keys512()
	r := Rate{Limit: 1e9, Period: time.Second, Burst: 1e9}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		l.Allow(ctx, ks[i&511], r, 1)
		i++
	}
}

func BenchmarkParallel512Keys(b *testing.B) {
	l, ks := NewLocal(), keys512()
	r := Rate{Limit: 1e9, Period: time.Second, Burst: 1e9}
	b.ReportAllocs()
	var seed atomic.Int64
	b.RunParallel(func(pb *testing.PB) {
		i := int(seed.Add(97))
		for pb.Next() {
			l.Allow(ctx, ks[i&511], r, 1)
			i++
		}
	})
}

// The gateway's local path: ban lookup, monthly cap and GCRA under one shard lock.
func BenchmarkMemoryCheck(b *testing.B) {
	m, ks := NewMemory(), keys512()
	m.Ban(ctx, Ban{Client: "10.0.0.0/8", Until: time.Now().Add(time.Hour)}) // one CIDR length to scan
	q := Request{Client: "203.0.113.7", Rate: Rate{Limit: 1e9, Period: time.Second, Burst: 1e9}, Cost: 1, Month: 1 << 60}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		q.Key = ks[i&511]
		m.Check(ctx, q)
		i++
	}
}

func BenchmarkBanned(b *testing.B) {
	l, now := NewBanList(), time.Now()
	for i := range 1000 {
		l.Ban(ctx, Ban{Client: "198.51.100." + strconv.Itoa(i%256), Until: now.Add(time.Hour)})
	}
	for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.0.2.0/24", "2001:db8::/32"} {
		l.Ban(ctx, Ban{Client: c, Until: now.Add(time.Hour)})
	}
	for _, c := range []struct{ name, ip string }{{"exact", "198.51.100.7"}, {"miss", "203.0.113.7"}} {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				l.Banned(c.ip, now)
			}
		})
	}
}
