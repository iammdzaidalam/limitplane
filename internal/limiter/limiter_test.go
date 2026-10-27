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

func TestLocalQuota(t *testing.T) {
	c := newClock(time.Date(2026, 1, 31, 23, 0, 0, 0, time.UTC))
	q := NewLocalQuota()
	q.now = c.now
	k := MonthKey("acme", c.now())
	for i, want := range []struct {
		cost, used int64
		ok         bool
	}{{4, 4, true}, {4, 8, true}, {4, 8, false}, {2, 10, true}, {1, 10, false}} {
		used, ok, _ := q.Spend(ctx, k, 10, want.cost)
		if used != want.used || ok != want.ok {
			t.Fatalf("step %d: used %d ok %v", i, used, ok)
		}
	}
	if used, ok, _ := q.Spend(ctx, "free", 0, 1e6); !ok || used != 1e6 {
		t.Fatal("limit 0 means uncapped")
	}
	c.add(2 * time.Hour) // February
	k2 := MonthKey("acme", c.now())
	if used, ok, _ := q.Spend(ctx, k2, 10, 1); !ok || used != 1 {
		t.Fatalf("new month should start at 0: %d", used)
	}
	if len(q.used) != 1 {
		t.Fatalf("old months not cleaned: %v", q.used)
	}
}

type failing struct{ calls atomic.Int64 }

var errDown = errors.New("down")

func (f *failing) Allow(context.Context, string, Rate, int64) (Result, error) {
	f.calls.Add(1)
	return Result{}, errDown
}
func (f *failing) Spend(context.Context, string, int64, int64) (int64, bool, error) {
	f.calls.Add(1)
	return 0, false, errDown
}

func TestFallback(t *testing.T) {
	p := &failing{}
	f := NewFallback(p, NewLocal())
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

	ok := NewFallback(NewLocal(), p)
	if res, _ := ok.Allow(ctx, "k", r, 1); res.Degraded || !res.Allowed {
		t.Fatalf("healthy primary: %+v", res)
	}

	fq := NewFallbackQuota(&failing{}, NewLocalQuota())
	if used, ok, err := fq.Spend(ctx, "m", 5, 3); err != nil || !ok || used != 3 {
		t.Fatalf("quota fallback: %d %v %v", used, ok, err)
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
