package limiter

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// hammer runs f from 32 goroutines released together, 50 calls each, and counts the trues.
func hammer(f func(g, i int) bool) int64 {
	var n atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for g := range 32 {
		wg.Go(func() {
			<-start
			for i := range 50 {
				if f(g, i) {
					n.Add(1)
				}
			}
		})
	}
	close(start)
	wg.Wait()
	return n.Load()
}

// 1600 racing requests against a monthly cap of 300: exactly 300 pass, and Used agrees.
func TestMonthlyCapExactUnderConcurrency(t *testing.T) {
	m := memAt(newClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)))
	got := hammer(func(int, int) bool {
		res, err := m.Check(ctx, capped("acme", 1, 300))
		return err == nil && res.Allowed
	})
	if n, _ := m.Used(ctx, "acme"); got != 300 || n != 300 {
		t.Fatalf("admitted %d, used %d, want 300", got, n)
	}
}

// Burst and monthly together, mixed costs: what passed plus what is left is exactly the burst,
// and the month billed exactly what passed.
func TestBurstAndMonthlyExactUnderConcurrency(t *testing.T) {
	m := memAt(newClock(t0))
	r := Rate{Limit: 1, Period: time.Hour, Burst: 250}
	var spent atomic.Int64
	hammer(func(g, _ int) bool {
		cost := int64(g%3 + 1)
		res, _ := m.Check(ctx, Request{Key: "acme", Rate: r, Cost: cost, Month: 1000})
		if res.Allowed {
			spent.Add(cost)
		}
		return res.Allowed
	})
	n, _ := m.Used(ctx, "acme")
	if n != spent.Load() {
		t.Fatalf("passed %d units, billed %d", spent.Load(), n)
	}
	for mustCheck(t, m, Request{Key: "acme", Rate: r, Cost: 1, Month: 1000}).Allowed { // drain the rest
		spent.Add(1)
	}
	if spent.Load() != 250 {
		t.Fatalf("spent %d of burst 250", spent.Load())
	}
}

// New keys created concurrently all land, and each gets exactly its own burst.
func TestDistinctKeysIsolatedUnderConcurrency(t *testing.T) {
	l := localAt(newClock(t0))
	r := Rate{Limit: 1, Period: time.Hour, Burst: 3}
	var per [32]atomic.Int64
	hammer(func(g, i int) bool {
		res, _ := l.Allow(ctx, "tenant-"+strconv.Itoa(g), r, 1)
		if res.Allowed {
			per[g].Add(1)
		}
		return res.Allowed
	})
	for g := range per {
		if n := per[g].Load(); n != 3 {
			t.Fatalf("tenant-%d admitted %d, want 3", g, n)
		}
	}
	if n := l.size(); n != 32 {
		t.Fatalf("tracking %d keys, want 32", n)
	}
}

// Ban writes racing the request path: every request from the banned range is refused once its
// ban is in, and nothing outside it ever is.
func TestBansRaceChecks(t *testing.T) {
	m := memAt(newClock(t0))
	m.Ban(ctx, Ban{Client: "10.0.0.0/8", Until: time.Now().Add(time.Hour)})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			m.Ban(ctx, Ban{Client: "192.0.2." + strconv.Itoa(i%256), Until: time.Now().Add(time.Hour)})
		}
	})
	q := Request{Key: "k", Rate: Rate{Limit: 1e9, Period: time.Second, Burst: 1e9}, Cost: 1}
	bad := hammer(func(g, i int) bool {
		q := q
		q.Client = "10.1." + strconv.Itoa(g) + "." + strconv.Itoa(i)
		a, _ := m.Check(ctx, q)
		q.Client = "203.0.113." + strconv.Itoa(i)
		b, _ := m.Check(ctx, q)
		return a.Reason != Banned || b.Reason == Banned
	})
	close(stop)
	wg.Wait()
	if bad != 0 {
		t.Fatalf("%d wrong ban decisions", bad)
	}
}
