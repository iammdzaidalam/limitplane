package limiter

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/redisx"
)

// switchable is a Memory that fails every call with err while err is set.
type switchable struct {
	*Memory
	err   atomic.Pointer[error]
	calls atomic.Int64
}

func newSwitchable() *switchable { return &switchable{Memory: NewMemory()} }

func (s *switchable) fail(err error) { s.err.Store(&err) }
func (s *switchable) heal()          { s.err.Store(nil) }
func (s *switchable) failing() error {
	s.calls.Add(1)
	if p := s.err.Load(); p != nil {
		return *p
	}
	return nil
}

func (s *switchable) Allow(ctx context.Context, k string, r Rate, c int64) (Result, error) {
	if err := s.failing(); err != nil {
		return Result{}, err
	}
	return s.Memory.Allow(ctx, k, r, c)
}

func (s *switchable) Check(ctx context.Context, q Request) (Result, error) {
	if err := s.failing(); err != nil {
		return Result{}, err
	}
	return s.Memory.Check(ctx, q)
}

func (s *switchable) Used(ctx context.Context, k string) (int64, error) {
	if err := s.failing(); err != nil {
		return 0, err
	}
	return s.Memory.Used(ctx, k)
}

func (s *switchable) Ban(ctx context.Context, b Ban) error {
	if err := s.failing(); err != nil {
		return err
	}
	return s.Memory.Ban(ctx, b)
}

func (s *switchable) Unban(ctx context.Context, c string) error {
	if err := s.failing(); err != nil {
		return err
	}
	return s.Memory.Unban(ctx, c)
}

func (s *switchable) Bans(ctx context.Context) ([]Ban, error) {
	if err := s.failing(); err != nil {
		return nil, err
	}
	return s.Memory.Bans(ctx)
}

var oneUnit = Request{Key: "k", Rate: Rate{Limit: 100, Period: time.Second, Burst: 100}, Cost: 1}

func degraded(t *testing.T, f Backend) bool {
	t.Helper()
	res, err := f.Check(ctx, oneUnit)
	if err != nil {
		t.Fatal(err)
	}
	return res.Degraded
}

// closed -> (error) open -> (cooldown) retry primary -> closed again if it answers.
func TestBreakerTransitions(t *testing.T) {
	p := newSwitchable()
	f := NewFallback(p, NewMemory(), nil)
	fb := f.(*fallback)
	if degraded(t, f) || !fb.closed() {
		t.Fatal("healthy primary must answer")
	}
	p.fail(errDown)
	if !degraded(t, f) || fb.closed() {
		t.Fatal("first failure must trip the breaker and answer from the backup")
	}
	if until := time.Unix(0, fb.openUntil.Load()); time.Until(until) > cooldown || time.Until(until) < cooldown-time.Second/2 {
		t.Fatalf("open for %v, want about %v", time.Until(until), cooldown)
	}
	calls := p.calls.Load()
	for range 10 {
		degraded(t, f)
	}
	if p.calls.Load() != calls {
		t.Fatal("an open breaker still called the primary")
	}
	fb.openUntil.Store(0) // cooldown over, primary still down: one probe, then open again
	if !degraded(t, f) || p.calls.Load() != calls+1 || fb.closed() {
		t.Fatal("probe of a still-dead primary must re-trip")
	}
	p.heal()
	fb.openUntil.Store(0)
	if degraded(t, f) || !fb.closed() {
		t.Fatal("a recovered primary must close the breaker")
	}
}

// What must not fail over: caller cancels and bad input belong to the caller, not to Redis.
func TestFailoverOnlyForBackendErrors(t *testing.T) {
	for name, c := range map[string]struct {
		err      error
		cancel   bool
		failover bool
		trips    bool
	}{
		"backend error":     {err: errDown, failover: true, trips: true},
		"one cluster node":  {err: fmt.Errorf("%w: 10.0.0.3:6379", redisx.ErrNodeDown), failover: true},
		"invalid rate":      {err: ErrInvalid},
		"bad ban":           {err: ErrBadBan},
		"caller cancelled":  {err: context.Canceled, cancel: true},
		"deadline, ctx set": {err: errDown, cancel: true},
	} {
		p := newSwitchable()
		p.fail(c.err)
		f := NewFallback(p, NewMemory(), nil)
		cctx, cancel := context.WithCancel(ctx)
		if c.cancel {
			cancel()
		}
		res, err := f.Check(cctx, oneUnit)
		cancel()
		if c.failover != (err == nil && res.Degraded) {
			t.Errorf("%s: res %+v err %v, failover want %v", name, res, err, c.failover)
		}
		if !c.failover && !errors.Is(err, c.err) {
			t.Errorf("%s: want the primary's error, got %v", name, err)
		}
		if tripped := !f.(*fallback).closed(); tripped != c.trips {
			t.Errorf("%s: tripped %v, want %v", name, tripped, c.trips)
		}
	}
}

// A Cluster node failing sends only that request to the backup: the next one tries Redis again.
func TestNodeDownDoesNotOpenBreaker(t *testing.T) {
	p := newSwitchable()
	f := NewFallback(p, NewMemory(), nil)
	p.fail(fmt.Errorf("%w: 10.0.0.3:6379", redisx.ErrNodeDown))
	for range 3 {
		if !degraded(t, f) {
			t.Fatal("node down must answer from the backup")
		}
	}
	if p.calls.Load() != 3 {
		t.Fatalf("primary called %d times, want every request", p.calls.Load())
	}
	p.heal()
	if degraded(t, f) {
		t.Fatal("node back: shared again at once")
	}
}

// Every operation falls back, and the backup's answers come back as they are.
func TestFallbackEveryOp(t *testing.T) {
	p, b := newSwitchable(), NewMemory()
	p.fail(errDown)
	f := NewFallback(p, b, nil)
	until := time.Now().Add(time.Minute)
	if err := f.Ban(ctx, Ban{Client: "192.0.2.1", Until: until}); err != nil {
		t.Fatal(err)
	}
	if err := f.Ban(ctx, Ban{Client: "::ffff:0:0/90", Until: until}); !errors.Is(err, ErrBadBan) {
		t.Fatalf("the backup's ErrBadBan: %v", err)
	}
	mustCheck(t, f, Request{Key: "acme", Rate: oneUnit.Rate, Cost: 3, Month: 10})
	if n, err := f.Used(ctx, "acme"); err != nil || n != 3 {
		t.Fatalf("Used %d %v", n, err)
	}
	if res, _ := f.Allow(ctx, "k", oneUnit.Rate, 1); !res.Degraded || !res.Allowed {
		t.Fatalf("Allow %+v", res)
	}
	if err := f.Unban(ctx, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if bs, err := f.Bans(ctx); err != nil || len(bs) != 0 {
		t.Fatalf("Bans %v %v", bs, err)
	}

	// Both down: the backup's error is what the caller sees.
	both := NewFallback(p, &failing{}, nil)
	if _, err := both.Check(ctx, oneUnit); !errors.Is(err, errDown) {
		t.Fatalf("both down: %v", err)
	}
	if _, err := both.Used(ctx, "acme"); !errors.Is(err, errDown) {
		t.Fatalf("both down Used: %v", err)
	}
}

func TestShareEdges(t *testing.T) {
	r := Rate{Limit: 10, Period: time.Second, Burst: 30}
	for _, n := range []int{-1, 0, 1} {
		if got := share(r, n, 1); got != r {
			t.Errorf("n=%d: %+v, want the full rate", n, got)
		}
	}
	// Burst 0 means Limit, and the split uses that.
	if got := share(Rate{Limit: 12, Period: time.Second}, 4, 1); got.Burst != 3 || got.Period != 4*time.Second {
		t.Errorf("burst 0: %+v", got)
	}
	// The split never drops below one request's cost, however many replicas.
	if got := share(r, 1000, 7); got.Burst != 7 {
		t.Errorf("tiny share: %+v", got)
	}
}

// The replica count is read per request, so a scale-up during an outage tightens the share at once.
func TestShareFollowsReplicaCount(t *testing.T) {
	var n atomic.Int64
	n.Store(1)
	f := NewFallback(&failing{}, memAt(newClock(t0)), func() int { return int(n.Load()) })
	r := Rate{Limit: 1, Period: time.Hour, Burst: 12}
	count := func(key string) int {
		admitted := 0
		for range 20 {
			if res, _ := f.Check(ctx, Request{Key: key, Rate: r, Cost: 1}); res.Allowed {
				admitted++
			}
		}
		return admitted
	}
	for _, c := range []struct {
		replicas int64
		want     int
	}{{1, 12}, {3, 4}, {6, 2}, {100, 1}} {
		n.Store(c.replicas)
		if got := count(fmt.Sprint("k", c.replicas)); got != c.want {
			t.Errorf("%d replicas: admitted %d, want %d", c.replicas, got, c.want)
		}
	}
}

// Many requests racing through a tripping breaker: each is answered once, by one side.
func TestFallbackConcurrent(t *testing.T) {
	p := newSwitchable()
	backup := memAt(newClock(t0))
	f := NewFallback(p, backup, func() int { return 2 })
	r := Rate{Limit: 1, Period: time.Hour, Burst: 200}
	p.fail(errDown)
	var admitted atomic.Int64
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 50 {
				res, err := f.Check(ctx, Request{Key: "hot", Rate: r, Cost: 1})
				if err != nil || !res.Degraded {
					t.Errorf("%+v %v", res, err)
					return
				}
				if res.Allowed {
					admitted.Add(1)
				}
			}
		})
	}
	wg.Wait()
	if admitted.Load() != 100 { // burst 200 split over 2 replicas
		t.Fatalf("admitted %d, want 100", admitted.Load())
	}
}
