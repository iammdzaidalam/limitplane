package limiter

import (
	"encoding/json"
	"errors"
	"math/rand/v2"
	"testing"
	"time"
)

var t0 = time.Unix(1_700_000_000, 0)

// Waiting exactly RetryAfter is enough, and one nanosecond less is not, for any rate and cost.
func TestRetryAfterIsExact(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for i := range 300 {
		r := Rate{Limit: 1 + rng.Int64N(1000), Period: time.Duration(1+rng.Int64N(60_000)) * time.Millisecond, Burst: 1 + rng.Int64N(50)}
		cost := 1 + rng.Int64N(r.Burst)
		c := newClock(t0)
		l := localAt(c)
		for range r.Burst + 1 { // drain, ending on a reject
			c.add(time.Duration(rng.Int64N(int64(r.Interval()))))
			res := mustAllow(t, l, "k", r, cost)
			if res.Allowed {
				continue
			}
			if res.RetryAfter <= 0 || res.ResetAfter < res.RetryAfter {
				t.Fatalf("case %d %+v cost %d: reject %+v", i, r, cost, res)
			}
			c.add(res.RetryAfter - 1)
			if mustAllow(t, l, "k", r, cost).Allowed {
				t.Fatalf("case %d %+v cost %d: allowed 1ns before RetryAfter", i, r, cost)
			}
			c.add(1)
			if !mustAllow(t, l, "k", r, cost).Allowed {
				t.Fatalf("case %d %+v cost %d: rejected at RetryAfter", i, r, cost)
			}
		}
	}
}

// Over a long run the limiter admits exactly burst + elapsed/interval.
func TestSustainedRateIsExact(t *testing.T) {
	c := newClock(t0)
	l := localAt(c)
	r := Rate{Limit: 10, Period: time.Second, Burst: 5}
	n := 0
	for ms := 0; ms <= 10_000; ms++ { // one request every millisecond for 10s
		if mustAllow(t, l, "k", r, 1).Allowed {
			n++
		}
		c.add(time.Millisecond)
	}
	if n != 5+100 {
		t.Fatalf("admitted %d, want 105", n)
	}
}

func TestCostAboveBurstNeverPasses(t *testing.T) {
	c := newClock(t0)
	l := localAt(c)
	r := Rate{Limit: 1, Period: time.Second, Burst: 3}
	for range 3 {
		c.add(24 * time.Hour)
		if res := mustAllow(t, l, "k", r, 4); res.Allowed || res.Reason != Burst || res.Remaining != 3 {
			t.Fatalf("cost 4 > burst 3: %+v", res)
		}
	}
	// The rejects spent nothing: the whole burst is still there for cost 3.
	if res := mustAllow(t, l, "k", r, 3); !res.Allowed || res.Remaining != 0 {
		t.Fatalf("cost == burst from full: %+v", res)
	}
	if res := mustAllow(t, l, "k", r, 3); res.Allowed {
		t.Fatalf("cost == burst needs a full bucket: %+v", res)
	}
}

func TestInvalidInputs(t *testing.T) {
	ok := Rate{Limit: 1, Period: time.Second, Burst: 1}
	for name, c := range map[string]struct {
		r    Rate
		cost int64
	}{
		"cost 0":             {ok, 0},
		"negative cost":      {ok, -1},
		"limit 0":            {Rate{Period: time.Second}, 1},
		"negative limit":     {Rate{Limit: -5, Period: time.Second}, 1},
		"period 0":           {Rate{Limit: 1}, 1},
		"negative period":    {Rate{Limit: 1, Period: -time.Second}, 1},
		"interval under 1ns": {Rate{Limit: 2, Period: 1}, 1},
	} {
		m := memAt(newClock(t0))
		if _, err := m.Allow(ctx, "k", c.r, c.cost); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Allow %v", name, err)
		}
		if _, err := m.Check(ctx, Request{Key: "k", Rate: c.r, Cost: c.cost, Month: 10}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Check %v", name, err)
		}
		if n, _ := m.Used(ctx, "k"); n != 0 || m.size() != 0 {
			t.Errorf("%s: an invalid request left state behind", name)
		}
	}
}

// A key idle for centuries is simply full again: no overflow from the gap.
func TestHugeGap(t *testing.T) {
	c := newClock(time.Unix(0, 1))
	l := localAt(c)
	r := Rate{Limit: 1, Period: time.Second, Burst: 2}
	mustAllow(t, l, "k", r, 2)
	c.t.Store(time.Date(2250, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	if res := mustAllow(t, l, "k", r, 1); !res.Allowed || res.Remaining != 1 || res.ResetAfter != time.Second {
		t.Fatalf("after a 280-year gap: %+v", res)
	}
}

// A wall clock stepping back never lets more through: the key just waits out the step.
func TestClockBackwardsNeverOverAdmits(t *testing.T) {
	c := newClock(t0)
	l := localAt(c)
	r := Rate{Limit: 1, Period: time.Second, Burst: 3}
	for range 3 {
		mustAllow(t, l, "k", r, 1)
	}
	c.add(-time.Hour)
	for i := range time.Duration(10) {
		if res := mustAllow(t, l, "k", r, 1); res.Allowed || res.RetryAfter != time.Hour+time.Second-i*time.Second {
			t.Fatalf("after stepping back: %+v", res)
		}
		c.add(time.Second)
	}
	c.add(time.Hour - 10*time.Second + time.Second) // back where we were, plus one interval
	if res := mustAllow(t, l, "k", r, 1); !res.Allowed {
		t.Fatalf("clock caught up: %+v", res)
	}
}

// Remaining feeds the RateLimit-Remaining header, so it must never go below 0. It does when the
// stored tat is further ahead than the current rate's burst allows: the wall clock stepped back,
// or the key's tier was lowered by a policy reload while it was busy.
func TestRemainingNeverNegative(t *testing.T) {
	c := newClock(t0)
	l := localAt(c)
	pro := Rate{Limit: 100, Period: time.Second, Burst: 100}
	for range 100 {
		mustAllow(t, l, "k", pro, 1)
	}
	free := Rate{Limit: 10, Period: time.Second, Burst: 5} // downgraded mid-burst: 0.5s of burst, 1s queued
	if res := mustAllow(t, l, "k", free, 1); res.Remaining < 0 {
		t.Fatalf("after a tier downgrade: %+v", res)
	}
	c.add(-time.Minute)
	if res := mustAllow(t, l, "k", pro, 1); res.Remaining < 0 {
		t.Fatalf("after the clock stepped back: %+v", res)
	}
}

// burst*interval is computed in int64 nanoseconds. A slow rate with a big burst (1 a day, burst
// a million) wraps it negative and the key rejects everything; Redis (Lua doubles) admits.
func TestLongBurstWindowDoesNotOverflow(t *testing.T) {
	l := localAt(newClock(t0))
	r := Rate{Limit: 1, Period: 24 * time.Hour, Burst: 1_000_000}
	if res := mustAllow(t, l, "k", r, 1); !res.Allowed || res.Remaining != r.Burst-1 {
		t.Fatalf("first request of a fresh key: %+v", res)
	}
}

// Allow is Check with no client and no monthly cap.
func TestAllowMatchesCheck(t *testing.T) {
	c := newClock(t0)
	a, b := memAt(c), memAt(c)
	r := Rate{Limit: 3, Period: time.Second, Burst: 4}
	for i := range 20 {
		cost := int64(i%3 + 1)
		x := mustAllow(t, a, "k", r, cost)
		y := mustCheck(t, b, Request{Key: "k", Rate: r, Cost: cost})
		if x != y {
			t.Fatalf("step %d: Allow %+v, Check %+v", i, x, y)
		}
		c.add(170 * time.Millisecond)
	}
}

// Shards only spread lock contention: the decisions must not depend on how many there are.
func TestShardCountDoesNotChangeDecisions(t *testing.T) {
	var want []bool
	ks := keys512()
	for _, n := range []int{1, 2, 8, 64} {
		c := newClock(t0)
		l := &Local{shards: make([]shard, n), mask: uint32(n - 1), now: c.now}
		for i := range l.shards {
			l.shards[i].tat, l.shards[i].used = map[string]int64{}, map[string]int64{}
		}
		var got []bool
		for step := range 200 {
			res := mustAllow(t, l, ks[step%37], Rate{Limit: 2, Period: time.Second, Burst: 3}, 1)
			got = append(got, res.Allowed)
			c.add(90 * time.Millisecond)
		}
		if want == nil {
			want = got
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("%d shards: decision %d differs from 1 shard", n, i)
			}
		}
	}
}

// sameShard is another key that lands in key's shard.
func sameShard(l *Local, key string) string {
	for _, k := range keys512() {
		if k != key && l.shard(k) == l.shard(key) {
			return k
		}
	}
	panic("no key shares a shard with " + key)
}

func has(l *Local, key string) bool {
	s := l.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.tat[key]
	return ok
}

// The sweep only drops keys that have fully refilled, so it never hands out burst.
func TestSweepNeverRefunds(t *testing.T) {
	c := newClock(t0)
	l := localAt(c)
	slow := Rate{Limit: 1, Period: time.Hour, Burst: 2}
	mustAllow(t, l, "drained", slow, 2)
	mustAllow(t, l, "idle", Rate{Limit: 1, Period: time.Second, Burst: 1}, 1)
	c.add(2 * time.Minute)
	for _, k := range []string{"drained", "idle"} { // a write after sweepEvery sweeps its shard
		mustAllow(t, l, sameShard(l, k), slow, 1)
	}
	if !has(l, "drained") || has(l, "idle") {
		t.Fatalf("sweep kept drained=%v idle=%v, want true false", has(l, "drained"), has(l, "idle"))
	}
	if res := mustAllow(t, l, "drained", slow, 1); res.Allowed {
		t.Fatalf("sweep refunded a drained key: %+v", res)
	}
}

func TestRateJSONEdges(t *testing.T) {
	var r Rate
	if err := json.Unmarshal([]byte(`{"limit":5,"period":"250ms"}`), &r); err != nil || r != (Rate{Limit: 5, Period: 250 * time.Millisecond}) || r.burst() != 5 {
		t.Fatalf("omitted burst: %+v %v", r, err)
	}
	for _, bad := range []string{`{"limit":1}`, `{"limit":1,"period":10}`, `{"limit":"x","period":"1s"}`, `[]`} {
		if json.Unmarshal([]byte(bad), &r) == nil {
			t.Errorf("%s: want error", bad)
		}
	}
}
