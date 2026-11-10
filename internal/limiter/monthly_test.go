package limiter

import (
	"testing"
	"time"
)

var wide = Rate{Limit: 1_000_000, Period: time.Second, Burst: 1_000_000} // never the limit here

func capped(key string, cost, month int64) Request {
	return Request{Key: key, Rate: wide, Cost: cost, Month: month}
}

// The count resets on the first nanosecond of the next UTC month, not a nanosecond earlier.
func TestMonthlyRolloverBoundaries(t *testing.T) {
	for _, first := range []time.Time{
		time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), // Jan 31 -> Feb
		time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), // year
		time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC), // Feb 28, non-leap
		time.Date(2028, 3, 1, 0, 0, 0, 0, time.UTC), // Feb 29, leap
		time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), // 30-day April
	} {
		c := newClock(first.Add(-time.Nanosecond))
		m := memAt(c)
		if res := mustCheck(t, m, capped("acme", 10, 10)); !res.Allowed || res.Used != 10 {
			t.Fatalf("%v: fill: %+v", first, res)
		}
		if res := mustCheck(t, m, capped("acme", 1, 10)); res.Reason != Monthly {
			t.Fatalf("%v: last ns of the month must still be capped: %+v", first, res)
		}
		c.add(time.Nanosecond)
		if n, _ := m.Used(ctx, "acme"); n != 0 {
			t.Fatalf("%v: Used %d in a fresh month", first, n)
		}
		if res := mustCheck(t, m, capped("acme", 1, 10)); !res.Allowed || res.Used != 1 {
			t.Fatalf("%v: first ns of the month: %+v", first, res)
		}
	}
}

// Months are UTC whatever zone the clock reports in.
func TestMonthlyIsUTC(t *testing.T) {
	kiritimati := time.FixedZone("+14", 14*3600)
	at := time.Date(2026, 3, 1, 5, 0, 0, 0, kiritimati) // still Feb 28 in UTC
	m := NewMemory()
	m.now = func() time.Time { return at }
	mustCheck(t, m, capped("acme", 7, 10))
	at = time.Date(2026, 2, 28, 23, 0, 0, 0, time.UTC)
	if n, _ := m.Used(ctx, "acme"); n != 7 {
		t.Fatalf("Used %d: a local-time month leaked in", n)
	}
	at = time.Date(2026, 2, 28, 15, 0, 0, 0, time.FixedZone("-10", -10*3600)) // Mar 1 01:00 UTC
	if n, _ := m.Used(ctx, "acme"); n != 0 {
		t.Fatalf("Used %d after the UTC rollover", n)
	}
}

func TestMonthlyEdges(t *testing.T) {
	m := memAt(newClock(time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)))
	if n, _ := m.Used(ctx, "fresh"); n != 0 {
		t.Fatalf("fresh key used %d", n)
	}
	// Uncapped traffic never bills the month.
	for range 5 {
		mustCheck(t, m, capped("acme", 3, 0))
	}
	if n, _ := m.Used(ctx, "acme"); n != 0 {
		t.Fatalf("uncapped requests billed %d", n)
	}
	// A cost above the cap never passes and spends nothing.
	if res := mustCheck(t, m, capped("acme", 11, 10)); res.Reason != Monthly || res.Used != 0 || res.Allowed {
		t.Fatalf("cost > cap: %+v", res)
	}
	// Exactly the cap passes.
	if res := mustCheck(t, m, capped("acme", 10, 10)); !res.Allowed || res.Used != 10 {
		t.Fatalf("cost == cap: %+v", res)
	}
	// Keys sharing a shard (and its month) still count separately.
	other := sameShard(m.Local, "acme")
	if res := mustCheck(t, m, capped(other, 4, 10)); !res.Allowed || res.Used != 4 {
		t.Fatalf("neighbour key: %+v", res)
	}
	if n, _ := m.Used(ctx, "acme"); n != 10 {
		t.Fatalf("acme used %d", n)
	}
}

// When both would fail, monthly wins: it is the one that holds until the 1st.
func TestMonthlyWinsOverBurst(t *testing.T) {
	m := memAt(newClock(t0))
	q := Request{Key: "acme", Rate: Rate{Limit: 1, Period: time.Hour, Burst: 2}, Cost: 2, Month: 3}
	mustCheck(t, m, q)
	if res := mustCheck(t, m, q); res.Reason != Monthly || res.Used != 2 {
		t.Fatalf("both exhausted: %+v", res)
	}
}
