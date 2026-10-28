package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/gateway"
)

func newTestHub() *Hub {
	return NewHub(nil, func() map[string]string { return map[string]string{"acme": "free"} })
}

func TestHubAuditRing(t *testing.T) {
	h := newTestHub()
	now := time.Now()
	for i := range auditSize + 5 {
		h.process(event{d: gateway.Decision{Time: now, Cost: int64(i), Allowed: true}})
	}
	a := h.Audit(3)
	if len(a) != 3 || a[0].Cost != auditSize+4 || a[2].Cost != auditSize+2 {
		t.Fatalf("want newest first, got %+v", a)
	}
	if n := len(h.Audit(5000)); n != auditSize {
		t.Fatalf("ring holds %d, want %d", n, auditSize)
	}
}

func TestHubStatsAndMetrics(t *testing.T) {
	h := newTestHub()
	now := time.Unix(1_700_000_000, 0)
	h.process(event{d: gateway.Decision{Time: now.Add(-2 * time.Second), Tenant: "acme", Allowed: true, Reason: "ok"}, dur: 200 * time.Microsecond})
	h.process(event{d: gateway.Decision{Time: now, Tenant: "anonymous", Reason: "burst", Degraded: true}})
	h.process(event{d: gateway.Decision{Time: now, Tenant: "evil\"tenant", Reason: "burst"}})

	s, per := h.snapshot(now)
	if s.Total != 3 || s.Allowed != 1 || s.ByReason["burst"] != 2 || !s.Degraded {
		t.Fatalf("bad totals %+v", s)
	}
	if len(s.Series) != seriesSize || s.Series[seriesSize-1] != (point{now.Unix(), 0, 2}) || s.Series[seriesSize-3].Allowed != 1 || s.Series[0].T != now.Unix()-seriesSize+1 {
		t.Fatalf("bad series tail %+v", s.Series[seriesSize-3:])
	}
	if per["acme"].Allowed != 1 || per[anonLabel].Blocked != 2 {
		t.Fatalf("per tenant %+v", per)
	}

	h.Quota("acme", 85, 100)
	h.Quota("evil\"tenant", 1, 2) // unknown: no label
	var b strings.Builder
	h.writeMetrics(&b, 2, time.Now())
	out := b.String()
	for _, want := range []string{
		`limitplane_decisions_total{tenant="acme",reason="ok"} 1`,
		`limitplane_decisions_total{tenant="anon",reason="burst"} 2`, // unknown tenants collapse
		"limitplane_degraded_total 1",
		"limitplane_bans_active 2",
		`limitplane_check_seconds_bucket{le="0.0001"} 2`,
		`limitplane_check_seconds_bucket{le="0.00025"} 3`,
		`limitplane_check_seconds_bucket{le="+Inf"} 3`,
		"limitplane_check_seconds_count 3",
		`limitplane_quota_used_ratio{tenant="acme"} 0.85`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "evil") {
		t.Error("unknown tenant leaked into labels")
	}
	// Next month the gauge is stale until the tenant's next request.
	b.Reset()
	h.writeMetrics(&b, -1, time.Now().AddDate(0, 1, 0))
	if out := b.String(); strings.Contains(out, `ratio{tenant="acme"}`) || strings.Contains(out, "bans_active") {
		t.Errorf("stale gauge or unknown bans count:\n%s", out)
	}
}

func TestHubNeverBlocks(t *testing.T) {
	h := newTestHub()
	slow := h.Subscribe() // never read
	defer h.Unsubscribe(slow)
	done := make(chan struct{})
	go func() {
		for range queueSize * 2 { // no consumer running: queue fills, then drops
			h.OnDecision(gateway.Decision{Time: time.Now()})
		}
		for range 1000 {
			h.Publish("decision", 1)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("request path blocked")
	}
	if h.dropped.Load() != queueSize {
		t.Fatalf("dropped %d, want %d", h.dropped.Load(), queueSize)
	}
	if len(slow) != cap(slow) {
		t.Fatalf("slow subscriber buffer %d/%d", len(slow), cap(slow))
	}
}

func BenchmarkOnDecision(b *testing.B) {
	h := newTestHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	d := gateway.Decision{Time: time.Now(), Tenant: "acme", Allowed: true, Reason: "ok"}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			h.OnDecision(d)
		}
	})
}
