package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/gateway"
)

const (
	auditSize  = 1000
	seriesSize = 120
	queueSize  = 8192
	anonLabel  = "anon"
)

// Check-latency buckets in seconds: local GCRA is ~µs, a Redis round trip ~ms.
var latencyBuckets = [...]float64{.00005, .0001, .00025, .0005, .001, .0025, .005, .01, .025, .05, .1, .25}

type event struct {
	d   gateway.Decision
	dur time.Duration
}

type point struct {
	T       int64 `json:"t"`
	Allowed int64 `json:"allowed"`
	Blocked int64 `json:"blocked"`
}

type counts struct{ Allowed, Blocked int64 }

// Hub fans each decision out to the audit ring, stats, metrics, SSE and the autopilot.
// The request path only does a non-blocking channel send; one goroutine does the rest,
// so request goroutines never contend on the stats lock or pay for JSON encoding.
type Hub struct {
	in      chan event
	dropped atomic.Int64
	observe func(gateway.Decision)
	known   func() map[string]string // tenant -> tier; bounds metric label cardinality
	done    chan struct{}

	mu        sync.Mutex
	audit     [auditSize]gateway.Decision
	auditN    int // total ever written
	series    [seriesSize]point
	total     counts
	byReason  map[string]int64
	tenants   map[string]*counts
	decisions map[[2]string]int64 // {tenant label, reason}
	degraded  int64
	lastDeg   time.Time
	hist      [len(latencyBuckets) + 1]int64 // last is +Inf
	histSum   float64
	tenantSet map[string]string

	subMu sync.Mutex
	subs  map[chan []byte]struct{}
}

func NewHub(observe func(gateway.Decision), known func() map[string]string) *Hub {
	h := &Hub{
		in: make(chan event, queueSize), observe: observe, known: known, done: make(chan struct{}),
		byReason: map[string]int64{}, tenants: map[string]*counts{}, decisions: map[[2]string]int64{},
		subs: map[chan []byte]struct{}{},
	}
	if known != nil {
		h.tenantSet = known()
	}
	return h
}

// OnDecision is the gateway hook. Drops (and counts) when the consumer falls behind.
// Latency assumes Decision.Time is stamped when the check starts.
func (h *Hub) OnDecision(d gateway.Decision) {
	select {
	case h.in <- event{d, time.Since(d.Time)}:
	default:
		h.dropped.Add(1)
	}
}

// Run consumes decisions until ctx ends, then closes Done so SSE streams end.
func (h *Hub) Run(ctx context.Context) {
	defer close(h.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-h.in:
			h.process(e)
		case <-tick.C:
			if h.known != nil {
				ks := h.known()
				h.mu.Lock()
				h.tenantSet = ks
				h.mu.Unlock()
			}
		}
	}
}

func (h *Hub) Done() <-chan struct{} { return h.done }

func (h *Hub) process(e event) {
	d := e.d
	label := anonLabel
	h.mu.Lock()
	if _, ok := h.tenantSet[d.Tenant]; ok {
		label = d.Tenant
	}
	h.audit[h.auditN%auditSize] = d
	h.auditN++

	sec := d.Time.Unix()
	p := &h.series[sec%seriesSize]
	if p.T != sec {
		*p = point{T: sec}
	}
	c := h.tenants[label]
	if c == nil {
		c = &counts{}
		h.tenants[label] = c
	}
	if d.Allowed {
		p.Allowed++
		h.total.Allowed++
		c.Allowed++
	} else {
		p.Blocked++
		h.total.Blocked++
		c.Blocked++
		h.byReason[d.Reason]++
	}
	h.decisions[[2]string{label, d.Reason}]++
	if d.Degraded {
		h.degraded++
		h.lastDeg = d.Time
	}
	s := e.dur.Seconds()
	i, _ := slices.BinarySearch(latencyBuckets[:], s)
	h.hist[i]++
	h.histSum += s
	h.mu.Unlock()

	h.Publish("decision", d)
	if h.observe != nil {
		h.observe(d)
	}
}

// Publish sends an SSE event to every subscriber, skipping any whose buffer is full.
func (h *Hub) Publish(event string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	msg := []byte("event: " + event + "\ndata: " + string(b) + "\n\n")
	h.subMu.Lock()
	defer h.subMu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- msg:
		default: // slow consumer: drop rather than stall the hub
		}
	}
}

func (h *Hub) Subscribe() chan []byte {
	ch := make(chan []byte, 64)
	h.subMu.Lock()
	h.subs[ch] = struct{}{}
	h.subMu.Unlock()
	return ch
}

func (h *Hub) Unsubscribe(ch chan []byte) {
	h.subMu.Lock()
	delete(h.subs, ch)
	h.subMu.Unlock()
}

// Audit returns up to limit decisions, newest first.
func (h *Hub) Audit(limit int) []gateway.Decision {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := min(limit, h.auditN, auditSize)
	out := make([]gateway.Decision, n)
	for i := range n {
		out[i] = h.audit[(h.auditN-1-i)%auditSize]
	}
	return out
}

type stats struct {
	Total    int64            `json:"total"`
	Allowed  int64            `json:"allowed"`
	Blocked  int64            `json:"blocked"`
	ByReason map[string]int64 `json:"byReason"` // blocked decisions only
	Tenants  []tenantStats    `json:"tenants"`
	Series   []point          `json:"series"`
	Degraded bool             `json:"degraded"`
	Backend  string           `json:"backend"`
}

type tenantStats struct {
	Tenant       string `json:"tenant"`
	Tier         string `json:"tier"`
	Allowed      int64  `json:"allowed"`
	Blocked      int64  `json:"blocked"`
	MonthlyUsed  int64  `json:"monthlyUsed"`
	MonthlyLimit int64  `json:"monthlyLimit"`
}

// snapshot returns totals, the last 120s oldest first (gaps zero-filled), and per-label counts.
func (h *Hub) snapshot(now time.Time) (stats, map[string]counts) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := stats{
		Total: h.total.Allowed + h.total.Blocked, Allowed: h.total.Allowed, Blocked: h.total.Blocked,
		ByReason: maps.Clone(h.byReason), Series: make([]point, seriesSize),
		Degraded: !h.lastDeg.IsZero() && now.Sub(h.lastDeg) < 10*time.Second,
	}
	end := now.Unix()
	for i := range seriesSize {
		t := end - seriesSize + 1 + int64(i)
		p := h.series[t%seriesSize]
		if p.T != t {
			p = point{T: t}
		}
		s.Series[i] = p
	}
	per := make(map[string]counts, len(h.tenants))
	for k, c := range h.tenants {
		per[k] = *c
	}
	return s, per
}

// writeMetrics renders Prometheus text exposition format 0.0.4.
func (h *Hub) writeMetrics(w io.Writer, bans int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fmt.Fprint(w, "# HELP limitplane_decisions_total Rate limit decisions by tenant and reason.\n# TYPE limitplane_decisions_total counter\n")
	keys := slices.SortedFunc(maps.Keys(h.decisions), func(a, b [2]string) int {
		return strings.Compare(a[0]+"\x00"+a[1], b[0]+"\x00"+b[1])
	})
	for _, k := range keys {
		fmt.Fprintf(w, "limitplane_decisions_total{tenant=%s,reason=%s} %d\n", quote(k[0]), quote(k[1]), h.decisions[k])
	}
	fmt.Fprintf(w, "# HELP limitplane_degraded_total Decisions answered by the local fallback.\n# TYPE limitplane_degraded_total counter\nlimitplane_degraded_total %d\n", h.degraded)
	fmt.Fprintf(w, "# HELP limitplane_events_dropped_total Decisions dropped because the event queue was full.\n# TYPE limitplane_events_dropped_total counter\nlimitplane_events_dropped_total %d\n", h.dropped.Load())
	fmt.Fprintf(w, "# HELP limitplane_bans_active Clients currently banned.\n# TYPE limitplane_bans_active gauge\nlimitplane_bans_active %d\n", bans)
	fmt.Fprint(w, "# HELP limitplane_check_seconds Time spent deciding a request.\n# TYPE limitplane_check_seconds histogram\n")
	var cum int64
	for i, le := range latencyBuckets {
		cum += h.hist[i]
		fmt.Fprintf(w, "limitplane_check_seconds_bucket{le=\"%g\"} %d\n", le, cum)
	}
	cum += h.hist[len(latencyBuckets)]
	fmt.Fprintf(w, "limitplane_check_seconds_bucket{le=\"+Inf\"} %d\nlimitplane_check_seconds_sum %g\nlimitplane_check_seconds_count %d\n", cum, h.histSum, cum)
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func quote(s string) string { return `"` + labelEscaper.Replace(s) + `"` }
