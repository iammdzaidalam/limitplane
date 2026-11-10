package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math"
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
	clientTTL  = 15 * time.Minute // how long a client counts as one of a tenant's, for scoped views
	maxClients = 50000
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

// agg is the totals, per-second series and block reasons, for everyone or for one org.
type agg struct {
	series   [seriesSize]point
	total    counts
	byReason map[string]int64
}

func (a *agg) add(d gateway.Decision) {
	sec := d.Time.Unix()
	p := &a.series[sec%seriesSize]
	if p.T != sec {
		*p = point{T: sec}
	}
	if d.Allowed {
		p.Allowed++
		a.total.Allowed++
	} else {
		p.Blocked++
		a.total.Blocked++
		a.byReason[d.Reason]++
	}
}

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
	all       agg
	orgs      map[string]*agg             // by the org stamped on the decision
	seen      map[string]map[string]int64 // client -> tenant -> last seen, unix seconds
	tenants   map[string]*counts
	decisions map[[2]string]int64 // {tenant label, reason}
	degraded  int64
	lastDeg   time.Time
	hist      [len(latencyBuckets) + 1]int64 // last is +Inf
	histSum   float64
	tenantSet map[string]string

	subMu sync.Mutex
	subs  map[chan []byte]func(event string, v any) bool

	quota sync.Map // tenant -> *quotaGauge, written on the request path
}

// quotaGauge is a tenant's latest used/limit ratio and when it was set (unix seconds).
type quotaGauge struct{ ratio, at atomic.Int64 }

func NewHub(observe func(gateway.Decision), known func() map[string]string) *Hub {
	h := &Hub{
		in: make(chan event, queueSize), observe: observe, known: known, done: make(chan struct{}),
		all: agg{byReason: map[string]int64{}}, orgs: map[string]*agg{}, seen: map[string]map[string]int64{},
		tenants: map[string]*counts{}, decisions: map[[2]string]int64{},
		subs: map[chan []byte]func(string, any) bool{},
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
	ticks := 0
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-h.in:
			h.process(e)
		case t := <-tick.C:
			var ks map[string]string
			if h.known != nil {
				ks = h.known()
			}
			h.mu.Lock()
			if ks != nil {
				h.tenantSet = ks
			}
			if ticks++; ticks%10 == 0 {
				h.prune(t.Add(-clientTTL).Unix())
			}
			h.mu.Unlock()
		}
	}
}

func (h *Hub) Done() <-chan struct{} { return h.done }

// Refresh rereads the known tenants now, instead of on the next tick.
func (h *Hub) Refresh() {
	if h.known == nil {
		return
	}
	ks := h.known()
	h.mu.Lock()
	h.tenantSet = ks
	h.mu.Unlock()
}

// Quota records a tenant's monthly usage for limitplane_quota_used_ratio. It takes no lock:
// after a tenant's first call it is a sync.Map hit and three atomic stores.
func (h *Hub) Quota(tenant string, used, limit int64) {
	if limit <= 0 {
		return
	}
	g, ok := h.quota.Load(tenant)
	if !ok {
		g, _ = h.quota.LoadOrStore(tenant, new(quotaGauge))
	}
	q := g.(*quotaGauge)
	q.ratio.Store(int64(math.Float64bits(float64(used) / float64(limit))))
	q.at.Store(time.Now().Unix())
}

func (h *Hub) process(e event) {
	d := e.d
	label := anonLabel
	h.mu.Lock()
	if _, ok := h.tenantSet[d.Tenant]; ok {
		label = d.Tenant
	}
	h.audit[h.auditN%auditSize] = d
	h.auditN++

	h.all.add(d)
	if d.Org != "" {
		a := h.orgs[d.Org]
		if a == nil {
			a = &agg{byReason: map[string]int64{}}
			h.orgs[d.Org] = a
		}
		a.add(d)
	}
	if ts := h.seen[d.Client]; ts != nil || len(h.seen) < maxClients {
		if ts == nil {
			ts = map[string]int64{}
			h.seen[d.Client] = ts
		}
		ts[d.Tenant] = d.Time.Unix()
	}
	c := h.tenants[label]
	if c == nil {
		c = &counts{}
		h.tenants[label] = c
	}
	if d.Allowed {
		c.Allowed++
	} else {
		c.Blocked++
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

// prune forgets client-tenant pairs not seen since before. Callers hold mu.
func (h *Hub) prune(before int64) {
	for c, ts := range h.seen {
		for t, at := range ts {
			if at < before {
				delete(ts, t)
			}
		}
		if len(ts) == 0 {
			delete(h.seen, c)
		}
	}
}

// ClientsOf is every client that sent a kept tenant traffic in the last clientTTL.
func (h *Hub) ClientsOf(keep func(tenant string) bool) map[string]bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]bool{}
	for c, ts := range h.seen {
		for t := range ts {
			if keep(t) {
				out[c] = true
				break
			}
		}
	}
	return out
}

// Publish sends an SSE event to every subscriber whose filter keeps it, skipping any whose buffer is full.
func (h *Hub) Publish(event string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	msg := []byte("event: " + event + "\ndata: " + string(b) + "\n\n")
	h.subMu.Lock()
	defer h.subMu.Unlock()
	for ch, keep := range h.subs {
		if keep != nil && !keep(event, v) {
			continue
		}
		select {
		case ch <- msg:
		default: // slow consumer: drop rather than stall the hub
		}
	}
}

// Subscribe returns a channel of SSE messages; keep (nil: all) chooses which. It runs on the
// publisher's goroutine with the subscriber lock held, so it must be quick and not call back in.
func (h *Hub) Subscribe(keep func(event string, v any) bool) chan []byte {
	ch := make(chan []byte, 64)
	h.subMu.Lock()
	h.subs[ch] = keep
	h.subMu.Unlock()
	return ch
}

func (h *Hub) Unsubscribe(ch chan []byte) {
	h.subMu.Lock()
	delete(h.subs, ch)
	h.subMu.Unlock()
}

// Audit returns up to limit decisions, newest first.
func (h *Hub) Audit(limit int) []gateway.Decision { return h.AuditOf(limit, nil) }

// AuditOf returns up to limit decisions that keep (nil: all) accepts, newest first.
func (h *Hub) AuditOf(limit int, keep func(gateway.Decision) bool) []gateway.Decision {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]gateway.Decision, 0, min(limit, h.auditN, auditSize))
	for i := 0; i < min(h.auditN, auditSize) && len(out) < limit; i++ {
		if d := h.audit[(h.auditN-1-i)%auditSize]; keep == nil || keep(d) {
			out = append(out, d)
		}
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
	Org      *orgView         `json:"org,omitempty"` // the org in view, with its budget
	Degraded bool             `json:"degraded"`
	Backend  string           `json:"backend"`
	Kube     bool             `json:"kube"`
	Leader   bool             `json:"leader"`
}

type tenantStats struct {
	Tenant       string `json:"tenant"`
	Tier         string `json:"tier"`
	Org          string `json:"org,omitempty"`
	Allowed      int64  `json:"allowed"`
	Blocked      int64  `json:"blocked"`
	MonthlyUsed  int64  `json:"monthlyUsed"`
	MonthlyLimit int64  `json:"monthlyLimit"`
}

// snapshot returns totals, the last 120s oldest first (gaps zero-filled), and per-label counts,
// for everyone (org "") or for one org.
func (h *Hub) snapshot(now time.Time, org string) (stats, map[string]counts) {
	h.mu.Lock()
	defer h.mu.Unlock()
	a := &h.all
	if org != "" {
		if a = h.orgs[org]; a == nil {
			a = &agg{}
		}
	}
	s := stats{
		Total: a.total.Allowed + a.total.Blocked, Allowed: a.total.Allowed, Blocked: a.total.Blocked,
		ByReason: maps.Clone(a.byReason), Series: make([]point, seriesSize),
		Degraded: !h.lastDeg.IsZero() && now.Sub(h.lastDeg) < 10*time.Second,
	}
	if s.ByReason == nil {
		s.ByReason = map[string]int64{}
	}
	end := now.Unix()
	for i := range seriesSize {
		t := end - seriesSize + 1 + int64(i)
		p := a.series[t%seriesSize]
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

// writeMetrics renders Prometheus text exposition format 0.0.4. bans < 0 means unknown.
func (h *Hub) writeMetrics(w io.Writer, bans int, now time.Time) {
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
	if bans >= 0 {
		fmt.Fprintf(w, "# HELP limitplane_bans_active Clients currently banned.\n# TYPE limitplane_bans_active gauge\nlimitplane_bans_active %d\n", bans)
	}
	// Last month's figure is stale once the month turns, until the tenant's next request.
	y, m, _ := now.UTC().Date()
	monthStart := time.Date(y, m, 1, 0, 0, 0, 0, time.UTC).Unix()
	ratios := map[string]float64{}
	h.quota.Range(func(k, v any) bool {
		q := v.(*quotaGauge)
		if _, known := h.tenantSet[k.(string)]; known && q.at.Load() >= monthStart {
			ratios[k.(string)] = math.Float64frombits(uint64(q.ratio.Load()))
		}
		return true
	})
	fmt.Fprint(w, "# HELP limitplane_quota_used_ratio Share of the monthly quota used, per tenant.\n# TYPE limitplane_quota_used_ratio gauge\n")
	for _, t := range slices.Sorted(maps.Keys(ratios)) {
		fmt.Fprintf(w, "limitplane_quota_used_ratio{tenant=%s} %g\n", quote(t), ratios[t])
	}
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
