package ai

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/autopilot"
	"github.com/iammdzaidalam/limitplane/internal/gateway"
	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

const (
	stormBlocks = 100              // a tenant's blocks in one minute that make a storm
	stormQuiet  = 10 * time.Minute // at most one storm incident per tenant per this
	degQuiet    = 15 * time.Second // no degraded decision for this long ends a window
)

type degWindow struct {
	since, last time.Time
	n           int64
}

// minute counts one tenant's decisions in one wall-clock minute.
type minute struct {
	at             int64 // unix minute
	total, blocked int
	reasons        map[string]int
	clients        map[string]int // blocks per client, up to 64 clients
}

// Observe feeds one decision in, on the hub goroutine: two counters under a lock.
func (s *Service) Observe(d gateway.Decision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.Degraded {
		if s.deg.since.IsZero() {
			s.deg.since = d.Time
		}
		s.deg.last = d.Time
		s.deg.n++
	}
	at := d.Time.Unix() / 60
	m := s.minutes[d.Tenant]
	if m == nil || m.at != at {
		if m != nil {
			s.closeMinute(d.Tenant, m)
		}
		m = &minute{at: at, reasons: map[string]int{}, clients: map[string]int{}}
		s.minutes[d.Tenant] = m
	}
	m.total++
	if !d.Allowed {
		m.blocked++
		m.reasons[d.Reason]++
		if _, ok := m.clients[d.Client]; ok || len(m.clients) < 64 {
			m.clients[d.Client]++
		}
	}
}

// tick ends minutes and degraded windows that traffic has stopped closing. Caller: Run.
func (s *Service) tick(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for t, m := range s.minutes {
		if m.at < now.Unix()/60 {
			s.closeMinute(t, m)
			delete(s.minutes, t)
		}
	}
	if w := s.deg; !w.since.IsZero() && now.Sub(w.last) > degQuiet {
		s.deg = degWindow{}
		s.Memory.Add(Doc{
			Time: w.since, Kind: "degraded",
			Text: fmt.Sprintf("Shared backend unreachable from %s to %s (%s): %s decisions were made by local fallbacks.", clock(w.since), clock(w.last), span(w.last.Sub(w.since)), num(w.n)),
			Note: "Limits were enforced per replica during the window and monthly counts may have drifted. Check Redis availability and its network path.", NoteBy: "rules",
		}, true)
	}
}

// closeMinute records a storm if the minute had one. Caller holds s.mu.
func (s *Service) closeMinute(tenant string, m *minute) {
	start := time.Unix(m.at*60, 0)
	if m.blocked < stormBlocks || start.Sub(s.stormAt[tenant]) < stormQuiet {
		return
	}
	s.stormAt[tenant] = start
	var rs []string
	for _, r := range sortedKeys(m.reasons) {
		rs = append(rs, fmt.Sprintf("%s %d", r, m.reasons[r]))
	}
	top := ""
	for _, c := range sortedKeys(m.clients) {
		if top == "" || m.clients[c] > m.clients[top] {
			top = c
		}
	}
	text := fmt.Sprintf("Block storm on %s: %d of %d requests blocked in the minute from %s (%s), from %d clients; %s caused %d.",
		tenant, m.blocked, m.total, start.UTC().Format("15:04 UTC"), strings.Join(rs, ", "), len(m.clients), top, m.clients[top])
	note := "Blocks were spread over many clients: the tenant as a whole is sending more than its tier allows. Consider a bigger tier."
	if m.clients[top]*2 > m.blocked {
		note = fmt.Sprintf("One client, %s, caused most of it: check its retry and backoff logic before changing limits.", top)
	}
	s.Memory.Add(Doc{Time: start, Kind: "storm", Tenant: tenant, Client: top, Text: text, Note: note, NoteBy: "rules"}, true)
}

var citeGap = regexp.MustCompile(`\s*\[[A-Z]\d+(?:\s*,\s*[A-Z]\d+)*\]`)

type job struct {
	id    int
	note  string
	facts []Fact
	kind  string
}

// Ban records a ban as an incident with a rule-based note, returned at once so the caller can
// put it on the "ban" event. in carries the gateway state (Audit, Policy, Clients, Rules); its
// subject fields are ignored. With a model, the note is rewritten in the background and goes
// out again as a "note" event.
func (s *Service) Ban(b limiter.Ban, in Input) Doc {
	d := gateway.Decision{Time: in.Now, Client: b.Client, Reason: gateway.ReasonBanned}
	if i := slices.IndexFunc(in.Audit, func(a gateway.Decision) bool { return a.Client == b.Client }); i >= 0 {
		last := in.Audit[i]
		d.Tenant, d.Tier, d.Method, d.Path, d.Cost = last.Tenant, last.Tier, last.Method, last.Path, last.Cost
	}
	d.RetryAfter = b.Until.Sub(in.Now)
	in.Decision, in.Client, in.Tenant = &d, "", ""
	in.Bans = append(slices.Clone(in.Bans), b)
	e := Explain(in)
	who := b.Client
	if d.Tenant != "" {
		who += " (tenant " + d.Tenant + ")"
	}
	return s.incident(Doc{
		Time: in.Now, Kind: "ban", Tenant: d.Tenant, Client: b.Client,
		Text: fmt.Sprintf("Banned %s for %s, reason %q, until %s.", who, span(b.Until.Sub(in.Now)), b.Reason, clock(b.Until)),
	}, e)
}

// Alert records a quota alert as an incident, like Ban.
func (s *Service) Alert(a autopilot.Alert, in Input) Doc {
	in.Decision, in.Client, in.Tenant = nil, "", a.Tenant
	in.Used, in.UsedOK = a.Used, true
	e := Explain(in)
	return s.incident(Doc{
		Time: in.Now, Kind: "quota", Tenant: a.Tenant,
		Text: fmt.Sprintf("Quota alert: %s passed 80%% of its monthly quota in %s, %s of %s units (%d%%).", a.Tenant, a.Month, num(a.Used), num(a.Limit), pct(a.Used, a.Limit)),
	}, e)
}

// Remember stores any other notable event as an incident, as is.
func (s *Service) Remember(d Doc) Doc { return s.Memory.Add(d, true) }

func (s *Service) incident(d Doc, e Explanation) Doc {
	d.Note, d.NoteBy = noteOf(e), "rules"
	if s.llm == nil {
		return s.Memory.Add(d, true)
	}
	d = s.Memory.Add(d, false)
	select {
	case s.jobs <- job{id: d.ID, note: d.Note, facts: append([]Fact{{ID: "F0", Kind: "incident", Text: d.Text}}, e.Facts...), kind: d.Kind}:
	default:
		s.m.fallback(whyBusy)
		s.Memory.SetNote(d.ID, d.Note, "rules")
	}
	return d
}

func noteOf(e Explanation) string {
	var parts []string
	for _, f := range e.Findings[:min(2, len(e.Findings))] {
		parts = append(parts, f.Text)
	}
	if len(e.Actions) > 0 {
		parts = append(parts, e.Actions[0].Text)
	}
	return strings.Join(parts, " ")
}

// enrich rewrites incident notes with the model, off the request path.
func (s *Service) enrich(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-s.jobs:
			n := s.narrate(ctx, "You write short incident notes for the operator of a rate limiter.",
				"Rule-based note: "+j.note+"\n\nIn at most two sentences, say what happened and what the operator should do.", j.facts)
			text, by := j.note, "rules"
			if n.Text != "" { // its citations point at this prompt's facts, which aren't kept
				text, by = citeGap.ReplaceAllString(n.Text, ""), n.Model
			}
			d, ok := s.Memory.SetNote(j.id, text, by)
			if ok && by != "rules" && s.c.Publish != nil {
				s.c.Publish("note", d)
			}
		}
	}
}

// policyChanged turns a reload into incidents: one fleet-wide summary when tiers, routes or keys
// changed, plus one per tenant that was added, removed or moved (in the policy or the org
// directory), so each org sees its own. API keys never appear, only tenant ids.
func (s *Service) policyChanged(was, now snapshot, at time.Time) {
	if reflect.DeepEqual(was, now) {
		return
	}
	old, cur := was.policy, now.policy
	var ch []string
	for _, name := range sortedKeys(merge(old.Tiers, cur.Tiers)) {
		a, inOld := old.Tiers[name]
		b, inCur := cur.Tiers[name]
		switch {
		case !inOld:
			ch = append(ch, fmt.Sprintf("tier %s added (%s)", name, tierText(b)))
		case !inCur:
			ch = append(ch, "tier "+name+" removed")
		case !reflect.DeepEqual(a, b):
			ch = append(ch, fmt.Sprintf("tier %s changed from %s to %s", name, tierText(a), tierText(b)))
		}
	}
	oldR, curR := routeMap(old.Routes), routeMap(cur.Routes)
	for _, p := range sortedKeys(merge(oldR, curR)) {
		a, inOld := oldR[p]
		b, inCur := curR[p]
		switch {
		case !inOld:
			ch = append(ch, fmt.Sprintf("route %s added at %d units", p, b))
		case !inCur:
			ch = append(ch, "route "+p+" removed")
		case a != b:
			ch = append(ch, fmt.Sprintf("route %s cost %d to %d", p, a, b))
		}
	}
	if old.Anonymous != cur.Anonymous {
		ch = append(ch, fmt.Sprintf("anonymous traffic moved from tier %s to %s", old.Anonymous, cur.Anonymous))
	}
	oldT, curT := was.tenants, now.tenants
	var tenants []Doc
	for _, t := range sortedKeys(merge(oldT, curT)) {
		a, inOld := oldT[t]
		b, inCur := curT[t]
		text := ""
		switch {
		case !inOld:
			text = fmt.Sprintf("Tenant %s added on tier %s.", t, b)
		case !inCur:
			text = fmt.Sprintf("Tenant %s removed (was on tier %s).", t, a)
		case a != b:
			text = fmt.Sprintf("Tenant %s moved from tier %s to %s.", t, a, b)
		}
		if text != "" {
			tenants = append(tenants, Doc{Time: at, Kind: "policy", Tenant: t, Text: text})
		}
	}
	switch {
	case len(ch) > 0 && len(tenants) > 0:
		ch = append(ch, fmt.Sprintf("%d tenants added, removed or moved", len(tenants)))
	case len(ch) == 0 && len(tenants) == 0:
		ch = append(ch, "API keys changed") // only keys moved between existing tenants
	}
	if len(ch) > 0 {
		s.Memory.Add(Doc{Time: at, Kind: "policy", Text: "Policy reloaded: " + strings.Join(ch, "; ") + "."}, true)
	}
	for _, d := range tenants {
		s.Memory.Add(d, true)
	}
}

func merge[V any](a, b map[string]V) map[string]V {
	m := maps.Clone(a)
	if m == nil {
		m = map[string]V{}
	}
	maps.Copy(m, b)
	return m
}

func routeMap(rs []policy.Route) map[string]int64 {
	m := make(map[string]int64, len(rs))
	for _, r := range rs {
		m[r.Prefix] = r.Cost
	}
	return m
}

// snapshot is what a reload is diffed on: the policy, and every tenant's tier.
type snapshot struct {
	policy  policy.Config
	tenants map[string]string
}

func (s *Service) snapshot() snapshot {
	p := s.c.Policy()
	if s.c.Tenants != nil {
		return snapshot{p, s.c.Tenants()}
	}
	return snapshot{p, TenantTiers(p)}
}

// TenantTiers maps each tenant named in c.Keys to its tier. API keys are dropped.
func TenantTiers(c policy.Config) map[string]string {
	m := map[string]string{}
	for _, k := range sortedKeys(c.Keys) {
		t := c.Keys[k]
		if _, ok := m[t.ID]; !ok {
			m[t.ID] = t.Tier
		}
	}
	return m
}

func tierText(t policy.Tier) string {
	s := fmt.Sprintf("%s, burst %d", rate(t.Rate), burstOf(t.Rate))
	if t.Monthly > 0 {
		s += ", " + num(t.Monthly) + " a month"
	}
	return s
}
