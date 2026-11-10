package ai

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/autopilot"
	"github.com/iammdzaidalam/limitplane/internal/gateway"
	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

// Input is everything the explainer may draw on. The caller scopes Audit to what the asker may
// see; the explainer reads nothing else.
type Input struct {
	Now time.Time
	// The subject: one decision, a client, or a tenant.
	Decision *gateway.Decision
	Client   string
	Tenant   string

	Audit    []gateway.Decision // newest first
	Policy   policy.Config
	Tenants  map[string]string // tenant -> tier; nil: from Policy.Keys
	Used     int64             // the tenant's monthly units, when UsedOK
	UsedOK   bool
	Bans     []limiter.Ban
	Clients  []autopilot.Client // the subject client's fingerprint, if known
	Rules    autopilot.Rules
	Degraded bool // the shared backend is down right now
	Budget   *Budget
}

// Budget is an organisation's spend cap, for when tenants are grouped into orgs.
type Budget struct {
	Org         string
	Used, Limit int64
}

type Explanation struct {
	Subject   string    `json:"subject"`
	Reason    string    `json:"reason"` // ok, burst, monthly, banned, error, or "" for a quiet subject
	Summary   string    `json:"summary"`
	Findings  []Point   `json:"findings"`
	Actions   []Point   `json:"actions"`
	Facts     []Fact    `json:"facts"`
	Narrative Narrative `json:"narrative"`
}

// Explain answers "why was this blocked?" from rules, then lets the model rephrase.
func (s *Service) Explain(ctx context.Context, in Input) Explanation {
	e := Explain(in)
	if len(e.Facts) > 0 {
		e.Narrative = s.narrate(ctx, explainRole, "Rule-based reading: "+e.Summary+"\n\nIn at most three sentences, tell the operator why this happened and what to do next.", e.Facts)
	}
	return e
}

const explainRole = "You explain a rate limiter's decisions to the operator who runs it."

// Explain is the rule-based answer alone. It is deterministic for a given Input.
func Explain(in Input) Explanation {
	x := &explainer{in: in, f: facts{prefix: "F"}}
	return x.run()
}

type explainer struct {
	in        Input
	f         facts
	e         Explanation
	tenant    string
	tier      string
	client    string
	recent    []gateway.Decision // the client's decisions before the subject, oldest first
	timing    *timing
	label     string
	labelFact string
	banFact   string
	budgetID  string
	ban       limiter.Ban
	degraded  bool
}

func (x *explainer) find(text string, ids ...string) {
	x.e.Findings = append(x.e.Findings, Point{text, nonEmpty(ids)})
}

func (x *explainer) act(text string, ids ...string) {
	x.e.Actions = append(x.e.Actions, Point{text, nonEmpty(ids)})
}

func nonEmpty(ids []string) []string {
	return slices.DeleteFunc(slices.Clone(ids), func(s string) bool { return s == "" })
}

func (x *explainer) run() Explanation {
	in := x.in
	var d *gateway.Decision
	switch {
	case in.Decision != nil:
		d = in.Decision
		x.e.Subject = fmt.Sprintf("%s %s from %s", d.Method, d.Path, d.Client)
	case in.Client != "":
		x.client = in.Client
		x.e.Subject = "client " + in.Client
		if i := slices.IndexFunc(in.Audit, func(a gateway.Decision) bool { return a.Client == in.Client && !a.Allowed }); i >= 0 {
			d = &in.Audit[i] // the latest block says most about a client
		} else if i := slices.IndexFunc(in.Audit, func(a gateway.Decision) bool { return a.Client == in.Client }); i >= 0 {
			d = &in.Audit[i]
		}
	case in.Tenant != "":
		return x.tenantRun()
	}
	if d == nil {
		x.e.Summary = "No recent decisions for this client in the audit window, so there is nothing to explain yet."
		x.e.Facts = x.f.list
		return x.e
	}
	x.client, x.tenant, x.tier, x.e.Reason = d.Client, d.Tenant, d.Tier, d.Reason
	x.degraded = d.Degraded || in.Degraded

	df := x.decisionFact(*d)
	x.collectClient(d.Time)
	tierFact, routeFact := x.policyFacts(d.Path, d.Cost)
	usageFact := x.usageFact()
	x.backendFact()

	switch d.Reason {
	case gateway.ReasonBanned:
		x.banned(df)
	case gateway.ReasonBurst:
		x.burst(*d, df, tierFact, routeFact)
	case gateway.ReasonMonthly:
		x.monthly(df, usageFact, tierFact)
	case gateway.ReasonOrg:
		x.orgSpent(df)
	case gateway.ReasonError:
		x.find("The shared backend failed and the gateway runs fail-closed, so it refused rather than guess.", df)
		x.act("Check Redis reachability from this replica; run without --fail-closed to limit locally during outages instead.", df)
	default:
		x.find(fmt.Sprintf("Allowed: within limits, %d of %d left.", d.Remaining, d.Limit), df)
		if x.timing != nil && x.timing.blocks > 0 {
			x.burstPattern(df)
		}
	}
	if x.degraded && d.Reason != gateway.ReasonError {
		x.find("Decided by the local fallback while the shared backend is down; each replica enforces only its share of the budget.", x.backendFactID())
		x.act("Check Redis; limits are approximate until it is back.", x.backendFactID())
	}
	x.budget()
	x.e.Summary = x.e.Findings[0].Text
	x.e.Facts = x.f.list
	return x.e
}

func (x *explainer) decisionFact(d gateway.Decision) string {
	who := fmt.Sprintf("%s %s from client %s (tenant %s, tier %s)", d.Method, d.Path, d.Client, d.Tenant, d.Tier)
	if d.Allowed {
		return x.f.add("decision", "%s was allowed at %s; cost %d, %d of %d left.", who, clock(d.Time), d.Cost, d.Remaining, d.Limit)
	}
	s := fmt.Sprintf("%s was blocked (%s) at %s; cost %d", who, d.Reason, clock(d.Time), d.Cost)
	if d.Reason == gateway.ReasonBurst {
		s += fmt.Sprintf(", burst %d, %d left", d.Limit, d.Remaining)
	}
	if d.RetryAfter > 0 {
		s += ", retry after " + span(d.RetryAfter)
	}
	if d.Lane != "" {
		s += fmt.Sprintf("; the %s lane set its burst", d.Lane)
	}
	return x.f.add("decision", "%s.", s)
}

func (x *explainer) policyFacts(path string, cost int64) (tier, route string) {
	p := x.in.Policy
	t, ok := p.Tiers[x.tier]
	if !ok {
		return "", ""
	}
	s := fmt.Sprintf("Tier %s allows %s with a burst of %d", x.tier, rate(t.Rate), burstOf(t.Rate))
	if t.Monthly > 0 {
		s += fmt.Sprintf(" and %s units a month", num(t.Monthly))
	} else {
		s += " and has no monthly cap"
	}
	if len(t.Lanes) > 0 {
		var ls []string
		for _, l := range sortedKeys(t.Lanes) {
			ls = append(ls, fmt.Sprintf("%s x%g", l, t.Lanes[l]))
		}
		s += "; lanes scale its burst: " + strings.Join(ls, ", ")
	}
	tier = x.f.add("policy", "%s.", s)
	if path != "" {
		by := "no route (the default)"
		if r, ok := routeFor(p.Routes, path); ok {
			by = "route " + r
		}
		route = x.f.add("route", "%s is priced by %s at %s, so one burst fits %d such calls.", path, by, units(cost), burstOf(t.Rate)/max(cost, 1))
	}
	return tier, route
}

func (x *explainer) usageFact() string {
	t, ok := x.in.Policy.Tiers[x.tier]
	if !ok || t.Monthly <= 0 || !x.in.UsedOK || x.tenant == policy.AnonTenant {
		return ""
	}
	now := x.in.Now.UTC()
	reset := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	return x.f.add("usage", "%s has used %s of %s monthly units (%d%%); the month resets %s, in %s.",
		x.tenant, num(x.in.Used), num(t.Monthly), pct(x.in.Used, t.Monthly), reset.Format("2006-01-02"), days(reset.Sub(now)))
}

func (x *explainer) backendFact() {
	if x.degraded {
		x.f.add("backend", "The shared backend (Redis) is unreachable; decisions are made by each replica's local fallback.")
	}
}

func (x *explainer) backendFactID() string {
	for _, f := range x.f.list {
		if f.Kind == "backend" {
			return f.ID
		}
	}
	return ""
}

// collectClient gathers the client's ban, fingerprint and timing up to at.
func (x *explainer) collectClient(at time.Time) {
	in := x.in
	a, aerr := netip.ParseAddr(x.client)
	for _, b := range in.Bans {
		if b.Client == x.client || aerr == nil && covers(b.Client, a) {
			x.ban = b
			x.banFact = x.f.add("ban", "%s is banned until %s (%s left), reason %q.", b.Client, clock(b.Until), span(b.Until.Sub(in.Now)), b.Reason)
			break
		}
	}
	for _, c := range in.Clients {
		if c.Client == x.client {
			x.label = c.Label
			x.labelFact = x.f.add("client", "Autopilot labels %s as %s: %.1f requests/s, %d%% of recent requests blocked.", c.Client, c.Label, c.RPS, int(math.Round(c.BlockRatio*100)))
		}
	}
	for _, d := range in.Audit { // newest first
		if d.Client == x.client && !d.Time.After(at) && at.Sub(d.Time) <= time.Minute {
			x.recent = append(x.recent, d)
		}
	}
	slices.Reverse(x.recent)
	x.timing = measure(x.recent)
	if t := x.timing; t != nil {
		var bs []string
		for _, b := range []struct {
			n    int
			what string
		}{{t.burst, "by burst"}, {t.monthly, "by monthly quota"}, {t.banned, "while banned"}} {
			if b.n > 0 {
				bs = append(bs, fmt.Sprintf("%d blocked %s", b.n, b.what))
			}
		}
		if len(bs) == 0 {
			bs = []string{"none blocked"}
		}
		t.facts = append(t.facts, x.f.add("timing", "Over the %s up to then, %s sent %d requests: %s.", span(t.span), x.client, t.n, strings.Join(bs, ", ")))
		if t.gaps >= 4 {
			t.facts = append(t.facts, x.f.add("timing", "Gaps between its requests average %s with %d%% variation%s.", span(t.mean), int(math.Round(t.cv*100)), map[bool]string{true: " (near constant)", false: ""}[t.cv < 0.3]))
		}
		if t.followups > 0 {
			t.facts = append(t.facts, x.f.add("timing", "It retried before half the Retry-After had passed after %d of the %d 429s it got.", t.early, t.followups))
		}
	}
}

// routeFor is the longest route prefix matching path on whole segments, as the gateway prices it.
func routeFor(routes []policy.Route, path string) (string, bool) {
	best := ""
	for _, r := range routes {
		p := r.Prefix
		if len(p) > len(best) && strings.HasPrefix(path, p) && (len(path) == len(p) || p[len(p)-1] == '/' || path[len(p)] == '/') {
			best = p
		}
	}
	return best, best != ""
}

func covers(ban string, a netip.Addr) bool {
	p, err := netip.ParsePrefix(ban)
	return err == nil && p.Contains(a.Unmap())
}

type timing struct {
	n, burst, monthly, banned, blocks int
	span, mean                        time.Duration
	cv                                float64
	gaps                              int
	followups, early                  int
	facts                             []string
}

// measure reads a client's decisions (oldest first): counts, gap regularity, and whether it
// waits after a 429. Nil under three decisions.
func measure(ds []gateway.Decision) *timing {
	if len(ds) < 3 {
		return nil
	}
	t := &timing{n: len(ds), span: ds[len(ds)-1].Time.Sub(ds[0].Time)}
	var sum, sq float64
	for i, d := range ds {
		switch d.Reason {
		case gateway.ReasonBurst:
			t.burst++
		case gateway.ReasonMonthly:
			t.monthly++
		case gateway.ReasonBanned:
			t.banned++
		}
		if i == 0 {
			continue
		}
		g := d.Time.Sub(ds[i-1].Time).Seconds()
		sum += g
		sq += g * g
		t.gaps++
		if p := ds[i-1]; p.Reason == gateway.ReasonBurst || p.Reason == gateway.ReasonMonthly {
			t.followups++
			if d.Time.Sub(p.Time) < p.RetryAfter/2 {
				t.early++
			}
		}
	}
	t.blocks = t.burst + t.monthly + t.banned
	if t.gaps > 0 {
		mean := sum / float64(t.gaps)
		t.mean = time.Duration(mean * float64(time.Second))
		if mean > 0 {
			t.cv = math.Sqrt(max(0, sq/float64(t.gaps)-mean*mean)) / mean
		}
	}
	return t
}

func (x *explainer) banned(df string) {
	if x.banFact == "" {
		x.find("Blocked because the client was on the ban list when it called; the ban has since lifted.", df)
		x.act("Nothing to do unless it is banned again; the Clients tab shows active bans.", df)
		return
	}
	ids := []string{df, x.banFact}
	r := x.in.Rules
	if x.ban.Reason == "storm" {
		what := "repeated burst blocks"
		if r.StormBlocks > 0 {
			ids = append(ids, x.f.add("policy", "The storm rule bans a client for %s after %d burst blocks within %s.", span(r.BanFor), r.StormBlocks, span(r.StormWindow)))
			what = fmt.Sprintf("at least %d burst blocks inside %s", r.StormBlocks, span(r.StormWindow))
		}
		x.find(fmt.Sprintf("Autopilot banned %s for a storm: %s. The ban lifts in %s.", x.ban.Client, what, span(x.ban.Until.Sub(x.in.Now))), ids...)
		if x.timing != nil && x.retryLoop() {
			x.find("Before the ban it kept retrying straight after 429s, which is a retry loop rather than an attack.", x.timing.facts...)
		}
		x.act("If the client is legitimate, unban it from the Clients tab and fix its backoff first, or it will storm again.", ids...)
		return
	}
	x.find(fmt.Sprintf("%s is banned (%s) until %s.", x.ban.Client, x.ban.Reason, clock(x.ban.Until)), ids...)
	x.act("Unban it from the Clients tab if the ban was a mistake; otherwise it lifts on its own.", x.banFact)
}

func (x *explainer) retryLoop() bool {
	t := x.timing
	return x.label == "retry_bug" || t.followups >= 3 && t.early*2 > t.followups
}

func (x *explainer) burst(d gateway.Decision, df, tierFact, routeFact string) {
	x.find(fmt.Sprintf("Blocked by the burst limit: the %s tier's bucket of %d was empty and refills in %s.", d.Tier, d.Limit, span(d.RetryAfter)), df, tierFact)
	x.burstPattern(df)
	if t, ok := x.in.Policy.Tiers[d.Tier]; ok && d.Cost*4 > burstOf(t.Rate) && routeFact != "" {
		x.find(fmt.Sprintf("This route is expensive for the tier: one burst fits only %d calls.", burstOf(t.Rate)/max(d.Cost, 1)), routeFact, tierFact)
		x.act("Lower the route's cost or raise the tier's burst if a handful of calls is normal use.", routeFact, tierFact)
	}
	if len(x.e.Actions) == 0 {
		x.act(fmt.Sprintf("Have the client wait for Retry-After (%s) and spread calls out.", span(d.RetryAfter)), df)
	}
}

// burstPattern names what the client's timing looks like, when there is enough of it.
func (x *explainer) burstPattern(df string) {
	t := x.timing
	if t == nil {
		return
	}
	ids := append([]string{df, x.labelFact}, t.facts...)
	switch {
	case x.retryLoop():
		x.find(fmt.Sprintf("Retry loop: %d burst blocks in %s%s, and it retried early after %d of %d 429s.", t.burst, span(t.span), map[bool]string{true: " with near-constant spacing", false: ""}[t.cv < 0.3 && t.gaps >= 4], t.early, t.followups), ids...)
		x.act("Check the client's backoff: honour Retry-After and back off exponentially with jitter.", ids...)
		x.laneHint("retry_bug", "0.25", ids)
	case x.label == "crawler":
		x.find("Crawler: steady requests across many distinct paths.", ids...)
		x.act("Give the crawler its own API key and tier, or a crawler lane with a smaller burst.", ids...)
	case x.label == "bot" || t.cv < 0.3 && t.gaps >= 4:
		x.find(fmt.Sprintf("Scripted traffic: one request every %s with little variation, faster than the tier refills.", span(t.mean)), ids...)
		x.act("Slow the job below the tier's rate, or move it to a tier with a higher rate.", ids...)
	case x.label == "human":
		x.find("Bursty, human-like timing: short spikes with pauses between.", ids...)
		x.laneHint("human", "2", ids)
	}
}

func (x *explainer) laneHint(lane, factor string, ids []string) {
	if t, ok := x.in.Policy.Tiers[x.tier]; ok && t.Lanes[lane] == 0 {
		x.act(fmt.Sprintf(`Consider lanes on the %s tier, e.g. "lanes": {"%s": %s}, to reshape this client's burst without changing the rate or quota.`, x.tier, lane, factor), ids...)
	}
}

func (x *explainer) monthly(df, usageFact, tierFact string) {
	now := x.in.Now.UTC()
	reset := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	ids := []string{df, usageFact, tierFact}
	x.find(fmt.Sprintf("%s has used its whole monthly quota on the %s tier; it resets in %s (the 1st, UTC).", x.tenant, x.tier, days(reset.Sub(now))), ids...)
	x.act(fmt.Sprintf("Move %s to a bigger tier, or raise the %s tier's monthly units if this use is expected.", x.tenant, x.tier), ids...)
}

// orgSpent explains a block by the org's shared budget, which caps all of its tenants together.
func (x *explainer) orgSpent(ids ...string) {
	now := x.in.Now.UTC()
	reset := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	who := "The tenant's organisation"
	if b := x.in.Budget; b != nil && b.Limit > 0 {
		who = "Organisation " + b.Org
		ids = append(ids, x.budgetFact())
	}
	x.find(fmt.Sprintf("%s has used its whole shared monthly budget, so every tenant in it is blocked until it resets in %s (the 1st, UTC).", who, days(reset.Sub(now))), ids...)
	x.act("Have an org owner raise the budget in the Org tab, or find which of its tenants spent it.", ids...)
}

func (x *explainer) budgetFact() string {
	if b := x.in.Budget; x.budgetID == "" && b != nil && b.Limit > 0 {
		x.budgetID = x.f.add("budget", "Organisation %s has spent %s of its %s budget (%d%%).", b.Org, num(b.Used), num(b.Limit), pct(b.Used, b.Limit))
	}
	return x.budgetID
}

func (x *explainer) budget() {
	id, b := x.budgetFact(), x.in.Budget
	if id != "" && x.e.Reason != gateway.ReasonOrg && b.Used*5 >= b.Limit*4 {
		x.find(fmt.Sprintf("The %s organisation is at %d%% of its budget.", b.Org, pct(b.Used, b.Limit)), id)
	}
}

// tenantRun explains a tenant: its blocks in the audit window, usage and pace.
func (x *explainer) tenantRun() Explanation {
	in := x.in
	x.tenant = in.Tenant
	x.e.Subject = "tenant " + in.Tenant
	tiers := in.Tenants
	if tiers == nil {
		tiers = TenantTiers(in.Policy)
	}
	x.tier = cmp.Or(tiers[in.Tenant], in.Policy.Anonymous)
	var n, blocked int
	reasons := map[string]int{}
	byClient := map[string]int{} // blocks per client
	seen := map[string]bool{}
	for _, d := range in.Audit {
		if d.Tenant != in.Tenant {
			continue
		}
		n++
		seen[d.Client] = true
		x.degraded = x.degraded || d.Degraded && in.Now.Sub(d.Time) < 10*time.Second
		if !d.Allowed {
			blocked++
			reasons[d.Reason]++
			byClient[d.Client]++
		}
	}
	x.degraded = x.degraded || in.Degraded
	tierFact, _ := x.policyFacts("", 0)
	usage := x.usageFact()
	x.backendFact()
	if t, ok := in.Policy.Tiers[x.tier]; ok && t.Monthly > 0 && in.UsedOK {
		x.pace(t.Monthly, usage, tierFact)
	}
	var act string
	if n > 0 {
		var rs []string
		for _, r := range sortedKeys(reasons) {
			rs = append(rs, fmt.Sprintf("%s %d", r, reasons[r]))
		}
		s := fmt.Sprintf("In the audit window %s made %d requests, %d blocked", in.Tenant, n, blocked)
		if blocked > 0 {
			s += " (" + strings.Join(rs, ", ") + ")"
		}
		act = x.f.add("tenant", "%s, from %d clients.", s, len(seen))
		if reasons[gateway.ReasonOrg] > 0 { // it blocks every tenant of the org: say that first
			x.orgSpent(act)
		}
		top := slices.SortedFunc(func(yield func(string) bool) {
			for c := range byClient {
				if !yield(c) {
					return
				}
			}
		}, func(a, b string) int { return cmp.Or(cmp.Compare(byClient[b], byClient[a]), strings.Compare(a, b)) })
		if len(top) > 0 {
			id := x.f.add("tenant", "Client %s caused %d of those blocks.", top[0], byClient[top[0]])
			if byClient[top[0]]*2 > blocked {
				x.find(fmt.Sprintf("Most of %s's blocks come from one client, %s; explain that client for its pattern.", in.Tenant, top[0]), act, id)
			}
		}
	}
	switch {
	case reasons[gateway.ReasonOrg] > 0:
		x.e.Reason = gateway.ReasonOrg
	case reasons[gateway.ReasonMonthly] > 0:
		x.e.Reason = gateway.ReasonMonthly
	case blocked > 0:
		x.e.Reason = gateway.ReasonBurst
	case n > 0:
		x.e.Reason = gateway.ReasonOK
	}
	if blocked > 0 && len(x.e.Findings) == 0 {
		x.find(fmt.Sprintf("%s had %d blocked requests in the audit window, spread over several clients.", in.Tenant, blocked), act)
	}
	if n == 0 && len(x.e.Findings) == 0 {
		x.find(fmt.Sprintf("%s has no decisions in the audit window.", in.Tenant), tierFact)
	} else if len(x.e.Findings) == 0 {
		x.find(fmt.Sprintf("%s is within its limits: nothing blocked in the audit window.", in.Tenant), act)
	}
	if x.degraded {
		x.find("The shared backend is down, so limits are enforced per replica for now.", x.backendFactID())
	}
	x.budget()
	x.e.Summary = x.e.Findings[0].Text
	x.e.Facts = x.f.list
	return x.e
}

// pace projects monthly use at this month's average rate.
func (x *explainer) pace(limit int64, usage, tierFact string) {
	now := x.in.Now.UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	reset := start.AddDate(0, 1, 0)
	used := x.in.Used
	switch {
	case used >= limit:
		x.find(fmt.Sprintf("%s has used its whole monthly quota; requests are blocked until %s.", x.tenant, reset.Format("2006-01-02")), usage, tierFact)
		x.act(fmt.Sprintf("Move %s to a bigger tier, or raise the tier's monthly units.", x.tenant), usage, tierFact)
	case used > 0 && now.Sub(start) > time.Hour:
		perSec := float64(used) / now.Sub(start).Seconds()
		out := start.Add(time.Duration(float64(limit) / perSec * float64(time.Second)))
		if out.Before(reset) {
			id := x.f.add("usage", "At this month's average pace %s runs out on %s, %s before the reset.", x.tenant, out.Format("2006-01-02"), days(reset.Sub(out)))
			x.find(fmt.Sprintf("%s is on pace to run out of its monthly quota on %s.", x.tenant, out.Format("2006-01-02")), usage, id)
			x.act(fmt.Sprintf("Warn %s or move it to a bigger tier before %s.", x.tenant, out.Format("2006-01-02")), id)
		}
	}
}

func burstOf(r limiter.Rate) int64 { return cmp.Or(r.Burst, r.Limit) }

func rate(r limiter.Rate) string {
	if r.Period == time.Second {
		return fmt.Sprintf("%d per second", r.Limit)
	}
	return fmt.Sprintf("%d per %s", r.Limit, r.Period)
}

func units(n int64) string {
	if n == 1 {
		return "1 unit"
	}
	return num(n) + " units"
}

func pct(a, b int64) int {
	if b <= 0 {
		return 0
	}
	return int(math.Round(100 * float64(a) / float64(b)))
}

func num(n int64) string {
	s := fmt.Sprint(n)
	if n < 10000 && n > -10000 {
		return s
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 && s[i-1] != '-' {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}

func clock(t time.Time) string { return t.UTC().Format("15:04:05 UTC") }

func span(d time.Duration) string {
	switch {
	case d <= 0:
		return "0s"
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return d.Round(time.Second).String()
}

func days(d time.Duration) string {
	n := int(math.Ceil(d.Hours() / 24))
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}
