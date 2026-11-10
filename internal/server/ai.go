package server

import (
	"cmp"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/ai"
	"github.com/iammdzaidalam/limitplane/internal/autopilot"
	"github.com/iammdzaidalam/limitplane/internal/gateway"
	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

// The AI endpoints spend from the gateway's own limiter, per caller, so a dashboard left polling
// (or a script) can't run up CPU here or crowd out another org; model calls have a second,
// fleet-wide budget inside ai.Service.
var aiRate = limiter.Rate{Limit: 120, Period: time.Minute, Burst: 30}

// aiPlane feeds the AI layer from the hub and autopilot and serves its endpoints.
type aiPlane struct {
	s   *Server
	svc *ai.Service
}

// newAI wires c to the server's limiter, SSE hub and policy. Call it once the hub exists.
func newAI(s *Server, c ai.Config) *aiPlane {
	p := &aiPlane{s: s}
	c.Limits, c.Publish, c.Policy, c.Tenants = s.cfg.Limits, s.Hub.Publish, s.cfg.Policy.Config, p.tenants
	p.svc = ai.New(c)
	return p
}

// tenants maps every tenant, from the policy and the org directory, to its tier.
func (p *aiPlane) tenants() map[string]string {
	m := map[string]string{}
	for _, t := range p.s.cfg.Policy.Tenants() {
		m[t.ID] = t.Tier
	}
	return m
}

func (p *aiPlane) run(ctx context.Context)    { p.svc.Run(ctx) }
func (p *aiPlane) observe(d gateway.Decision) { p.svc.Observe(d) }
func (p *aiPlane) writeMetrics(w io.Writer)   { p.svc.WriteMetrics(w) }

// ban records a ban as an incident with its rule-based note, for an "incident" SSE event next
// to "ban". It is a separate event because a ban goes to every org whose clients it covers, while
// the note names one tenant. Autopilot calls this on the hub goroutine: in-process state only.
func (p *aiPlane) ban(b autopilot.Ban) ai.Doc { return p.svc.Ban(b, p.hookInput(b.Client)) }

// alert is ban's counterpart for quota alerts. It runs on the request path, once per tenant a month.
func (p *aiPlane) alert(a autopilot.Alert) ai.Doc { return p.svc.Alert(a, p.hookInput("")) }

func (p *aiPlane) hookInput(client string) ai.Input {
	in := ai.Input{Now: time.Now(), Audit: p.s.Hub.Audit(auditSize), Policy: p.s.cfg.Policy.Config(), Tenants: p.tenants(), Rules: p.s.Pilot.Rules()}
	in.Clients = p.client(client)
	return in
}

func (p *aiPlane) client(id string) []autopilot.Client {
	if c, ok := p.s.Pilot.Client(id); ok {
		return []autopilot.Client{c}
	}
	return nil
}

// routes registers the AI endpoints. Each is scoped like the other reads: an org member sees
// only its own tenants, their decisions, clients and incidents.
func (p *aiPlane) routes(handle func(pattern string, h http.HandlerFunc)) {
	limited := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if c, _ := caller(r); p.s.throttle(w, r, "ai:api:"+c.ID, aiRate) {
				h(w, r)
			}
		}
	}
	handle("GET /api/ai/status", func(w http.ResponseWriter, r *http.Request) {
		st := p.svc.Status()
		if _, all := scope(r); !all {
			st.Memory = 0 // the fleet's incident count is not an org's business
		}
		writeJSON(w, 200, st)
	})
	handle("POST /api/ai/explain", limited(p.handleExplain))
	handle("POST /api/ai/chat", limited(p.handleChat))
	handle("GET /api/ai/incidents", limited(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		writeJSON(w, 200, p.svc.Memory.Search(ai.Query{Text: q.Get("q"), Visible: p.s.visible(r), Now: time.Now(), Zone: zone(q.Get("tz")), K: 50}))
	}))
}

// input is the gateway state an explanation may draw on, scoped to what the caller of r sees:
// its tenants' decisions, and the bans that cover their clients.
func (p *aiPlane) input(r *http.Request) ai.Input {
	in := p.hookInput("")
	vis := p.s.visible(r)
	_, all := scope(r)
	if !all {
		in.Audit = p.s.Hub.AuditOf(auditSize, func(d gateway.Decision) bool { return vis(d.Tenant) })
	}
	if bans, err := p.s.Pilot.Bans(r.Context()); err == nil {
		if !all {
			bans = affecting(bans, p.s.Hub.ClientsOf(vis))
		}
		in.Bans = bans
	}
	for _, d := range in.Audit { // newest first: is the backend down right now?
		if in.Now.Sub(d.Time) > 10*time.Second {
			break
		}
		in.Degraded = in.Degraded || d.Degraded
	}
	return in
}

// withUsage fills in a named tenant's monthly spend, and its org's against the org's budget.
func (p *aiPlane) withUsage(r *http.Request, in *ai.Input, tenant string) {
	in.UsedOK, in.Budget = false, nil
	if tenant == "" || tenant == policy.AnonTenant {
		return
	}
	o := p.s.cfg.Policy.OrgOf(tenant)
	if u, err := p.s.cfg.Limits.UsedIn(r.Context(), tenant, o); err == nil {
		in.Used, in.UsedOK = u, true
	}
	g, ok := p.s.cfg.Dir.Snapshot().Orgs[o]
	if !ok || g.Budget <= 0 {
		return
	}
	if u, err := p.s.cfg.Limits.OrgUsed(r.Context(), o); err == nil {
		in.Budget = &ai.Budget{Org: cmp.Or(g.Name, g.ID), Used: u, Limit: g.Budget}
	}
}

func (p *aiPlane) handleExplain(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Decision *gateway.Decision `json:"decision"`
		Client   string            `json:"client"`
		Tenant   string            `json:"tenant"`
	}
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body)
	if set := btoi(body.Decision != nil) + btoi(body.Client != "") + btoi(body.Tenant != ""); err != nil || set != 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "need one of decision, client or tenant"})
		return
	}
	vis := p.s.visible(r)
	_, all := scope(r)
	in := p.input(r)
	switch {
	case body.Decision != nil:
		d := *body.Decision
		if !vis(d.Tenant) {
			notFound(w)
			return
		}
		// Prefer the audit's copy: the posted one only names which decision.
		if i := slices.IndexFunc(in.Audit, func(a gateway.Decision) bool {
			return a.Time.Equal(d.Time) && a.Client == d.Client && a.Path == d.Path
		}); i >= 0 {
			d = in.Audit[i]
		}
		in.Decision = &d
		in.Clients = p.client(d.Client)
		p.withUsage(r, &in, d.Tenant)
	case body.Client != "":
		// A client is an org's to explain once it has sent one of the org's tenants traffic.
		if !all && !p.s.Hub.ClientsOf(vis)[body.Client] {
			notFound(w)
			return
		}
		in.Client = body.Client
		in.Clients = p.client(body.Client)
		if i := slices.IndexFunc(in.Audit, func(a gateway.Decision) bool { return a.Client == body.Client }); i >= 0 {
			p.withUsage(r, &in, in.Audit[i].Tenant)
		}
	default:
		if !vis(body.Tenant) {
			notFound(w)
			return
		}
		in.Tenant = body.Tenant
		p.withUsage(r, &in, body.Tenant)
	}
	writeJSON(w, 200, p.svc.Explain(r.Context(), in))
}

func (p *aiPlane) handleChat(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Question string `json:"question"`
		TZ       string `json:"tz"` // minutes east of UTC
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body) != nil || body.Question == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "need a question"})
		return
	}
	vis := p.s.visible(r)
	q := ai.Question{Query: ai.Query{Text: body.Question, Visible: vis, Now: time.Now(), Zone: zone(body.TZ)}}
	// Tenants the question names get their live state too.
	var names []string
	for t := range p.tenants() {
		if vis(t) {
			names = append(names, t)
		}
	}
	slices.Sort(names)
	if m := ai.Mentions(body.Question, names); len(m) > 0 {
		in := p.input(r)
		for _, t := range m[:min(3, len(m))] {
			in.Tenant = t
			p.withUsage(r, &in, t)
			q.Live = append(q.Live, ai.Explain(in))
		}
	}
	writeJSON(w, 200, p.svc.Ask(r.Context(), q))
}

// zone is a fixed zone from minutes east of UTC; anything unparsable is UTC.
func zone(minutes string) *time.Location {
	m, err := strconv.Atoi(minutes)
	if err != nil || m < -14*60 || m > 14*60 {
		return time.UTC
	}
	return time.FixedZone("", m*60)
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func notFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}
