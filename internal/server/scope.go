package server

import (
	"encoding/json"
	"net/http"
	"net/netip"

	"github.com/iammdzaidalam/limitplane/internal/ai"
	"github.com/iammdzaidalam/limitplane/internal/autopilot"
	"github.com/iammdzaidalam/limitplane/internal/gateway"
	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/org"
)

// scope is the org a request looks at: the caller's own, or for the superadmin the one ?org=
// names, with all set when the superadmin names none. An unauthenticated request has no scope.
func scope(r *http.Request) (orgID string, all bool) {
	p, ok := caller(r)
	if !ok {
		return "", false
	}
	if p.super() {
		o := r.URL.Query().Get("org")
		return o, o == ""
	}
	return p.Org, false
}

// visible reports which tenants the caller of r may see: everything for the superadmin (or one
// org, with ?org=), else only the tenants of the caller's org. An unauthenticated request sees none.
// It reads the live tenant-to-org map, so a tenant moved to another org leaves the old one's view at once.
func (s *Server) visible(r *http.Request) func(tenant string) bool {
	o, all := scope(r)
	switch {
	case all:
		return func(string) bool { return true }
	case o == "":
		return func(string) bool { return false }
	}
	pol := s.cfg.Policy
	return func(t string) bool { return pol.OrgOf(t) == o }
}

// affecting keeps the bans that cover a client seen sending traffic to a tenant in view: a ban is
// per client, not per tenant, so that is the part of the list that matters to an org.
func affecting(bans []limiter.Ban, clients map[string]bool) []limiter.Ban {
	out := make([]limiter.Ban, 0)
	for _, b := range bans {
		if covers(b.Client, clients) {
			out = append(out, b)
		}
	}
	return out
}

func covers(ban string, clients map[string]bool) bool {
	if clients[ban] {
		return true
	}
	p, err := netip.ParsePrefix(ban)
	if err != nil {
		return false
	}
	for c := range clients {
		if a, err := netip.ParseAddr(c); err == nil && p.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}

// eventFilter keeps the SSE events about tenants in view: decisions, alerts and incidents (and
// their notes) by tenant, bans by whether they cover one of their clients. nil (everything) for the superadmin's unscoped view.
func (s *Server) eventFilter(r *http.Request) func(string, any) bool {
	if _, all := scope(r); all {
		return nil
	}
	vis := s.visible(r)
	about := func(tenant, client string) bool {
		if tenant != "" {
			return vis(tenant)
		}
		return client != "" && covers(client, s.Hub.ClientsOf(vis))
	}
	return func(_ string, v any) bool {
		switch x := v.(type) {
		case gateway.Decision: // the hot one: no reflection
			return vis(x.Tenant)
		case autopilot.Alert:
			return vis(x.Tenant)
		case ai.Doc: // "incident" and "note": the note names one tenant, so a fleet-wide one stays out
			return vis(x.Tenant)
		case limiter.Ban:
			return about("", x.Client)
		}
		// Anything else (say, a ban with more fields added) by the tenant or client it names; neither: dropped.
		var f struct{ Tenant, Client string }
		b, err := json.Marshal(v)
		return err == nil && json.Unmarshal(b, &f) == nil && about(f.Tenant, f.Client)
	}
}

// orgView is an org with its budget and this month's spend.
type orgView struct {
	org.Org
	Used    int64 `json:"used"`
	Members int   `json:"members"`
	Tenants int   `json:"tenants"`
}

func (s *Server) orgView(r *http.Request, o org.Org) *orgView {
	v := &orgView{Org: o, Members: len(s.cfg.Dir.Snapshot().Members(o.ID))}
	v.Used, _ = s.cfg.Limits.OrgUsed(r.Context(), o.ID) // best effort: 0 while the store is down
	for _, t := range s.cfg.Policy.Tenants() {
		if t.Org == o.ID {
			v.Tenants++
		}
	}
	return v
}
