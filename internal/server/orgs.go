package server

import (
	"cmp"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/org"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

func (s *Server) listOrgs(w http.ResponseWriter, r *http.Request) {
	p, _ := caller(r)
	out := []*orgView{}
	for _, o := range s.cfg.Dir.Snapshot().Orgs {
		if p.super() || o.ID == p.Org {
			out = append(out, s.orgView(r, o))
		}
	}
	slices.SortFunc(out, func(a, b *orgView) int { return strings.Compare(a.ID, b.ID) })
	writeJSON(w, 200, out)
}

func (s *Server) createOrg(w http.ResponseWriter, r *http.Request) {
	var body org.Org
	if !readJSON(w, r, &body) {
		return
	}
	o, err := s.cfg.Dir.CreateOrg(r.Context(), org.Org{ID: body.ID, Name: strings.TrimSpace(body.Name), Budget: body.Budget})
	if err != nil {
		dirError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, s.orgView(r, o))
}

// findOrg is the org in the path, if the caller holds role in it.
func (s *Server) findOrg(w http.ResponseWriter, r *http.Request, role org.Role) (org.Org, bool) {
	id := r.PathValue("org")
	if !need(w, r, id, role) {
		return org.Org{}, false
	}
	o, ok := s.cfg.Dir.Snapshot().Orgs[id]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
	return o, ok
}

func (s *Server) getOrg(w http.ResponseWriter, r *http.Request) {
	if o, ok := s.findOrg(w, r, org.Viewer); ok {
		writeJSON(w, 200, s.orgView(r, o))
	}
}

// updateOrg renames an org or sets its budget (owners): {"name", "budget"}, either optional.
func (s *Server) updateOrg(w http.ResponseWriter, r *http.Request) {
	o, ok := s.findOrg(w, r, org.Owner)
	var body struct {
		Name   *string `json:"name"`
		Budget *int64  `json:"budget"`
	}
	if !ok || !readJSON(w, r, &body) {
		return
	}
	o, err := s.cfg.Dir.UpdateOrg(r.Context(), o.ID, body.Name, body.Budget)
	if err != nil {
		dirError(w, err)
		return
	}
	writeJSON(w, 200, s.orgView(r, o))
}

func (s *Server) deleteOrg(w http.ResponseWriter, r *http.Request) {
	if err := s.cfg.Dir.DeleteOrg(r.Context(), r.PathValue("org")); err != nil {
		dirError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type userView struct {
	ID       string    `json:"id"`
	Email    string    `json:"email"`
	Org      string    `json:"org,omitempty"`
	Role     org.Role  `json:"role"`
	Created  time.Time `json:"created"`
	Password string    `json:"password,omitempty"` // only when it was generated, once
}

func viewUser(u org.User) userView {
	return userView{ID: u.ID, Email: u.Email, Org: u.Org, Role: u.Role, Created: u.Created}
}

func viewUsers(us []org.User) []userView {
	out := make([]userView, 0, len(us))
	for _, u := range us {
		out = append(out, viewUser(u))
	}
	slices.SortFunc(out, func(a, b userView) int { return strings.Compare(a.Email, b.Email) })
	return out
}

func (s *Server) listMembers(w http.ResponseWriter, r *http.Request) {
	if o, ok := s.findOrg(w, r, org.Owner); ok {
		writeJSON(w, 200, viewUsers(s.cfg.Dir.Snapshot().Members(o.ID)))
	}
}

// addUser creates a user in orgID: {"email", "role", "password"}. Without a password one is
// generated and returned once, for the inviter to pass on.
func (s *Server) addUser(w http.ResponseWriter, r *http.Request, orgID string, role org.Role) {
	var body struct {
		Email, Password string
		Role            org.Role
	}
	if !readJSON(w, r, &body) {
		return
	}
	if orgID != "" {
		role = body.Role
	}
	pw := body.Password
	if pw == "" {
		pw = org.NewPassword()
	}
	u, err := s.cfg.Dir.AddUser(r.Context(), orgID, body.Email, role, pw)
	if err != nil {
		dirError(w, err)
		return
	}
	v := viewUser(u)
	if body.Password == "" {
		v.Password = pw
	}
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) addMember(w http.ResponseWriter, r *http.Request) {
	if o, ok := s.findOrg(w, r, org.Owner); ok {
		s.addUser(w, r, o.ID, "")
	}
}

// findMember is the user in the path, if they belong to the org in the path and the caller owns it.
func (s *Server) findMember(w http.ResponseWriter, r *http.Request) (org.User, bool) {
	o, ok := s.findOrg(w, r, org.Owner)
	if !ok {
		return org.User{}, false
	}
	u, ok := s.cfg.Dir.Snapshot().Users[r.PathValue("user")]
	if !ok || u.Org != o.ID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return org.User{}, false
	}
	return u, true
}

func (s *Server) setRole(w http.ResponseWriter, r *http.Request) {
	u, ok := s.findMember(w, r)
	var body struct{ Role org.Role }
	if !ok || !readJSON(w, r, &body) {
		return
	}
	u, err := s.cfg.Dir.SetRole(r.Context(), u.ID, body.Role)
	if err != nil {
		dirError(w, err)
		return
	}
	writeJSON(w, 200, viewUser(u))
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request) {
	if u, ok := s.findMember(w, r); ok {
		s.removeUser(w, r, u.ID)
	}
}

func (s *Server) removeUser(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.cfg.Dir.RemoveUser(r.Context(), id); err != nil {
		dirError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// revokeMember ends every session of one member: their tokens stop working on every replica.
func (s *Server) revokeMember(w http.ResponseWriter, r *http.Request) {
	u, ok := s.findMember(w, r)
	if !ok {
		return
	}
	if _, err := s.cfg.Dir.Revoke(r.Context(), u.ID); err != nil {
		dirError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listUsers(w http.ResponseWriter, _ *http.Request) {
	us := s.cfg.Dir.Snapshot().Users
	all := make([]org.User, 0, len(us))
	for _, u := range us {
		all = append(all, u)
	}
	writeJSON(w, 200, viewUsers(all))
}

type keyView struct {
	ID      string    `json:"id"`
	Prefix  string    `json:"prefix"`
	Created time.Time `json:"created"`
}

type tenantView struct {
	policy.TenantInfo
	Keys []keyView `json:"keys,omitempty"`
}

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) {
	keep, st := s.visible(r), s.cfg.Dir.Snapshot()
	out := []tenantView{}
	for _, t := range s.cfg.Policy.Tenants() {
		if !keep(t.ID) {
			continue
		}
		v := tenantView{TenantInfo: t}
		for _, k := range st.KeysOf(t.ID) {
			v.Keys = append(v.Keys, keyView{k.ID, k.Prefix, k.Created})
		}
		slices.SortFunc(v.Keys, func(a, b keyView) int { return cmp.Or(a.Created.Compare(b.Created), strings.Compare(a.ID, b.ID)) })
		out = append(out, v)
	}
	writeJSON(w, 200, out)
}

// findTenant is the tenant in the path, if the caller holds role in its org.
func (s *Server) findTenant(w http.ResponseWriter, r *http.Request, role org.Role) (policy.TenantInfo, bool) {
	ts := s.cfg.Policy.Tenants()
	i := slices.IndexFunc(ts, func(t policy.TenantInfo) bool { return t.ID == r.PathValue("tenant") })
	if i < 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return policy.TenantInfo{}, false
	}
	return ts[i], need(w, r, ts[i].Org, role)
}

// createTenant adds a tenant with its own tier: {"id", "tier", "org"}. Members create in their own
// org; the superadmin names one, or none.
func (s *Server) createTenant(w http.ResponseWriter, r *http.Request) {
	var body struct{ ID, Tier, Org string }
	if !readJSON(w, r, &body) {
		return
	}
	if p, _ := caller(r); !p.super() && body.Org == "" {
		body.Org = p.Org
	}
	if !need(w, r, body.Org, org.Admin) {
		return
	}
	if _, ok := s.cfg.Policy.Config().Tiers[body.Tier]; !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown tier " + body.Tier})
		return
	}
	if body.ID == policy.AnonTenant || slices.ContainsFunc(s.cfg.Policy.Tenants(), func(t policy.TenantInfo) bool { return t.ID == body.ID }) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "tenant " + body.ID + " already exists"})
		return
	}
	t, err := s.cfg.Dir.CreateTenant(r.Context(), org.Tenant{ID: body.ID, Org: body.Org, Tier: body.Tier})
	if err != nil {
		dirError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

// managed refuses changes to tenants the policy defines: their keys and tier live in the policy file or Tenant CR.
func managed(w http.ResponseWriter, t policy.TenantInfo) bool {
	if !t.Managed {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "tenant " + t.ID + " is defined by the policy; change it there"})
	}
	return t.Managed
}

func (s *Server) deleteTenant(w http.ResponseWriter, r *http.Request) {
	t, ok := s.findTenant(w, r, org.Admin)
	if !ok || !managed(w, t) {
		return
	}
	if err := s.cfg.Dir.DeleteTenant(r.Context(), t.ID); err != nil {
		dirError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// placeTenant moves any tenant to an org, or out of one with "": {"org"}. Its counters follow.
func (s *Server) placeTenant(w http.ResponseWriter, r *http.Request) {
	t, ok := s.findTenant(w, r, org.Superadmin)
	var body struct{ Org string }
	if !ok || !readJSON(w, r, &body) {
		return
	}
	if t.Pinned {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "tenant " + t.ID + "'s org is set by the policy; change it there"})
		return
	}
	if _, err := s.cfg.Dir.PlaceTenant(r.Context(), t.ID, body.Org); err != nil {
		dirError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// createKey makes an API key for a tenant created here. The key is in this response only; the
// directory keeps its SHA-256, which every replica resolves.
func (s *Server) createKey(w http.ResponseWriter, r *http.Request) {
	t, ok := s.findTenant(w, r, org.Admin)
	if !ok || !managed(w, t) {
		return
	}
	k, plain, err := s.cfg.Dir.CreateKey(r.Context(), t.ID)
	if err != nil {
		dirError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": k.ID, "prefix": k.Prefix, "created": k.Created, "tenant": t.ID, "key": plain})
}

func (s *Server) deleteKey(w http.ResponseWriter, r *http.Request) {
	t, ok := s.findTenant(w, r, org.Admin)
	if !ok {
		return
	}
	if err := s.cfg.Dir.DeleteKey(r.Context(), t.ID, r.PathValue("key")); err != nil {
		dirError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
