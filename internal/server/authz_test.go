package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/gateway"
	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/org"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

const orgPolicy = `{
 "tiers": {"free": {"rate": {"limit": 100, "period": "1s", "burst": 100}, "monthly": 1000}},
 "keys": {"pinned-key": {"id": "acme-pinned", "tier": "free", "org": "acme"}, "loose-key": {"id": "loose", "tier": "free"}},
 "anonymous": "free"
}`

const testPassword = "a long enough password"

// orgRig is a server with two orgs (acme, globex) and an idle one, an owner, admin and viewer in
// each, a platform user, and one dashboard tenant with a key per org.
type orgRig struct {
	s      *Server
	ts     *httptest.Server
	tok    map[string]string // actor -> token
	ids    map[string]string // name -> user or key id
	keys   map[string]string // tenant -> its plaintext key
	logins int               // each sign-in comes from its own IP, clear of the per-IP limit
}

func email(actor string) string {
	if actor == "staff" {
		return "staff@platform.test"
	}
	o, role, _ := strings.Cut(actor, "/")
	return role + "@" + o + ".test"
}

var actors = []string{"anon", "admin-key", "staff", "acme/owner", "acme/admin", "acme/viewer", "globex/owner", "globex/admin", "globex/viewer"}

func newOrgRig(t *testing.T) *orgRig {
	t.Helper()
	cfg, err := policy.Parse([]byte(orgPolicy))
	if err != nil {
		t.Fatal(err)
	}
	dir := org.NewMemory()
	dir.UseIterations(1000)
	s := New(Config{Policy: policy.NewStore(cfg), Limits: limiter.NewMemory(), Dir: dir, AdminKey: "admin-key", Backend: "memory", TrustProxy: true})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	ts := httptest.NewServer(s.Handler(nil))
	t.Cleanup(func() { cancel(); ts.Close() })

	rg := &orgRig{s: s, ts: ts, tok: map[string]string{}, ids: map[string]string{}, keys: map[string]string{}}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, o := range []string{"acme", "globex", "idle"} {
		_, err := dir.CreateOrg(ctx, org.Org{ID: o, Name: strings.ToUpper(o[:1]) + o[1:]})
		must(err)
	}
	for _, a := range actors[3:] {
		o, role, _ := strings.Cut(a, "/")
		u, err := dir.AddUser(ctx, o, email(a), org.Role(role), testPassword)
		must(err)
		rg.ids[a] = u.ID
	}
	u, err := dir.AddUser(ctx, "", email("staff"), org.Superadmin, testPassword)
	must(err)
	rg.ids["staff"] = u.ID
	for _, o := range []string{"acme", "globex"} {
		_, err := dir.CreateTenant(ctx, org.Tenant{ID: o + "-web", Org: o, Tier: "free"})
		must(err)
		k, plain, err := dir.CreateKey(ctx, o+"-web")
		must(err)
		rg.ids[o+"-key"], rg.keys[o+"-web"] = k.ID, plain
	}
	for _, a := range actors[2:] {
		rg.tok[a] = rg.signIn(t, a)
	}
	rg.tok["admin-key"] = login(t, ts.URL)
	return rg
}

func (rg *orgRig) signIn(t *testing.T, actor string) string {
	t.Helper()
	if actor == "admin-key" {
		return ""
	}
	rg.logins++
	req, _ := http.NewRequest("POST", rg.ts.URL+"/api/login", strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email(actor), testPassword)))
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("192.0.2.%d", 100+rg.logins))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out sessionView
	if res.StatusCode != 200 || json.NewDecoder(res.Body).Decode(&out) != nil || out.Token == "" {
		t.Fatalf("login %s: %d", actor, res.StatusCode)
	}
	return out.Token
}

// send makes one gateway request with key from client ip (the rig trusts X-Forwarded-For).
func (rg *orgRig) send(t *testing.T, key, ip string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", rg.ts.URL+"/v1/ping", nil)
	req.Header.Set("X-Api-Key", key)
	req.Header.Set("X-Forwarded-For", ip)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

// Every admin endpoint, every role, own org and the other one. A member of another org gets 404
// (the same as for something that doesn't exist), a member whose role is too low 403, anyone for
// a platform-only route 403, and no token 401.
func TestAuthorizationMatrix(t *testing.T) {
	const own = "*" // reads scoped to the caller's own org: everyone signed in gets 200
	routes := []struct {
		method, path, body string
		org                string   // whose resource it is; own for scoped reads, "" platform only
		need               org.Role // the least role that may
		ok                 int
		except             map[string]int // actor -> status, where the rule above doesn't apply
	}{
		{"GET", "/api/me", "", own, org.Viewer, 200, nil},
		{"PUT", "/api/me/password", `{"current":"` + testPassword + `","password":"another long password"}`, own, org.Viewer, 200, map[string]int{"admin-key": 400}},
		{"POST", "/api/me/revoke", "", own, org.Viewer, 204, map[string]int{"admin-key": 400}},
		{"GET", "/api/stats", "", own, org.Viewer, 200, nil},
		{"GET", "/api/events", "", own, org.Viewer, 200, nil},
		{"GET", "/api/audit", "", own, org.Viewer, 200, nil},
		{"GET", "/api/clients", "", own, org.Viewer, 200, nil},
		{"GET", "/api/bans", "", own, org.Viewer, 200, nil},
		{"POST", "/api/bans", `{"client":"203.0.113.9","minutes":5}`, "", org.Superadmin, 204, nil},
		{"DELETE", "/api/bans/203.0.113.9", "", "", org.Superadmin, 204, nil},
		{"GET", "/api/policy", "", own, org.Viewer, 200, nil},
		{"PUT", "/api/policy", orgPolicy, "", org.Superadmin, 200, nil},
		{"GET", "/api/orgs", "", own, org.Viewer, 200, nil},
		{"POST", "/api/orgs", `{"name":"Initech"}`, "", org.Superadmin, 201, nil},
		{"DELETE", "/api/orgs/idle", "", "", org.Superadmin, 204, nil},
		{"DELETE", "/api/orgs/acme", "", "", org.Superadmin, 409, nil}, // it has tenants
		{"GET", "/api/orgs/acme", "", "acme", org.Viewer, 200, nil},
		{"PATCH", "/api/orgs/acme", `{"budget":100}`, "acme", org.Owner, 200, nil},
		{"GET", "/api/orgs/acme/members", "", "acme", org.Owner, 200, nil},
		{"POST", "/api/orgs/acme/members", `{"email":"new@acme.test","role":"viewer"}`, "acme", org.Owner, 201, nil},
		{"PATCH", "/api/orgs/acme/members/{acme/viewer}", `{"role":"admin"}`, "acme", org.Owner, 200, nil},
		{"DELETE", "/api/orgs/acme/members/{acme/viewer}", "", "acme", org.Owner, 204, nil},
		{"POST", "/api/orgs/acme/members/{acme/viewer}/revoke", "", "acme", org.Owner, 204, nil},
		// A member of another org through this org's path: not there.
		{"PATCH", "/api/orgs/acme/members/{globex/viewer}", `{"role":"admin"}`, "acme", org.Owner, 404, nil},
		{"DELETE", "/api/orgs/acme/members/{globex/owner}", "", "acme", org.Owner, 404, nil},
		{"GET", "/api/users", "", "", org.Superadmin, 200, nil},
		{"POST", "/api/users", `{"email":"ops@platform.test"}`, "", org.Superadmin, 201, nil},
		{"DELETE", "/api/users/{globex/viewer}", "", "", org.Superadmin, 204, nil},
		{"GET", "/api/tenants", "", own, org.Viewer, 200, nil},
		{"POST", "/api/tenants", `{"id":"acme-new","tier":"free","org":"acme"}`, "acme", org.Admin, 201, nil},
		{"DELETE", "/api/tenants/acme-web", "", "acme", org.Admin, 204, nil},
		{"DELETE", "/api/tenants/acme-pinned", "", "acme", org.Admin, 409, nil}, // the policy defines it
		{"PUT", "/api/tenants/acme-web/org", `{"org":"globex"}`, "", org.Superadmin, 204, nil},
		{"PUT", "/api/tenants/acme-pinned/org", `{"org":"globex"}`, "", org.Superadmin, 409, nil},
		{"POST", "/api/tenants/acme-web/keys", "", "acme", org.Admin, 201, nil},
		{"DELETE", "/api/tenants/acme-web/keys/{acme-key}", "", "acme", org.Admin, 204, nil},
		{"DELETE", "/api/tenants/acme-web/keys/{globex-key}", "", "acme", org.Admin, 404, nil},
		{"POST", "/api/tenants/loose/keys", "", "-", org.Admin, 409, nil}, // in no org: the platform's, and policy-defined
		{"GET", "/api/ai/status", "", own, org.Viewer, 200, nil},
		{"GET", "/api/ai/incidents", "", own, org.Viewer, 200, nil},
		{"POST", "/api/ai/chat", `{"question":"what happened today?"}`, own, org.Viewer, 200, nil},
		{"POST", "/api/ai/explain", `{"tenant":"acme-web"}`, "acme", org.Viewer, 200, nil},
		{"POST", "/api/ai/explain", `{"decision":{"tenant":"acme-pinned","client":"203.0.113.1"}}`, "acme", org.Viewer, 200, nil},
		{"POST", "/api/ai/explain", `{"tenant":"loose"}`, "-", org.Viewer, 200, nil}, // in no org: only the platform sees it
	}
	for _, rt := range routes {
		for _, a := range actors {
			t.Run(rt.method+" "+rt.path+" as "+a, func(t *testing.T) {
				rg := newOrgRig(t)
				path := rt.path
				for name, id := range rg.ids {
					path = strings.ReplaceAll(path, "{"+name+"}", id)
				}
				res := do(t, rt.method, rg.ts.URL+path, rg.tok[a], rt.body)
				if got, want := res.StatusCode, expect(a, rt.org, rt.need, rt.ok, rt.except); got != want {
					t.Fatalf("got %d, want %d", got, want)
				}
			})
		}
	}
}

func expect(actor, target string, need org.Role, ok int, except map[string]int) int {
	if c, found := except[actor]; found {
		return c
	}
	o, role, _ := strings.Cut(actor, "/")
	switch {
	case actor == "anon":
		return 401
	case actor == "admin-key" || actor == "staff":
		return ok
	case need == org.Superadmin:
		return 403
	case target != "*" && target != o:
		return 404
	case !org.Role(role).AtLeast(need):
		return 403
	}
	return ok
}

// What each role reads: only its own org's tenants, decisions, clients, bans and totals.
func TestScopedReads(t *testing.T) {
	rg := newOrgRig(t)
	for i := range 3 {
		rg.send(t, rg.keys["acme-web"], "203.0.113.1")
		rg.send(t, "pinned-key", "203.0.113.1")
		if i < 2 {
			rg.send(t, rg.keys["globex-web"], "198.51.100.2")
		}
	}
	rg.send(t, "loose-key", "192.0.2.3")
	for _, c := range []string{"203.0.113.0/24", "198.51.100.2", "192.0.2.3"} {
		if r := do(t, "POST", rg.ts.URL+"/api/bans", rg.tok["admin-key"], `{"client":"`+c+`","minutes":5}`); r.StatusCode != 204 {
			t.Fatalf("ban %s: %d", c, r.StatusCode)
		}
	}
	waitAudit(t, rg, 9)

	type view struct {
		tenants, clients, bans []string
		total                  int64
		budgetOrg              string
	}
	read := func(tok, query string) view {
		var v view
		var st stats
		json.NewDecoder(do(t, "GET", rg.ts.URL+"/api/stats"+query, tok, "").Body).Decode(&st)
		for _, x := range st.Tenants {
			v.tenants = append(v.tenants, x.Tenant)
		}
		v.total = st.Total
		if st.Org != nil {
			v.budgetOrg = st.Org.ID
		}
		var tenants []tenantView
		json.NewDecoder(do(t, "GET", rg.ts.URL+"/api/tenants"+query, tok, "").Body).Decode(&tenants)
		for _, x := range tenants {
			if !slices.Contains(v.tenants, x.ID) {
				t.Errorf("/api/tenants has %s, stats doesn't", x.ID)
			}
		}
		var audit []gateway.Decision
		json.NewDecoder(do(t, "GET", rg.ts.URL+"/api/audit"+query, tok, "").Body).Decode(&audit)
		for _, d := range audit {
			if !slices.Contains(v.tenants, d.Tenant) {
				t.Errorf("audit leaks %s", d.Tenant)
			}
		}
		var clients []struct{ Client string }
		json.NewDecoder(do(t, "GET", rg.ts.URL+"/api/clients"+query, tok, "").Body).Decode(&clients)
		for _, c := range clients {
			v.clients = append(v.clients, c.Client)
		}
		var bans []limiter.Ban
		json.NewDecoder(do(t, "GET", rg.ts.URL+"/api/bans"+query, tok, "").Body).Decode(&bans)
		for _, b := range bans {
			v.bans = append(v.bans, b.Client)
		}
		slices.Sort(v.clients)
		slices.Sort(v.bans)
		return v
	}
	acme := view{[]string{"acme-pinned", "acme-web"}, []string{"203.0.113.1"}, []string{"203.0.113.0/24"}, 6, "acme"}
	globex := view{[]string{"globex-web"}, []string{"198.51.100.2"}, []string{"198.51.100.2"}, 2, "globex"}
	for who, want := range map[string]view{
		"acme/viewer": acme, "acme/owner": acme, "globex/viewer": globex,
		"admin-key": {[]string{"acme-pinned", "acme-web", "globex-web", "loose", "anonymous"}, []string{"192.0.2.3", "198.51.100.2", "203.0.113.1"}, []string{"192.0.2.3", "198.51.100.2", "203.0.113.0/24"}, 9, ""},
	} {
		if got := read(rg.tok[who], ""); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s sees %+v, want %+v", who, got, want)
		}
	}
	// The org switcher: the superadmin looks at one org the way its members do; members can't switch.
	if got := read(rg.tok["staff"], "?org=acme"); fmt.Sprint(got) != fmt.Sprint(acme) {
		t.Errorf("superadmin as acme: %+v", got)
	}
	if got := read(rg.tok["globex/viewer"], "?org=acme"); fmt.Sprint(got) != fmt.Sprint(globex) {
		t.Errorf("a member can't switch orgs: %+v", got)
	}
	// Policy: tiers and routes for everyone, keys only for the platform admin.
	var c policy.Config
	json.NewDecoder(do(t, "GET", rg.ts.URL+"/api/policy", rg.tok["acme/owner"], "").Body).Decode(&c)
	if len(c.Keys) != 0 || len(c.Tiers) != 1 {
		t.Errorf("member policy view %+v", c)
	}
	var orgs []orgView
	json.NewDecoder(do(t, "GET", rg.ts.URL+"/api/orgs", rg.tok["globex/admin"], "").Body).Decode(&orgs)
	if len(orgs) != 1 || orgs[0].ID != "globex" || orgs[0].Used != 2 {
		t.Errorf("orgs as globex: %+v", orgs)
	}
}

func waitAudit(t *testing.T, rg *orgRig, n int) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); len(rg.s.Hub.Audit(n)) < n; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("hub saw %d decisions, want %d", len(rg.s.Hub.Audit(n)), n)
		}
	}
}

// The live stream carries only the org's decisions.
func TestScopedEvents(t *testing.T) {
	rg := newOrgRig(t)
	sse := do(t, "GET", rg.ts.URL+"/api/events?token="+rg.tok["acme/viewer"], "", "")
	got := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(sse.Body)
		for sc.Scan() {
			if d, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				got <- d
			}
		}
	}()
	rg.send(t, rg.keys["globex-web"], "198.51.100.2")
	rg.send(t, "loose-key", "192.0.2.3")
	rg.send(t, rg.keys["acme-web"], "203.0.113.1")
	next := func() string {
		select {
		case d := <-got:
			return d
		case <-time.After(2 * time.Second):
			t.Fatal("no event")
		}
		return ""
	}
	if d := next(); !strings.Contains(d, `"tenant":"acme-web"`) {
		t.Fatalf("first event %s: another org's decision leaked", d)
	}
	// Bans reach the org whose clients they cover, wrapped in more fields or not.
	waitAudit(t, rg, 3)
	for _, c := range []string{"198.51.100.2", "203.0.113.0/24"} {
		do(t, "POST", rg.ts.URL+"/api/bans", rg.tok["admin-key"], `{"client":"`+c+`","minutes":5}`)
	}
	if d := next(); !strings.Contains(d, `"client":"203.0.113.0/24"`) {
		t.Fatalf("ban event %s: want only the one covering acme's client", d)
	}
	rg.s.Hub.Publish("ban", struct {
		limiter.Ban
		Note string `json:"note"`
	}{limiter.Ban{Client: "198.51.100.2"}, "globex's"})
	rg.s.Hub.Publish("alert", struct {
		Tenant string `json:"tenant"`
		Note   string `json:"note"`
	}{"acme-web", "acme's"})
	if d := next(); !strings.Contains(d, `"note":"acme's"`) {
		t.Fatalf("wrapped event %s", d)
	}
}

// Revoking a member ends their tokens at once; signing in again works.
func TestRevokeAndRoleChange(t *testing.T) {
	rg := newOrgRig(t)
	viewer := rg.tok["acme/viewer"]
	if r := do(t, "GET", rg.ts.URL+"/api/stats", viewer, ""); r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	if r := do(t, "POST", rg.ts.URL+"/api/orgs/acme/members/"+rg.ids["acme/viewer"]+"/revoke", rg.tok["acme/owner"], ""); r.StatusCode != 204 {
		t.Fatal(r.StatusCode)
	}
	if r := do(t, "GET", rg.ts.URL+"/api/stats", viewer, ""); r.StatusCode != 401 {
		t.Fatalf("revoked token: %d", r.StatusCode)
	}
	fresh := rg.signIn(t, "acme/viewer")
	if r := do(t, "GET", rg.ts.URL+"/api/stats", fresh, ""); r.StatusCode != 200 {
		t.Fatalf("new token: %d", r.StatusCode)
	}
	// A role change ends the old sessions too: they carry the old role.
	do(t, "PATCH", rg.ts.URL+"/api/orgs/acme/members/"+rg.ids["acme/viewer"], rg.tok["acme/owner"], `{"role":"admin"}`)
	if r := do(t, "GET", rg.ts.URL+"/api/stats", fresh, ""); r.StatusCode != 401 {
		t.Fatalf("token with the old role: %d", r.StatusCode)
	}
	// The last owner can't be demoted or removed.
	if r := do(t, "PATCH", rg.ts.URL+"/api/orgs/acme/members/"+rg.ids["acme/owner"], rg.tok["acme/owner"], `{"role":"viewer"}`); r.StatusCode != 409 {
		t.Fatalf("demote the last owner: %d", r.StatusCode)
	}
	// A token for a user who no longer exists is dead.
	staff := rg.tok["staff"]
	do(t, "DELETE", rg.ts.URL+"/api/users/"+rg.ids["staff"], rg.tok["admin-key"], "")
	if r := do(t, "GET", rg.ts.URL+"/api/me", staff, ""); r.StatusCode != 401 {
		t.Fatalf("deleted user's token: %d", r.StatusCode)
	}
}

// Keys made in the dashboard work at once, and stop at once when revoked; an org budget set by
// its owner caps both of its tenants together.
func TestDashboardKeysAndBudget(t *testing.T) {
	rg := newOrgRig(t)
	owner := rg.tok["acme/owner"]
	var k struct{ ID, Key string }
	json.NewDecoder(do(t, "POST", rg.ts.URL+"/api/tenants/acme-web/keys", owner, "").Body).Decode(&k)
	if !strings.HasPrefix(k.Key, "lp_") || rg.send(t, k.Key, "203.0.113.1") != 200 {
		t.Fatalf("new key %+v", k)
	}
	var tenants []tenantView
	json.NewDecoder(do(t, "GET", rg.ts.URL+"/api/tenants", owner, "").Body).Decode(&tenants)
	if b, _ := json.Marshal(tenants); strings.Contains(string(b), k.Key) || strings.Contains(string(b), `"hash"`) {
		t.Fatalf("the key or its hash is listed: %s", b)
	}
	do(t, "DELETE", rg.ts.URL+"/api/tenants/acme-web/keys/"+k.ID, owner, "")
	req, _ := http.NewRequest("GET", rg.ts.URL+"/v1/ping", nil)
	req.Header.Set("X-Api-Key", k.Key)
	res, _ := http.DefaultClient.Do(req)
	var body struct{ Tenant string }
	json.NewDecoder(res.Body).Decode(&body)
	res.Body.Close()
	if body.Tenant != policy.AnonTenant {
		t.Fatalf("a revoked key still resolves to %q", body.Tenant)
	}

	if r := do(t, "PATCH", rg.ts.URL+"/api/orgs/acme", owner, `{"budget":5}`); r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	allowed := 0
	for i := range 8 {
		key := []string{rg.keys["acme-web"], "pinned-key"}[i%2]
		if rg.send(t, key, "203.0.113.1") == 200 {
			allowed++
		}
	}
	if allowed != 4 { // 1 already spent above, budget 5
		t.Fatalf("allowed %d of the budget's remaining 4", allowed)
	}
	if rg.send(t, rg.keys["globex-web"], "198.51.100.2") != 200 {
		t.Fatal("another org is not capped by acme's budget")
	}
	// A tenant made just now is counted under its own name from its first request.
	do(t, "POST", rg.ts.URL+"/api/tenants", rg.tok["globex/admin"], `{"id":"fresh","tier":"free"}`)
	json.NewDecoder(do(t, "POST", rg.ts.URL+"/api/tenants/fresh/keys", rg.tok["globex/admin"], "").Body).Decode(&k)
	rg.send(t, k.Key, "198.51.100.2")
	waitAudit(t, rg, 12)
	var st stats
	json.NewDecoder(do(t, "GET", rg.ts.URL+"/api/stats", rg.tok["globex/viewer"], "").Body).Decode(&st)
	if i := slices.IndexFunc(st.Tenants, func(x tenantStats) bool { return x.Tenant == "fresh" }); i < 0 || st.Tenants[i].Allowed != 1 {
		t.Fatalf("new tenant's stats %+v", st.Tenants)
	}
	var o orgView
	json.NewDecoder(do(t, "GET", rg.ts.URL+"/api/orgs/acme", rg.tok["acme/viewer"], "").Body).Decode(&o)
	if o.Budget != 5 || o.Used != 5 || o.Tenants != 2 {
		t.Fatalf("org view %+v", o)
	}
}

// Invite-only by default; with Signup, anyone can make an org they own.
func TestSignup(t *testing.T) {
	rg := newOrgRig(t)
	body := `{"org":"Hooli","email":"gavin@hooli.test","password":"` + testPassword + `"}`
	if r := do(t, "POST", rg.ts.URL+"/api/signup", "", body); r.StatusCode != 403 {
		t.Fatalf("signup while off: %d", r.StatusCode)
	}
	rg.s.cfg.Signup = true
	res := do(t, "POST", rg.ts.URL+"/api/signup", "", body)
	var s sessionView
	if json.NewDecoder(res.Body).Decode(&s); res.StatusCode != 201 || s.Org != "hooli" || s.Role != org.Owner {
		t.Fatalf("signup %d %+v", res.StatusCode, s)
	}
	if r := do(t, "GET", rg.ts.URL+"/api/orgs/hooli/members", s.Token, ""); r.StatusCode != 200 {
		t.Fatalf("new owner: %d", r.StatusCode)
	}
	if r := do(t, "POST", rg.ts.URL+"/api/signup", "", strings.Replace(body, "gavin", "other", 1)); r.StatusCode != 409 {
		t.Fatalf("taken org: %d", r.StatusCode)
	}
}

// Logins are limited per account across IPs, not only per IP.
func TestLoginPerAccountLimit(t *testing.T) {
	rg := newOrgRig(t)
	var codes []int
	for i := range 12 {
		req, _ := http.NewRequest("POST", rg.ts.URL+"/api/login", strings.NewReader(`{"email":"owner@acme.test","password":"wrong password!"}`))
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i+10))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		codes = append(codes, res.StatusCode)
	}
	if codes[0] != 401 || codes[8] != 401 || codes[9] != 429 { // the rig's own sign-in spent one
		t.Fatalf("codes %v", codes)
	}
}
