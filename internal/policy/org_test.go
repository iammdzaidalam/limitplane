package policy

import (
	"slices"
	"strings"
	"testing"
)

func TestValidateOrgs(t *testing.T) {
	for name, keys := range map[string]map[string]Tenant{
		"bad org id":    {"k": {ID: "acme", Tier: "pro", Org: "Corp Inc"}},
		"orgs disagree": {"k1": {ID: "acme", Tier: "pro", Org: "a"}, "k2": {ID: "acme", Tier: "pro", Org: "b"}},
		"brace in id":   {"k": {ID: "ac}me", Tier: "pro", Org: "corp"}},
	} {
		c := cfg()
		c.Keys = keys
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := cfg()
	c.Keys["k2"] = Tenant{ID: "acme", Tier: "free", Org: ""} // agrees with k1: no org
	c.Keys["k3"] = Tenant{ID: "ac}me", Tier: "pro"}          // braces are fine without an org
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "corp", "acme-inc", "9lives"} {
		if !ValidOrg(id) {
			t.Errorf("%q rejected", id)
		}
	}
	for _, id := range []string{"", "-a", "a-", "A", "a_b", "a.b", "a:b", strings.Repeat("a", 41)} {
		if ValidOrg(id) {
			t.Errorf("%q accepted", id)
		}
	}
}

func TestStoreOrgs(t *testing.T) {
	c := cfg()
	c.Keys["k2"] = Tenant{ID: "globex", Tier: "free", Org: "pinned"}
	s := NewStore(c)
	var moves []string
	s.OnMove(func(t, from, to string) { moves = append(moves, t+":"+from+">"+to) })

	dashKey := "lp_" + strings.Repeat("x", 40)
	s.SetOrgs(Orgs{
		Budgets: map[string]int64{"corp": 500, "pinned": 7},
		Tenants: map[string]OrgTenant{
			"acme":   {Org: "corp"},                  // places a policy tenant
			"globex": {Org: "corp"},                  // ignored: the policy pins its org
			"web":    {Org: "corp", Tier: "free"},    // created in the directory
			"gone":   {Org: "corp", Tier: "deleted"}, // its tier left the policy
		},
		Keys: map[[32]byte]string{HashKey(dashKey): "web", HashKey("gone-key"): "gone"},
	})
	for _, c := range []struct{ key, tenant, org string }{
		{"k1", "acme", "corp"}, {"k2", "globex", "pinned"}, {dashKey, "web", "corp"}, {"gone-key", AnonTenant, ""}, {"nope", AnonTenant, ""},
	} {
		m := s.Resolve(c.key, "/")
		if m.Tenant != c.tenant || m.Org != c.org || m.OrgMonth != map[string]int64{"corp": 500, "pinned": 7}[c.org] {
			t.Errorf("%s: %+v", c.key, m)
		}
	}
	if m := s.Resolve(dashKey, "/"); m.Tier != "free" || m.Month != 100 {
		t.Errorf("directory key gets its tenant's tier: %+v", m)
	}
	var got []string
	for _, ti := range s.Tenants() {
		got = append(got, ti.ID+"/"+ti.Org+"/"+map[bool]string{true: "m", false: "-"}[ti.Managed]+map[bool]string{true: "p", false: "-"}[ti.Pinned])
	}
	if want := []string{"acme/corp/--", "globex/pinned/-p", "gone/corp/m-", "web/corp/m-"}; !slices.Equal(got, want) {
		t.Errorf("tenants %v, want %v", got, want)
	}
	slices.Sort(moves)
	if want := []string{"acme:>corp", "gone:>corp", "web:>corp"}; !slices.Equal(moves, want) {
		t.Errorf("moves %v, want %v", moves, want)
	}

	// The policy taking acme out of the directory's hands moves it too.
	moves = nil
	c.Keys["k1"] = Tenant{ID: "acme", Tier: "pro", Org: "other"}
	if err := s.Swap(c); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(moves, []string{"acme:corp>other"}) || s.OrgOf("acme") != "other" {
		t.Errorf("moves %v, org %q", moves, s.OrgOf("acme"))
	}
	if n := testing.AllocsPerRun(100, func() { s.Resolve(dashKey, "/v1/generate") }); n != 0 {
		t.Errorf("directory key lookup allocates %v", n)
	}
}
