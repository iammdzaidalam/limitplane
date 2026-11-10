package kube

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/autopilot"
)

func policyCR(t *testing.T, spec string) RateLimitPolicy {
	t.Helper()
	if !json.Valid([]byte(spec)) {
		t.Fatalf("bad test spec %s", spec)
	}
	return RateLimitPolicy{Metadata: ObjectMeta{Name: "default"}, Spec: json.RawMessage(spec)}
}

const goodSpec = `{"tiers":{"free":{"rate":{"limit":5,"period":"1s","burst":10}},"pro":{"rate":{"limit":50,"period":"1s","burst":100},"monthly":1000}},
	"routes":[{"prefix":"/v1","cost":2}],"anonymous":"free"}`

func tenant(id, tier, secret, key string) Tenant {
	var t Tenant
	t.Spec.ID, t.Spec.Tier = id, tier
	t.Spec.KeySecretRef.Name, t.Spec.KeySecretRef.Key = secret, key
	return t
}

func secret(kv ...string) Secret {
	s := Secret{Data: map[string][]byte{}}
	for i := 0; i < len(kv); i += 2 {
		s.Data[kv[i]] = []byte(kv[i+1])
	}
	return s
}

// Each unusable Tenant gets its own reason, and none of them blocks the others or the policy.
func TestBuildTenantConditions(t *testing.T) {
	tenants := map[string]Tenant{
		"a-ok":       tenant("acme", "pro", "acme-key", "apiKey"),
		"b-noid":     tenant("", "pro", "acme-key", "apiKey"),
		"c-tier":     tenant("c", "gold", "acme-key", "apiKey"),
		"d-nosecret": tenant("d", "pro", "missing", "apiKey"),
		"e-nokey":    tenant("e", "pro", "acme-key", "other"),
		"f-blank":    tenant("f", "pro", "blank", "apiKey"),
		"g-dup":      tenant("globex", "free", "acme-key", "apiKey"), // same key as a-ok, sorts after it
		"h-trim":     tenant("hooli", "free", "hooli-key", "apiKey"),
	}
	secrets := map[string]Secret{
		"acme-key":  secret("apiKey", "k-acme"),
		"blank":     secret("apiKey", " \n"),
		"hooli-key": secret("apiKey", "  k-hooli\n"), // kubectl create secret --from-file adds a newline
	}
	cfg, _, conds, err := build(policyCR(t, goodSpec), tenants, secrets)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"a-ok": "True/Active", "b-noid": "False/InvalidSpec", "c-tier": "False/UnknownTier",
		"d-nosecret": "False/SecretNotFound", "e-nokey": "False/KeyNotFound", "f-blank": "False/KeyNotFound",
		"g-dup": "False/DuplicateKey", "h-trim": "True/Active",
	}
	for name, w := range want {
		if got := conds[name].Status + "/" + conds[name].Reason; got != w || conds[name].Type != "Ready" {
			t.Errorf("%s: %s (%s), want %s", name, got, conds[name].Message, w)
		}
	}
	if !strings.Contains(conds["g-dup"].Message, "acme") || !strings.Contains(conds["c-tier"].Message, `"gold"`) {
		t.Errorf("messages: %q, %q", conds["g-dup"].Message, conds["c-tier"].Message)
	}
	if len(cfg.Keys) != 2 || cfg.Keys["k-acme"].ID != "acme" || cfg.Keys["k-hooli"].Tier != "free" {
		t.Fatalf("keys %+v", cfg.Keys)
	}
}

// An invalid policy turns every otherwise-ready Tenant to PolicyInvalid; the per-tenant reasons stay.
func TestBuildInvalidPolicy(t *testing.T) {
	tenants := map[string]Tenant{"ok": tenant("acme", "free", "s", "k"), "bad": tenant("x", "gold", "s", "k")}
	secrets := map[string]Secret{"s": secret("k", "v")}
	for name, spec := range map[string]string{
		"burst < cost":    `{"tiers":{"free":{"rate":{"limit":5,"period":"1s","burst":1}}},"routes":[{"prefix":"/a","cost":3}],"anonymous":"free"}`,
		"unknown field":   `{"tiers":{"free":{"rate":{"limit":5,"period":"1s","burst":5}}},"anonymous":"free","typo":1}`,
		"no anonymous":    `{"tiers":{"free":{"rate":{"limit":5,"period":"1s","burst":5}}}}`,
		"bad autopilot":   `{"tiers":{"free":{"rate":{"limit":5,"period":"1s","burst":5}}},"anonymous":"free","autopilot":{"banFor":"forever"}}`,
		"spec not object": `[1,2]`,
		"keys in the CR":  `{"tiers":{"free":{"rate":{"limit":5,"period":"1s","burst":5}}},"anonymous":"free","keys":{"k":{"id":"a","tier":"free"}}}`,
	} {
		_, _, conds, err := build(policyCR(t, spec), tenants, secrets)
		if name == "keys in the CR" { // Tenants own the keys: inline ones are replaced, not merged
			if err != nil || conds["ok"].Status != "True" {
				t.Errorf("%s: %v %+v", name, err, conds)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: want error", name)
			continue
		}
		if conds["ok"].Reason != "PolicyInvalid" && name != "spec not object" {
			t.Errorf("%s: ok tenant %+v", name, conds["ok"])
		}
		if name != "spec not object" && conds["bad"].Reason != "UnknownTier" {
			t.Errorf("%s: bad tenant %+v", name, conds["bad"])
		}
	}
}

func TestBuildAutopilotRules(t *testing.T) {
	_, rules, _, err := build(policyCR(t, goodSpec), nil, nil)
	if err != nil || rules != autopilot.DefaultRules {
		t.Fatalf("no autopilot block: %+v %v", rules, err)
	}
	spec := strings.Replace(goodSpec, `"anonymous":"free"`, `"anonymous":"free","autopilot":{"stormWindow":"30s"}`, 1)
	_, rules, _, err = build(policyCR(t, spec), nil, nil)
	if err != nil || rules.StormWindow != 30*time.Second || rules.StormBlocks != autopilot.DefaultRules.StormBlocks {
		t.Fatalf("partial autopilot: %+v %v", rules, err)
	}
	// "null" spec is an empty policy: invalid (no tiers), not a crash.
	if _, _, _, err := build(policyCR(t, `null`), nil, nil); err == nil {
		t.Fatal("null spec must be invalid")
	}
}

func TestTransition(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	old := []Condition{{Type: "Ready", Status: "True", Reason: "Active", LastTransitionTime: "2026-01-01T00:00:00Z"}}
	if c := transition(Condition{Type: "Ready", Status: "True", Reason: "Other"}, old, now); c.LastTransitionTime != "2026-01-01T00:00:00Z" {
		t.Fatalf("same status kept? %s", c.LastTransitionTime)
	}
	if c := transition(Condition{Type: "Ready", Status: "False"}, old, now); c.LastTransitionTime != "2026-11-10T12:00:00Z" {
		t.Fatalf("flip: %s", c.LastTransitionTime)
	}
	if c := transition(Condition{Type: "Applied", Status: "True"}, old, now); c.LastTransitionTime != "2026-11-10T12:00:00Z" {
		t.Fatalf("new type: %s", c.LastTransitionTime)
	}
	cur := Condition{Type: "Ready", Status: "True", Reason: "Active", Message: "m"}
	for _, c := range []struct {
		old  []Condition
		want bool
	}{
		{nil, true},
		{[]Condition{{Type: "Ready", Status: "True", Reason: "Active", Message: "m", LastTransitionTime: "x"}}, false},
		{[]Condition{{Type: "Ready", Status: "True", Reason: "Active", Message: "other"}}, true},
		{[]Condition{{Type: "Ready", Status: "False", Reason: "Active", Message: "m"}}, true},
		{[]Condition{{Type: "Applied", Status: "True", Reason: "Active", Message: "m"}}, true},
	} {
		if got := changed(cur, c.old); got != c.want {
			t.Errorf("changed(%+v) = %v", c.old, got)
		}
	}
	if s := oneLine(errors.Join(errors.New("a"), errors.New("b"))); s != "a; b" {
		t.Fatalf("oneLine %q", s)
	}
}

// spec.org places a Tenant in an org; a bad org id, or two Tenants of one id in different orgs,
// make only that Tenant not ready.
func TestBuildTenantOrg(t *testing.T) {
	inOrg := func(id, org, key string) Tenant {
		x := tenant(id, "pro", "keys", key)
		x.Spec.Org = org
		return x
	}
	tenants := map[string]Tenant{
		"a": inOrg("acme", "corp", "a"), "b": inOrg("acme", "corp", "b"), "c": inOrg("acme", "other", "c"),
		"d": inOrg("bad", "Not An Org", "d"), "e": inOrg("br{ce}", "corp", "e"),
	}
	cfg, _, conds, err := build(policyCR(t, goodSpec), tenants, map[string]Secret{"keys": secret("a", "ka", "b", "kb", "c", "kc", "d", "kd", "e", "ke")})
	if err != nil {
		t.Fatal(err)
	}
	for name, w := range map[string]string{"a": "True/Active", "b": "True/Active", "c": "False/OrgConflict", "d": "False/InvalidSpec", "e": "False/InvalidSpec"} {
		if got := conds[name].Status + "/" + conds[name].Reason; got != w {
			t.Errorf("%s: %s (%s), want %s", name, got, conds[name].Message, w)
		}
	}
	if cfg.Keys["ka"].Org != "corp" || cfg.Keys["kb"].Org != "corp" || len(cfg.Keys) != 2 || !strings.Contains(conds["a"].Message, "org corp") {
		t.Fatalf("keys %+v, %q", cfg.Keys, conds["a"].Message)
	}
}
