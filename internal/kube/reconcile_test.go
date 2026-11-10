package kube

import (
	"context"
	"encoding/base64"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/autopilot"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

const (
	tenantsPath = "/apis/limitplane.dev/v1alpha1/namespaces/ns/tenants"
	secretsPath = "/api/v1/namespaces/ns/secrets"
	eventsPath  = "/api/v1/namespaces/ns/events"
)

func policyObj(name string, cost int) obj {
	rate := func(l, b int) obj { return obj{"limit": l, "period": "1s", "burst": b} }
	return obj{"metadata": obj{"name": name}, "spec": obj{
		"tiers": obj{
			"free": obj{"rate": rate(5, 10), "monthly": 1000},
			"pro":  obj{"rate": rate(50, 100), "monthly": 100000},
		},
		"routes":    []any{obj{"prefix": "/v1/generate", "cost": cost}},
		"anonymous": "free",
		"autopilot": obj{"stormBlocks": 20, "stormWindow": "10s", "banFor": "5m"},
	}}
}

func tenantObj(name, tier string) obj {
	return obj{"metadata": obj{"name": name}, "spec": obj{"id": name, "tier": tier,
		"keySecretRef": obj{"name": name + "-key", "key": "apiKey"}}}
}

func secretObj(name, key string) obj {
	return obj{"metadata": obj{"name": name}, "data": obj{"apiKey": base64.StdEncoding.EncodeToString([]byte(key))}}
}

func startStore() *policy.Store {
	c, err := policy.Parse([]byte(`{"tiers":{"free":{"rate":{"limit":1,"period":"1s","burst":1}}},"anonymous":"free"}`))
	if err != nil {
		panic(err)
	}
	return policy.NewStore(c)
}

func startController(t *testing.T, c *Client, id string, leader *atomic.Bool) (*Controller, *policy.Store) {
	store := startStore()
	k := NewController(c, store, "default", id, leader.Load)
	k.Resync = 20 * time.Millisecond
	k.Usage = func(context.Context, string, int64) int64 { return 42 }
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go k.Run(ctx)
	return k, store
}

// condition returns "Status/Reason" of an object's first status condition, plus its message.
func condition(o obj) (string, string) {
	st, _ := o["status"].(obj)
	cs, _ := st["conditions"].([]any)
	if len(cs) == 0 {
		return "", ""
	}
	c := cs[0].(obj)
	return c["status"].(string) + "/" + c["reason"].(string), c["message"].(string)
}

func status(o obj, field string) float64 {
	st, _ := o["status"].(obj)
	v, _ := st[field].(float64)
	return v
}

func TestReconcileAppliesPolicyAndTenants(t *testing.T) {
	f, srv := newFake(t)
	f.seed(policiesPath, policyObj("default", 3))
	f.seed(policiesPath, policyObj("other", 1))
	f.seed(tenantsPath, tenantObj("acme", "pro"))
	var leader atomic.Bool
	leader.Store(true)
	k, store := startController(t, clientFor(srv, "a"), "a", &leader)

	waitFor(t, "policy applied", func() bool { return store.Resolve("", "/v1/generate").Cost == 3 })
	<-k.Ready()
	waitFor(t, "tenant without secret not ready", func() bool {
		c, _ := condition(f.get(tenantsPath, "acme"))
		return c == "False/SecretNotFound"
	})
	if store.Resolve("k-acme", "/").Tenant == "acme" {
		t.Fatal("tenant applied without its key")
	}

	f.seed(secretsPath, secretObj("acme-key", "k-acme"))
	waitFor(t, "tenant key applied", func() bool { return store.Resolve("k-acme", "/").Tier == "pro" })
	waitFor(t, "tenant ready with usage", func() bool {
		c, _ := condition(f.get(tenantsPath, "acme"))
		return c == "True/Active" && status(f.get(tenantsPath, "acme"), "monthlyUsed") == 42
	})
	waitFor(t, "policy status", func() bool {
		p := f.get(policiesPath, "default")
		c, msg := condition(p)
		return c == "True/Valid" && msg == "2 tiers, 1 routes, 1 tenants" && status(p, "activeReplicas") == 1
	})
	waitFor(t, "other policy ignored", func() bool {
		c, _ := condition(f.get(policiesPath, "other"))
		return c == "False/Ignored"
	})

	// Editing the CR changes limits live.
	f.seed(policiesPath, policyObj("default", 7))
	waitFor(t, "edit applied", func() bool { return store.Resolve("k-acme", "/v1/generate").Cost == 7 })
	waitFor(t, "observedGeneration 2", func() bool { return status(f.get(policiesPath, "default"), "observedGeneration") == 2 })

	// The CR is the source of truth: a swap from elsewhere (dashboard PUT) is undone on the next resync.
	if err := store.Swap(startStore().Config()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "out-of-band swap reverted", func() bool { return store.Resolve("k-acme", "/v1/generate").Cost == 7 })
	if e := f.event("PolicyApplied"); e == nil || e["involvedObject"].(obj)["name"] != "default" {
		t.Fatalf("PolicyApplied event: %v", e)
	}
}

func TestInvalidPolicyKeepsLastGood(t *testing.T) {
	f, srv := newFake(t)
	f.seed(policiesPath, policyObj("default", 3))
	var leader atomic.Bool
	leader.Store(true)
	_, store := startController(t, clientFor(srv, "a"), "a", &leader)
	waitFor(t, "policy applied", func() bool { return store.Resolve("", "/v1/generate").Cost == 3 })

	f.seed(policiesPath, policyObj("default", 50)) // cost 50 > free burst 10
	waitFor(t, "Applied=False", func() bool {
		p := f.get(policiesPath, "default")
		c, msg := condition(p)
		return c == "False/Invalid" && strings.Contains(msg, "burst 10 < max route cost 50") &&
			status(p, "observedGeneration") == 2 && status(p, "activeReplicas") == 0
	})
	if got := store.Resolve("", "/v1/generate").Cost; got != 3 {
		t.Fatalf("invalid policy replaced the live one: cost %d", got)
	}
	waitFor(t, "PolicyInvalid event", func() bool { return f.event("PolicyInvalid") != nil })
}

func TestOnlyLeaderWritesStatus(t *testing.T) {
	f, srv := newFake(t)
	f.seed(policiesPath, policyObj("default", 3))
	f.seed(tenantsPath, tenantObj("acme", "pro"))
	f.seed(secretsPath, secretObj("acme-key", "k-acme"))
	var leadA, leadB atomic.Bool
	leadA.Store(true)
	ka, storeA := startController(t, clientFor(srv, "a"), "a", &leadA)
	kb, storeB := startController(t, clientFor(srv, "b"), "b", &leadB)

	// Both replicas serve the policy; the leader reports both of them.
	waitFor(t, "both applied", func() bool {
		return storeA.Resolve("k-acme", "/").Tenant == "acme" && storeB.Resolve("k-acme", "/").Tenant == "acme"
	})
	waitFor(t, "activeReplicas 2", func() bool { return status(f.get(policiesPath, "default"), "activeReplicas") == 2 })
	// Every replica, leader or not, knows the count (it splits the fallback budget).
	waitFor(t, "both count 2 replicas", func() bool { return ka.Replicas() == 2 && kb.Replicas() == 2 })
	if n := len(f.requests("b PATCH")) + len(f.requests("b POST "+eventsPath)); n != 0 {
		t.Fatalf("follower wrote %d status patches/events", n)
	}

	// Leadership moves to b: b takes over status writing for the next edit, a stops.
	leadA.Store(false)
	leadB.Store(true)
	time.Sleep(100 * time.Millisecond) // let a pass that started while a still led finish
	aWrites := len(f.requests("a PATCH"))
	f.seed(policiesPath, policyObj("default", 9))
	waitFor(t, "new leader writes status", func() bool {
		return status(f.get(policiesPath, "default"), "observedGeneration") == 2 && len(f.requests("b PATCH")) > 0
	})
	if n := len(f.requests("a PATCH")); n != aWrites {
		t.Fatalf("old leader kept writing: %d new patches", n-aWrites)
	}
}

func TestAutopilotRules(t *testing.T) {
	f, srv := newFake(t)
	f.seed(policiesPath, policyObj("default", 3)) // stormBlocks 20, 10s, 5m
	var leader atomic.Bool
	leader.Store(true)
	got := make(chan autopilot.Rules, 10)
	store := startStore()
	k := NewController(clientFor(srv, "a"), store, "default", "a", leader.Load)
	k.Resync = 20 * time.Millisecond
	k.OnRules = func(r autopilot.Rules) { got <- r }
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go k.Run(ctx)

	next := func() autopilot.Rules {
		select {
		case r := <-got:
			return r
		case <-time.After(5 * time.Second):
			t.Fatal("no OnRules call")
		}
		return autopilot.Rules{}
	}
	if r := next(); r != autopilot.DefaultRules {
		t.Fatalf("first rules %+v", r)
	}
	p := policyObj("default", 3)
	p["spec"].(obj)["autopilot"] = obj{"stormBlocks": 4, "banFor": "1h"}
	f.seed(policiesPath, p)
	if r := next(); r != (autopilot.Rules{StormBlocks: 4, StormWindow: 10 * time.Second, BanFor: time.Hour}) {
		t.Fatalf("edited rules %+v", r)
	}

	// Rules the Pilot can't use make the policy Invalid, and the last good rules stay.
	p["spec"].(obj)["autopilot"] = obj{"stormBlocks": 4, "stormWindow": "0s"}
	f.seed(policiesPath, p)
	waitFor(t, "Applied=False", func() bool {
		c, msg := condition(f.get(policiesPath, "default"))
		return c == "False/Invalid" && strings.Contains(msg, "autopilot")
	})
	select {
	case r := <-got:
		t.Fatalf("invalid rules delivered: %+v", r)
	default:
	}
}

// A Tenant that arrives before its policy waits as PolicyNotFound, then goes live with it.
func TestTenantBeforePolicy(t *testing.T) {
	f, srv := newFake(t)
	f.seed(tenantsPath, tenantObj("acme", "pro"))
	f.seed(secretsPath, secretObj("acme-key", "k-acme"))
	var leader atomic.Bool
	leader.Store(true)
	k, store := startController(t, clientFor(srv, "a"), "a", &leader)
	<-k.Ready()
	waitFor(t, "PolicyNotFound", func() bool {
		c, _ := condition(f.get(tenantsPath, "acme"))
		return c == "False/PolicyNotFound"
	})
	if store.Resolve("k-acme", "/").Tenant == "acme" || store.Config().Anonymous != "free" {
		t.Fatal("no policy yet: the startup policy must stay")
	}
	f.seed(policiesPath, policyObj("default", 3))
	waitFor(t, "tenant live", func() bool { return store.Resolve("k-acme", "/").Tier == "pro" })
	waitFor(t, "tenant ready", func() bool {
		c, _ := condition(f.get(tenantsPath, "acme"))
		return c == "True/Active"
	})

	// Deleting the policy keeps serving the last one; Tenants say why they can't be checked.
	f.remove(policiesPath, "default")
	waitFor(t, "PolicyNotFound again", func() bool {
		c, _ := condition(f.get(tenantsPath, "acme"))
		return c == "False/PolicyNotFound"
	})
	if store.Resolve("k-acme", "/").Tier != "pro" {
		t.Fatal("deleting the CR dropped the live policy")
	}
}

// Rotating a Secret revokes the old key; deleting a Tenant revokes its key.
func TestKeyRotationAndRevocation(t *testing.T) {
	f, srv := newFake(t)
	f.seed(policiesPath, policyObj("default", 3))
	f.seed(tenantsPath, tenantObj("acme", "pro"))
	f.seed(secretsPath, secretObj("acme-key", "k-old"))
	var leader atomic.Bool
	_, store := startController(t, clientFor(srv, "a"), "a", &leader) // a follower serves keys too
	waitFor(t, "old key live", func() bool { return store.Resolve("k-old", "/").Tenant == "acme" })

	f.seed(secretsPath, secretObj("acme-key", "k-new"))
	waitFor(t, "new key live", func() bool { return store.Resolve("k-new", "/").Tenant == "acme" })
	if store.Resolve("k-old", "/").Tenant == "acme" {
		t.Fatal("old key still accepted after rotation")
	}

	f.remove(tenantsPath, "acme")
	waitFor(t, "tenant revoked", func() bool { return store.Resolve("k-new", "/").Anon })
	if n := len(f.requests("a PATCH")) + len(f.requests("a POST "+eventsPath)); n != 0 {
		t.Fatalf("follower wrote %d times", n)
	}
}

// Once status matches, resyncs and the MODIFIED events our own patches cause write nothing more.
func TestStatusSettles(t *testing.T) {
	f, srv := newFake(t)
	f.seed(policiesPath, policyObj("default", 3))
	f.seed(tenantsPath, tenantObj("acme", "pro"))
	f.seed(secretsPath, secretObj("acme-key", "k-acme"))
	var leader atomic.Bool
	leader.Store(true)
	startController(t, clientFor(srv, "a"), "a", &leader)
	waitFor(t, "converged", func() bool {
		c, _ := condition(f.get(tenantsPath, "acme"))
		p, _ := condition(f.get(policiesPath, "default"))
		return c == "True/Active" && p == "True/Valid" && status(f.get(policiesPath, "default"), "activeReplicas") == 1
	})
	time.Sleep(60 * time.Millisecond) // a pass already running when we looked can still land
	patches, events := len(f.requests("PATCH")), len(f.requests("POST "+eventsPath))
	time.Sleep(150 * time.Millisecond) // about 7 resyncs
	if p, e := len(f.requests("PATCH")), len(f.requests("POST "+eventsPath)); p != patches || e != events {
		t.Fatalf("idle controller wrote %d patches and %d events", p-patches, e-events)
	}
	if events != 1 {
		t.Fatalf("%d events for one applied generation, want 1", events)
	}
	lt := f.get(tenantsPath, "acme")["status"].(obj)["conditions"].([]any)[0].(obj)["lastTransitionTime"]
	f.seed(tenantsPath, tenantObj("acme", "pro")) // a no-op re-apply bumps generation only
	waitFor(t, "observedGeneration 2", func() bool { return status(f.get(tenantsPath, "acme"), "observedGeneration") == 2 })
	if got := f.get(tenantsPath, "acme")["status"].(obj)["conditions"].([]any)[0].(obj)["lastTransitionTime"]; got != lt {
		t.Fatalf("lastTransitionTime moved %v -> %v without a status change", lt, got)
	}
}

// Autopilot bans and quota alerts become Events, from the leader only.
func TestEventsFromLeaderOnly(t *testing.T) {
	f, srv := newFake(t)
	f.seed(policiesPath, policyObj("default", 3))
	f.seed(tenantsPath, tenantObj("acme", "pro"))
	var leader atomic.Bool
	k, _ := startController(t, clientFor(srv, "a"), "a", &leader)
	<-k.Ready()
	ctx := context.Background()
	until := time.Date(2026, 11, 10, 13, 0, 0, 0, time.UTC)
	k.Banned(ctx, "192.0.2.7", "storm", until)
	k.QuotaAlert(ctx, "acme", 800, 1000)
	if n := len(f.requests("POST " + eventsPath)); n != 0 {
		t.Fatalf("follower sent %d events", n)
	}
	leader.Store(true)
	k.Banned(ctx, "192.0.2.7", "storm", until)
	k.QuotaAlert(ctx, "acme", 800, 1000)
	k.QuotaAlert(ctx, "nobody", 1, 1) // no Tenant object to attach it to: dropped
	ban, quota := f.event("TenantBanned"), f.event("QuotaAlert")
	if ban == nil || ban["involvedObject"].(obj)["kind"] != "RateLimitPolicy" || ban["type"] != "Warning" ||
		!strings.Contains(ban["message"].(string), "192.0.2.7 banned until 2026-11-10T13:00:00Z (storm)") {
		t.Fatalf("ban event %v", ban)
	}
	if quota == nil || quota["involvedObject"].(obj)["kind"] != "Tenant" || quota["involvedObject"].(obj)["uid"] != "uid-acme" {
		t.Fatalf("quota event %v", quota)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n := map[any]int{}
	for _, e := range f.objs[eventsPath] {
		n[e["reason"]]++
	}
	if n["TenantBanned"] != 1 || n["QuotaAlert"] != 1 {
		t.Fatalf("events by reason %v", n)
	}
}
