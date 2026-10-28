package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/policy"
)

const apiVersion = "limitplane.dev/v1alpha1"

// Controller is the operator. Every replica watches RateLimitPolicies, Tenants and Secrets and
// hot-swaps the policy store; only the leader writes status and emits Events.
//
// Reconciling is level-triggered: any change to any watched object rebuilds the whole policy from
// the caches. With a handful of objects that is cheap, and it can't drift the way per-event deltas can.
type Controller struct {
	c          *Client
	store      *policy.Store
	policyName string // the one RateLimitPolicy that is applied
	id         string // this replica, for its heartbeat Lease
	isLeader   func() bool

	Owner  *OwnerReference                                             // our pod, so the heartbeat Lease is garbage collected; may be nil
	Usage  func(ctx context.Context, tenant string, limit int64) int64 // monthly usage for Tenant status; may be nil
	Resync time.Duration                                               // status refresh and heartbeat period

	policies *Cache[RateLimitPolicy]
	tenants  *Cache[Tenant]
	secrets  *Cache[Secret]
	kick     chan struct{}
	ready    chan struct{}

	// Owned by Run's goroutine.
	applied  int64 // generation of the policy this replica serves
	rejected int64 // last generation logged as invalid
	missing  bool
	beatGen  int64
	lastBeat time.Time
}

func NewController(c *Client, store *policy.Store, policyName, id string, isLeader func() bool) *Controller {
	k := &Controller{c: c, store: store, policyName: policyName, id: id, isLeader: isLeader,
		Resync: 5 * time.Second, kick: make(chan struct{}, 1), ready: make(chan struct{})}
	k.policies = NewCache[RateLimitPolicy](c, Policies, k.Kick)
	k.tenants = NewCache[Tenant](c, Tenants, k.Kick)
	k.secrets = NewCache[Secret](c, Secrets, k.Kick)
	return k
}

// Kick asks for a reconcile. Kicks coalesce, so a burst of watch events costs one pass.
func (k *Controller) Kick() {
	select {
	case k.kick <- struct{}{}:
	default:
	}
}

// Ready is closed after the first reconcile with every cache synced.
func (k *Controller) Ready() <-chan struct{} { return k.ready }

// Run starts the caches and reconciles on every change, and every Resync, until ctx ends.
func (k *Controller) Run(ctx context.Context) {
	go k.policies.Run(ctx)
	go k.tenants.Run(ctx)
	go k.secrets.Run(ctx)
	t := time.NewTicker(k.Resync)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-k.kick:
		case <-t.C:
		}
		k.reconcile(ctx, time.Now())
	}
}

func (k *Controller) reconcile(ctx context.Context, now time.Time) {
	if !k.policies.Synced() || !k.tenants.Synced() || !k.secrets.Synced() {
		return
	}
	pols, tenants := k.policies.Items(), k.tenants.Items()
	pol, found := pols[k.policyName]
	if found != !k.missing {
		k.missing = !found
		if !found {
			log.Printf("kube: RateLimitPolicy %q not found, keeping the current policy", k.policyName)
		}
	}

	var cfg policy.Config
	var applyErr error
	conds := map[string]Condition{}
	if found {
		cfg, conds, applyErr = build(pol, tenants, k.secrets.Items())
		// Compare with the live store, not our last write, so a dashboard PUT /api/policy is undone too:
		// in kube mode the CR is the source of truth.
		if applyErr == nil && !reflect.DeepEqual(cfg, k.store.Config()) {
			if applyErr = k.store.Swap(cfg); applyErr == nil { // the same validated atomic swap file reload uses
				log.Printf("kube: applied %s generation %d (%d tenants)", k.policyName, pol.Metadata.Generation, len(cfg.Keys))
			}
		}
		if applyErr == nil {
			k.applied = pol.Metadata.Generation
		} else if k.rejected != pol.Metadata.Generation {
			k.rejected = pol.Metadata.Generation
			log.Printf("kube: %s generation %d rejected, keeping the current policy: %s", k.policyName, k.rejected, oneLine(applyErr))
		}
	}
	for name := range tenants {
		if _, ok := conds[name]; !ok { // no usable policy to check this tenant against
			conds[name] = notReady("PolicyNotFound", "RateLimitPolicy "+k.policyName+" is missing or unreadable")
		}
	}

	select {
	case <-k.ready:
	default:
		close(k.ready)
	}
	if now.Sub(k.lastBeat) >= k.Resync || k.beatGen != k.applied {
		if err := k.c.beat(ctx, k.id, k.applied, k.Owner, now); err != nil {
			log.Printf("kube: heartbeat: %v", err)
		} else {
			k.beatGen, k.lastBeat = k.applied, now
		}
	}
	if k.isLeader() {
		k.writeStatus(ctx, pols, tenants, conds, cfg, applyErr, now)
	}
}

// build turns the policy spec plus every usable Tenant into a validated policy.Config.
// Tenants that can't be used (missing Secret, unknown tier, ...) are left out and get Ready=False,
// so one bad Tenant never blocks the policy.
func build(pol RateLimitPolicy, tenants map[string]Tenant, secrets map[string]Secret) (policy.Config, map[string]Condition, error) {
	conds := map[string]Condition{}
	var spec map[string]json.RawMessage
	if err := json.Unmarshal(pol.Spec, &spec); err != nil {
		return policy.Config{}, conds, fmt.Errorf("policy: spec: %w", err)
	}
	if spec == nil {
		spec = map[string]json.RawMessage{}
	}
	delete(spec, "autopilot") // part of the CRD, not of the policy file format (see docs/OPERATOR.md)
	var tiers map[string]json.RawMessage
	json.Unmarshal(spec["tiers"], &tiers)

	keys := map[string]policy.Tenant{}
	for _, name := range slices.Sorted(maps.Keys(tenants)) {
		t := tenants[name].Spec
		key, reason, msg := apiKey(t, tiers, secrets)
		if prev, dup := keys[key]; reason == "" && dup {
			reason, msg = "DuplicateKey", "API key already used by tenant "+prev.ID
		}
		if reason != "" {
			conds[name] = notReady(reason, msg)
			continue
		}
		keys[key] = policy.Tenant{ID: t.ID, Tier: t.Tier}
		conds[name] = Condition{Type: "Ready", Status: "True", Reason: "Active", Message: "tier " + t.Tier}
	}
	spec["keys"], _ = json.Marshal(keys)
	b, _ := json.Marshal(spec)
	cfg, err := policy.Parse(b) // the same parse + validation as the policy file
	if err != nil {
		for name, c := range conds {
			if c.Status == "True" {
				conds[name] = notReady("PolicyInvalid", "RateLimitPolicy "+pol.Metadata.Name+" is invalid")
			}
		}
	}
	return cfg, conds, err
}

func apiKey(t TenantSpec, tiers map[string]json.RawMessage, secrets map[string]Secret) (key, reason, msg string) {
	ref := t.KeySecretRef
	if t.ID == "" {
		return "", "InvalidSpec", "spec.id is empty"
	}
	if _, ok := tiers[t.Tier]; !ok {
		return "", "UnknownTier", fmt.Sprintf("tier %q is not in the RateLimitPolicy", t.Tier)
	}
	s, ok := secrets[ref.Name]
	if !ok {
		return "", "SecretNotFound", fmt.Sprintf("Secret %q not found", ref.Name)
	}
	if v := strings.TrimSpace(string(s.Data[ref.Key])); v != "" {
		return v, "", ""
	}
	return "", "KeyNotFound", fmt.Sprintf("Secret %q has no non-empty key %q", ref.Name, ref.Key)
}

func notReady(reason, msg string) Condition {
	return Condition{Type: "Ready", Status: "False", Reason: reason, Message: msg}
}

// writeStatus patches status only where it differs, so the MODIFIED events our own writes cause
// end in a no-op reconcile instead of a loop. Events go out only when a condition changes, so a
// new leader that finds status already up to date stays quiet.
func (k *Controller) writeStatus(ctx context.Context, pols map[string]RateLimitPolicy, tenants map[string]Tenant,
	conds map[string]Condition, cfg policy.Config, applyErr error, now time.Time) {
	for _, name := range slices.Sorted(maps.Keys(pols)) {
		p := pols[name]
		want := PolicyStatus{ObservedGeneration: p.Metadata.Generation}
		cond := Condition{Type: "Applied", Status: "False", Reason: "Ignored",
			Message: "only RateLimitPolicy " + k.policyName + " is applied"}
		if name == k.policyName {
			cond = Condition{Type: "Applied", Status: "True", Reason: "Valid", Message: summary(cfg)}
			if applyErr != nil {
				cond = Condition{Type: "Applied", Status: "False", Reason: "Invalid",
					Message: oneLine(applyErr)}
			}
			n, err := k.c.countReplicas(ctx, p.Metadata.Generation, 15*time.Second, now)
			if err != nil {
				log.Printf("kube: count replicas: %v", err)
				n = p.Status.ActiveReplicas
			}
			want.ActiveReplicas = n
		}
		want.Conditions = []Condition{transition(cond, p.Status.Conditions, now)}
		if reflect.DeepEqual(want, p.Status) {
			continue
		}
		if err := k.c.PatchStatus(ctx, k.c.Path(Policies, name), want); err != nil {
			log.Printf("kube: status %s: %v", name, err)
			continue
		}
		if name == k.policyName && (p.Status.ObservedGeneration != want.ObservedGeneration || changed(cond, p.Status.Conditions)) {
			reason, typ := "PolicyApplied", "Normal"
			if applyErr != nil {
				reason, typ = "PolicyInvalid", "Warning"
			}
			msg := fmt.Sprintf("generation %d: %s", p.Metadata.Generation, cond.Message)
			k.event(ctx, policyRef(p.Metadata), typ, reason, msg)
		}
	}

	live := k.store.Config()
	for _, name := range slices.Sorted(maps.Keys(tenants)) {
		t := tenants[name]
		cond := conds[name]
		want := TenantStatus{ObservedGeneration: t.Metadata.Generation, Conditions: []Condition{transition(cond, t.Status.Conditions, now)}}
		if lim := live.Tiers[t.Spec.Tier].Monthly; cond.Status == "True" && lim > 0 && k.Usage != nil {
			want.MonthlyUsed = k.Usage(ctx, t.Spec.ID, lim)
		}
		if reflect.DeepEqual(want, t.Status) {
			continue
		}
		if err := k.c.PatchStatus(ctx, k.c.Path(Tenants, name), want); err != nil {
			log.Printf("kube: status tenant %s: %v", name, err)
		}
	}
}

// oneLine joins the lines of a multi-error (errors.Join) for logs and condition messages.
func oneLine(err error) string { return strings.ReplaceAll(err.Error(), "\n", "; ") }

func summary(c policy.Config) string {
	return fmt.Sprintf("%d tiers, %d routes, %d tenants", len(c.Tiers), len(c.Routes), len(c.Keys))
}

// transition keeps lastTransitionTime unless the condition's status flips.
func transition(c Condition, old []Condition, now time.Time) Condition {
	c.LastTransitionTime = now.UTC().Format(time.RFC3339)
	for _, o := range old {
		if o.Type == c.Type && o.Status == c.Status {
			c.LastTransitionTime = o.LastTransitionTime
		}
	}
	return c
}

func changed(c Condition, old []Condition) bool {
	for _, o := range old {
		if o.Type == c.Type {
			return o.Status != c.Status || o.Reason != c.Reason || o.Message != c.Message
		}
	}
	return true
}

func policyRef(m ObjectMeta) Ref {
	return Ref{APIVersion: apiVersion, Kind: "RateLimitPolicy", Name: m.Name, Namespace: m.Namespace, UID: m.UID}
}

func (k *Controller) event(ctx context.Context, about Ref, typ, reason, msg string) {
	if !k.isLeader() {
		return
	}
	if err := k.c.Event(ctx, about, typ, reason, msg); err != nil {
		log.Printf("kube: event %s: %v", reason, err)
	}
}

// Banned reports an autopilot ban as a TenantBanned Event on the applied policy.
// Bans are per client address, so the Event can't name a Tenant object. Safe from any goroutine.
func (k *Controller) Banned(ctx context.Context, client, reason string, until time.Time) {
	if p, ok := k.policies.Get(k.policyName); ok {
		k.event(ctx, policyRef(p.Metadata), "Warning", "TenantBanned",
			fmt.Sprintf("client %s banned until %s (%s)", client, until.UTC().Format(time.RFC3339), reason))
	}
}

// QuotaAlert reports a tenant crossing 80% of its monthly quota as an Event on its Tenant.
func (k *Controller) QuotaAlert(ctx context.Context, tenant string, used, limit int64) {
	for _, t := range k.tenants.Items() {
		if t.Spec.ID == tenant {
			ref := Ref{APIVersion: apiVersion, Kind: "Tenant", Name: t.Metadata.Name, Namespace: t.Metadata.Namespace, UID: t.Metadata.UID}
			k.event(ctx, ref, "Warning", "QuotaAlert", fmt.Sprintf("tenant %s used %d of %d monthly units", tenant, used, limit))
			return
		}
	}
}
