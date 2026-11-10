package kube

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"
)

const leasesPath = "/apis/coordination.k8s.io/v1/namespaces/ns/leases"

func TestLeaseAcquireRenewTakeover(t *testing.T) {
	f, srv := newFake(t)
	ctx := context.Background()
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	a := NewElector(clientFor(srv, "a"), "limitplane-leader", "a")
	b := NewElector(clientFor(srv, "b"), "limitplane-leader", "b")
	a.now, b.now = clock, clock
	step := func(e *Elector) {
		t.Helper()
		if err := e.tryAcquireOrRenew(ctx); err != nil {
			t.Fatal(err)
		}
	}
	holder := func() string {
		h, _ := f.get(leasesPath, "limitplane-leader")["spec"].(obj)["holderIdentity"].(string)
		return h
	}

	step(a) // creates the lease
	step(b)
	if !a.IsLeader() || b.IsLeader() || holder() != "a" {
		t.Fatalf("acquire: a=%v b=%v holder=%s", a.IsLeader(), b.IsLeader(), holder())
	}

	// a renews on time; b keeps seeing a fresh lease and never takes over.
	for range 6 {
		now = now.Add(5 * time.Second)
		step(a)
		step(b)
	}
	if !a.IsLeader() || b.IsLeader() {
		t.Fatal("renew: leadership moved while the holder kept renewing")
	}

	// a stops renewing. a gives up after Duration-Renew; b takes over once the lease has been
	// unchanged for Duration by b's clock, never before.
	lastRenew := now
	for now.Sub(lastRenew) < 15*time.Second {
		if b.IsLeader() {
			t.Fatalf("b took over %v after the last renew", now.Sub(lastRenew))
		}
		now = now.Add(5 * time.Second)
		step(b)
		if now.Sub(lastRenew) >= 10*time.Second && a.IsLeader() {
			t.Fatal("a still claims leadership after its renew deadline")
		}
	}
	if !b.IsLeader() || holder() != "b" {
		t.Fatalf("takeover failed: b=%v holder=%s", b.IsLeader(), holder())
	}
	if n := f.get(leasesPath, "limitplane-leader")["spec"].(obj)["leaseTransitions"].(float64); n != 1 {
		t.Fatalf("leaseTransitions = %v", n)
	}
	step(a) // a comes back and sees b's live lease
	if a.IsLeader() {
		t.Fatal("a reclaimed a live lease")
	}

	// A clean shutdown releases the lease, so a takes over on its next tick without waiting.
	b.release()
	step(a)
	if !a.IsLeader() || b.IsLeader() {
		t.Fatalf("release: a=%v b=%v", a.IsLeader(), b.IsLeader())
	}
}

func TestLeaseRaceHasOneWinner(t *testing.T) {
	for range 20 {
		_, srv := newFake(t)
		var es []*Elector
		for _, id := range []string{"a", "b", "c"} {
			es = append(es, NewElector(clientFor(srv, id), "limitplane-leader", id))
		}
		var wg sync.WaitGroup
		for _, e := range es {
			wg.Go(func() { e.tryAcquireOrRenew(context.Background()) })
		}
		wg.Wait()
		n := 0
		for _, e := range es {
			if e.IsLeader() {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("%d leaders after a creation race", n)
		}
	}
}

func leaseSpec(f *fakeAPI) obj { return f.get(leasesPath, "limitplane-leader")["spec"].(obj) }

func TestLeaseRenewKeepsAcquireTime(t *testing.T) {
	f, srv := newFake(t)
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	a := NewElector(clientFor(srv, "a"), "limitplane-leader", "a")
	a.now = func() time.Time { return now }
	ctx := context.Background()
	a.tryAcquireOrRenew(ctx)
	now = now.Add(5 * time.Second)
	if err := a.tryAcquireOrRenew(ctx); err != nil || !a.IsLeader() {
		t.Fatalf("renew: %v", err)
	}
	s := leaseSpec(f)
	if s["acquireTime"] != "2026-11-10T12:00:00.000000Z" || s["renewTime"] != "2026-11-10T12:00:05.000000Z" ||
		s["leaseTransitions"] != nil || s["leaseDurationSeconds"] != 15.0 {
		t.Fatalf("lease after renew %v", s)
	}
}

// Two candidates read the same expired lease; the slower PUT carries a stale resourceVersion,
// gets 409 and quietly loses.
func TestLeaseTakeoverLostRace(t *testing.T) {
	f, srv := newFake(t)
	ctx := context.Background()
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	old := NewElector(clientFor(srv, "old"), "limitplane-leader", "old")
	a := NewElector(clientFor(srv, "a"), "limitplane-leader", "a")
	b := NewElector(clientFor(srv, "b"), "limitplane-leader", "b")
	old.now, a.now, b.now = clock, clock, clock
	old.tryAcquireOrRenew(ctx)
	a.tryAcquireOrRenew(ctx) // both start watching the lease's version
	b.tryAcquireOrRenew(ctx)
	now = now.Add(20 * time.Second) // old is gone

	var once sync.Once
	f.intercept(func(r *http.Request) int {
		if r.Method == http.MethodPut && r.Header.Get("Authorization") == "Bearer b" {
			once.Do(func() { // a wins the race between b's GET and b's PUT
				if err := a.tryAcquireOrRenew(ctx); err != nil {
					t.Error(err)
				}
			})
		}
		return 0
	})
	if err := b.tryAcquireOrRenew(ctx); err != nil {
		t.Fatalf("a lost race must not be an error: %v", err)
	}
	if !a.IsLeader() || b.IsLeader() || leaseSpec(f)["holderIdentity"] != "a" {
		t.Fatalf("a=%v b=%v holder=%v", a.IsLeader(), b.IsLeader(), leaseSpec(f)["holderIdentity"])
	}
	if len(f.requests("b PUT")) != 1 || leaseSpec(f)["leaseTransitions"] != 1.0 {
		t.Fatalf("b PUTs %d, transitions %v", len(f.requests("b PUT")), leaseSpec(f)["leaseTransitions"])
	}
}

// RBAC missing for Leases: errors are reported, and a leader that can't renew steps down on its own
// one Renew interval before anyone else may take over.
func TestLeaseForbidden(t *testing.T) {
	f, srv := newFake(t)
	ctx := context.Background()
	now := time.Unix(1_000_000, 0)
	a := NewElector(clientFor(srv, "a"), "limitplane-leader", "a")
	a.now = func() time.Time { return now }
	a.tryAcquireOrRenew(ctx)
	f.intercept(func(*http.Request) int { return http.StatusForbidden })
	for range 2 {
		now = now.Add(5 * time.Second)
		if err := a.tryAcquireOrRenew(ctx); !IsStatus(err, http.StatusForbidden) {
			t.Fatalf("want 403, got %v", err)
		}
	}
	if a.IsLeader() {
		t.Fatal("still leader 10s after the last renew (Duration 15s - Renew 5s)")
	}
	c := NewElector(clientFor(srv, "c"), "limitplane-leader", "c")
	if err := c.tryAcquireOrRenew(ctx); !IsStatus(err, http.StatusForbidden) || c.IsLeader() {
		t.Fatalf("a create that is forbidden: %v", err)
	}
}

// Takeover waits for the holder's own leaseDurationSeconds, not ours.
func TestLeaseHonoursHolderDuration(t *testing.T) {
	f, srv := newFake(t)
	ctx := context.Background()
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	slow := NewElector(clientFor(srv, "slow"), "limitplane-leader", "slow")
	slow.Duration, slow.now = time.Minute, clock
	b := NewElector(clientFor(srv, "b"), "limitplane-leader", "b")
	b.now = clock
	slow.tryAcquireOrRenew(ctx)
	for range 12 { // up to 55s of silence: past our 15s, inside the holder's 60s
		b.tryAcquireOrRenew(ctx)
		now = now.Add(5 * time.Second)
	}
	if b.IsLeader() || leaseSpec(f)["holderIdentity"] != "slow" {
		t.Fatal("took over inside the holder's lease duration")
	}
	b.tryAcquireOrRenew(ctx) // 60s
	if !b.IsLeader() {
		t.Fatal("no takeover after the holder's duration")
	}
}

func TestReleaseOnlyOwnLease(t *testing.T) {
	f, srv := newFake(t)
	ctx := context.Background()
	a := NewElector(clientFor(srv, "a"), "limitplane-leader", "a")
	b := NewElector(clientFor(srv, "b"), "limitplane-leader", "b")
	a.tryAcquireOrRenew(ctx)
	b.tryAcquireOrRenew(ctx)
	b.release() // not the leader: nothing to send
	if n := len(f.requests("b PUT")); n != 0 {
		t.Fatalf("non-leader release sent %d PUTs", n)
	}
	// a still thinks it leads, but the lease moved meanwhile (a was paused): leave it alone.
	f.mu.Lock()
	f.objs[leasesPath]["limitplane-leader"]["spec"].(obj)["holderIdentity"] = "b"
	f.mu.Unlock()
	a.release()
	if n := len(f.requests("a PUT")); n != 0 || leaseSpec(f)["holderIdentity"] != "b" {
		t.Fatalf("release overwrote someone else's lease (%d PUTs)", n)
	}
	if a.IsLeader() {
		t.Fatal("release must stop acting as leader first")
	}
}

// Run: OnChange(true) on acquiring, and on shutdown a release plus OnChange(false).
func TestElectorRun(t *testing.T) {
	f, srv := newFake(t)
	e := NewElector(clientFor(srv, "a"), "limitplane-leader", "a")
	e.Renew = 10 * time.Millisecond
	changes := make(chan bool, 4)
	e.OnChange = func(l bool) { changes <- l }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()
	if l := <-changes; !l {
		t.Fatal("first change must be to leader")
	}
	waitFor(t, "a few renewals", func() bool { return len(f.requests("a PUT")) >= 3 })
	cancel()
	<-done
	if l := <-changes; l {
		t.Fatal("shutdown must report loss of leadership")
	}
	if h, _ := leaseSpec(f)["holderIdentity"].(string); h != "" {
		t.Fatalf("lease still held by %q after shutdown", h)
	}
	select {
	case l := <-changes:
		t.Fatalf("extra change %v", l)
	default:
	}
}

// Replica heartbeats: one small Lease per replica, counted while fresh, per policy generation.
func TestHeartbeats(t *testing.T) {
	f, srv := newFake(t)
	ctx := context.Background()
	c := clientFor(srv, "")
	now := time.Unix(1_000_000, 0)
	owner := &OwnerReference{APIVersion: "v1", Kind: "Pod", Name: "gw-0", UID: "pod-uid"}
	if err := c.beat(ctx, "gw-0", 3, owner, now); err != nil {
		t.Fatal(err)
	}
	if err := c.beat(ctx, "gw-0", 4, owner, now); err != nil { // update in place
		t.Fatal(err)
	}
	c.beat(ctx, "gw-1", 4, nil, now.Add(-20*time.Second)) // stale
	c.beat(ctx, "gw-2", 3, nil, now)                      // behind on the policy
	l := f.get(leasesPath, "limitplane-replica-gw-0")
	m := meta(l)
	if m["labels"].(obj)[replicaLabel] != "true" || m["annotations"].(obj)[generationAnn] != "4" ||
		m["ownerReferences"].([]any)[0].(obj)["uid"] != "pod-uid" || l["spec"].(obj)["holderIdentity"] != "gw-0" {
		t.Fatalf("heartbeat lease %v", l)
	}
	f.seed(leasesPath, obj{"metadata": obj{"name": "limitplane-leader"}, "spec": obj{"holderIdentity": "gw-0",
		"renewTime": MicroTime{now}.UTC().Format("2006-01-02T15:04:05.000000Z")}}) // not a heartbeat: no label
	for gen, want := range map[int64]int{-1: 2, 4: 1, 3: 1, 9: 0} {
		if n, err := c.countReplicas(ctx, gen, 15*time.Second, now); err != nil || n != want {
			t.Errorf("gen %d: %d %v, want %d", gen, n, err, want)
		}
	}
}
