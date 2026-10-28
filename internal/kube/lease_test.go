package kube

import (
	"context"
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
