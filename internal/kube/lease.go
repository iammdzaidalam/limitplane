package kube

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

// Elector runs Lease-based leader election (coordination.k8s.io/v1).
//
// Every Renew interval each candidate reads the Lease. The holder renews it; anyone else takes it
// over only when it has gone unchanged for Duration by the candidate's own clock (so clock skew
// between nodes doesn't matter). Writes carry the resourceVersion that was read, so when two
// candidates race only one PUT succeeds and the other gets 409 Conflict.
type Elector struct {
	c        *Client
	name, id string
	Duration time.Duration
	Renew    time.Duration
	OnChange func(leader bool) // optional, called from Run's goroutine
	now      func() time.Time

	renewedAt  atomic.Int64 // unix nanos of our last successful write as holder; 0 when not leader
	observedRV string       // last Lease version seen, and when we first saw it
	observedAt time.Time
	was        bool
}

func NewElector(c *Client, name, id string) *Elector {
	return &Elector{c: c, name: name, id: id, Duration: 15 * time.Second, Renew: 5 * time.Second, now: time.Now}
}

// IsLeader is true while our last renewal is fresh. We give up one Renew interval before others
// may take over (Duration - Renew), so two replicas never both believe they lead.
func (e *Elector) IsLeader() bool {
	t := e.renewedAt.Load()
	return t != 0 && e.now().Sub(time.Unix(0, t)) < e.Duration-e.Renew
}

// Run campaigns until ctx ends, then releases the Lease so a successor needn't wait it out.
func (e *Elector) Run(ctx context.Context) {
	t := time.NewTicker(e.Renew)
	defer t.Stop()
	for {
		if err := e.tryAcquireOrRenew(ctx); err != nil && ctx.Err() == nil {
			log.Printf("kube: lease: %v", err)
		}
		e.notify()
		select {
		case <-ctx.Done():
			e.release()
			e.notify()
			return
		case <-t.C:
		}
	}
}

func (e *Elector) notify() {
	if now := e.IsLeader(); now != e.was {
		e.was = now
		log.Printf("kube: %s leader=%v", e.id, now)
		if e.OnChange != nil {
			e.OnChange(now)
		}
	}
}

func (e *Elector) tryAcquireOrRenew(ctx context.Context) error {
	now := e.now()
	var l Lease
	err := e.c.Get(ctx, e.c.Path(Leases, e.name), &l)
	if IsStatus(err, http.StatusNotFound) {
		l = Lease{Metadata: ObjectMeta{Name: e.name}, Spec: e.hold(LeaseSpec{}, now)}
		if err := e.c.Create(ctx, e.c.Path(Leases, ""), &l, nil); err != nil {
			return lost(err) // 409: another candidate created it first
		}
		e.renewedAt.Store(now.UnixNano())
		return nil
	}
	if err != nil {
		return err
	}
	if l.Metadata.ResourceVersion != e.observedRV {
		e.observedRV, e.observedAt = l.Metadata.ResourceVersion, now
	}
	dur := time.Duration(l.Spec.LeaseDurationSeconds) * time.Second
	switch holder := l.Spec.HolderIdentity; {
	case holder == e.id: // renew
	case holder == "" || now.Sub(e.observedAt) >= dur: // released or expired: take over
		l.Spec.LeaseTransitions++
		l.Spec.AcquireTime = MicroTime{}
	default:
		e.renewedAt.Store(0) // someone else holds a live lease
		return nil
	}
	l.Spec = e.hold(l.Spec, now)
	if err := e.c.Update(ctx, e.c.Path(Leases, e.name), &l, nil); err != nil {
		return lost(err) // IsLeader decays on its own if we can't renew
	}
	e.renewedAt.Store(now.UnixNano())
	return nil
}

// lost treats 409 Conflict as losing a race, which is normal, not an error worth logging.
func lost(err error) error {
	if IsStatus(err, http.StatusConflict) {
		return nil
	}
	return err
}

func (e *Elector) hold(s LeaseSpec, now time.Time) LeaseSpec {
	if s.AcquireTime.IsZero() {
		s.AcquireTime = MicroTime{now}
	}
	s.HolderIdentity, s.RenewTime = e.id, MicroTime{now}
	s.LeaseDurationSeconds = int(e.Duration / time.Second)
	return s
}

// release clears the holder so the next candidate takes over on its next tick.
func (e *Elector) release() {
	if !e.IsLeader() {
		return
	}
	e.renewedAt.Store(0) // stop acting as leader before anyone else can start
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var l Lease
	if err := e.c.Get(ctx, e.c.Path(Leases, e.name), &l); err != nil || l.Spec.HolderIdentity != e.id {
		return
	}
	l.Spec.HolderIdentity = ""
	if err := e.c.Update(ctx, e.c.Path(Leases, e.name), &l, nil); err != nil {
		log.Printf("kube: lease release: %v", err)
	}
}

// Replica heartbeats: each replica keeps its own small Lease that says which policy generation it
// serves. The leader counts the fresh ones for status.activeReplicas.
const (
	replicaLabel  = "limitplane.dev/replica"
	generationAnn = "limitplane.dev/policy-generation"
)

func (c *Client) beat(ctx context.Context, id string, gen int64, owner *OwnerReference, now time.Time) error {
	name := "limitplane-replica-" + id
	var l Lease
	err := c.Get(ctx, c.Path(Leases, name), &l)
	if err != nil && !IsStatus(err, http.StatusNotFound) {
		return err
	}
	create := err != nil
	if create {
		l.Metadata = ObjectMeta{Name: name, Labels: map[string]string{replicaLabel: "true"}}
		if owner != nil { // owned by the pod, so it's garbage collected with it
			l.Metadata.OwnerReferences = []OwnerReference{*owner}
		}
	}
	if l.Metadata.Annotations == nil {
		l.Metadata.Annotations = map[string]string{}
	}
	l.Metadata.Annotations[generationAnn] = strconv.FormatInt(gen, 10)
	l.Spec = LeaseSpec{HolderIdentity: id, LeaseDurationSeconds: 15, RenewTime: MicroTime{now}}
	if create {
		return c.Create(ctx, c.Path(Leases, ""), &l, nil)
	}
	return c.Update(ctx, c.Path(Leases, name), &l, nil)
}

// countReplicas counts replicas that heartbeated within maxAge and serve generation gen (any if gen < 0).
func (c *Client) countReplicas(ctx context.Context, gen int64, maxAge time.Duration, now time.Time) (int, error) {
	var l struct{ Items []Lease }
	if err := c.Get(ctx, c.Path(Leases, "")+"?labelSelector="+replicaLabel+"%3Dtrue", &l); err != nil {
		return 0, err
	}
	n := 0
	for _, x := range l.Items {
		if now.Sub(x.Spec.RenewTime.Time) < maxAge && (gen < 0 || x.Metadata.Annotations[generationAnn] == strconv.FormatInt(gen, 10)) {
			n++
		}
	}
	return n, nil
}
