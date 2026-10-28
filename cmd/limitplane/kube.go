package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/autopilot"
	"github.com/iammdzaidalam/limitplane/internal/kube"
	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

// operator is --kube mode: Lease leader election plus the CRD reconcilers.
type operator struct {
	elector *kube.Elector
	ctl     *kube.Controller
	events  chan func(context.Context) // Kubernetes Events to send, off the request path
	cancel  context.CancelFunc
	done    chan struct{}
}

func newOperator(store *policy.Store, limits limiter.Meter, policyName string) (*operator, error) {
	c, err := kube.InCluster()
	if err != nil {
		return nil, err
	}
	id := os.Getenv("POD_NAME")
	if id == "" {
		id, _ = os.Hostname()
	}
	el := kube.NewElector(c, "limitplane-leader", id)
	ctl := kube.NewController(c, store, policyName, id, el.IsLeader)
	if uid := os.Getenv("POD_UID"); uid != "" {
		ctl.Owner = &kube.OwnerReference{APIVersion: "v1", Kind: "Pod", Name: id, UID: uid}
	}
	ctl.Usage = func(ctx context.Context, tenant string, _ int64) int64 {
		used, _ := limits.Used(ctx, tenant)
		return used
	}
	el.OnChange = func(bool) { ctl.Kick() } // a new leader brings status up to date at once
	log.Printf("kube: namespace %s, identity %s, policy %s", c.Namespace, id, policyName)
	return &operator{elector: el, ctl: ctl, events: make(chan func(context.Context), 64), done: make(chan struct{})}, nil
}

// start runs the operator and blocks until the caches have synced once, so the first requests
// we serve already see the CRD policy (or until a timeout, keeping the startup policy).
func (o *operator) start(ctx context.Context, pilot *autopilot.Pilot) {
	ctx, o.cancel = context.WithCancel(ctx)
	o.ctl.OnRules = func(r autopilot.Rules) {
		pilot.SetRules(r)
		log.Printf("kube: autopilot %d blocks in %s bans for %s", r.StormBlocks, r.StormWindow, r.BanFor)
	}
	go func() {
		defer close(o.done)
		o.elector.Run(ctx) // releases the Lease on the way out
	}()
	go o.ctl.Run(ctx)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case send := <-o.events:
				send(ctx)
			}
		}
	}()
	select {
	case <-o.ctl.Ready():
	case <-ctx.Done():
	case <-time.After(20 * time.Second):
		log.Print("kube: no sync after 20s, serving the startup policy until it completes")
	}
}

// stop cancels the operator and waits for the Lease release, so a successor takes over at once.
func (o *operator) stop() {
	o.cancel()
	<-o.done
}

// banned and alert are server.Config hooks. They queue a Kubernetes Event (the controller drops it
// unless this replica leads) and never block: when the queue is full the Event is dropped.
func (o *operator) banned(b autopilot.Ban) {
	o.send(func(ctx context.Context) { o.ctl.Banned(ctx, b.Client, b.Reason, b.Until) })
}

func (o *operator) alert(a autopilot.Alert) {
	o.send(func(ctx context.Context) { o.ctl.QuotaAlert(ctx, a.Tenant, a.Used, a.Limit) })
}

func (o *operator) send(f func(context.Context)) {
	select {
	case o.events <- f:
	default:
	}
}
