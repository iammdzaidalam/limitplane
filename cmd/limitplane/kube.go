package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/autopilot"
	"github.com/iammdzaidalam/limitplane/internal/kube"
	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/policy"
	"github.com/iammdzaidalam/limitplane/internal/server"
)

// operator is --kube mode: Lease leader election plus the CRD reconcilers.
type operator struct {
	elector *kube.Elector
	ctl     *kube.Controller
	cancel  context.CancelFunc
	done    chan struct{}
}

func newOperator(store *policy.Store, quota limiter.Quota, policyName string) (*operator, error) {
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
	ctl.Usage = func(ctx context.Context, tenant string, limit int64) int64 {
		used, _, _ := quota.Spend(ctx, limiter.MonthKey(tenant, time.Now()), limit, 0) // cost 0 just reads
		return used
	}
	el.OnChange = func(bool) { ctl.Kick() } // a new leader brings status up to date at once
	log.Printf("kube: namespace %s, identity %s, policy %s", c.Namespace, id, policyName)
	return &operator{elector: el, ctl: ctl, done: make(chan struct{})}, nil
}

// start runs the operator and blocks until the caches have synced once, so the first requests
// we serve already see the CRD policy (or until a timeout, keeping the startup policy).
func (o *operator) start(ctx context.Context, hub *server.Hub) {
	ctx, o.cancel = context.WithCancel(ctx)
	go func() {
		defer close(o.done)
		o.elector.Run(ctx) // releases the Lease on the way out
	}()
	go o.ctl.Run(ctx)
	go forwardAutopilot(ctx, hub, o.ctl)
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

// forwardAutopilot reads bans and quota alerts off the dashboard's event stream and turns them
// into Kubernetes Events (the controller drops them unless this replica leads).
func forwardAutopilot(ctx context.Context, hub *server.Hub, ctl *kube.Controller) {
	ch := hub.Subscribe()
	defer hub.Unsubscribe(ch)
	for {
		var msg []byte
		select {
		case <-ctx.Done():
			return
		case msg = <-ch:
		}
		// Messages are SSE frames: "event: <name>\ndata: <json>\n\n".
		name, data, _ := strings.Cut(strings.TrimPrefix(string(msg), "event: "), "\ndata: ")
		switch name {
		case "ban":
			var b autopilot.Ban
			if json.Unmarshal([]byte(data), &b) == nil {
				ctl.Banned(ctx, b.Client, b.Reason, b.Until)
			}
		case "alert":
			var a autopilot.Alert
			if json.Unmarshal([]byte(data), &a) == nil {
				ctl.QuotaAlert(ctx, a.Tenant, a.Used, a.Limit)
			}
		}
	}
}
