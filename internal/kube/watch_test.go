package kube

import (
	"context"
	"strings"
	"testing"
)

const policiesPath = "/apis/limitplane.dev/v1alpha1/namespaces/ns/ratelimitpolicies"

func named(name string) obj { return obj{"metadata": obj{"name": name}, "spec": obj{}} }

func TestCacheResumesAndRelists(t *testing.T) {
	f, srv := newFake(t)
	f.seed(policiesPath, named("a"))
	k := NewCache[RateLimitPolicy](clientFor(srv, ""), Policies, func() {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go k.Run(ctx)

	has := func(names ...string) func() bool {
		return func() bool {
			items := k.Items()
			for _, n := range names {
				if _, ok := items[n]; !ok {
					return false
				}
			}
			return len(items) == len(names)
		}
	}
	waitFor(t, "initial list", has("a"))
	f.seed(policiesPath, named("b"))
	waitFor(t, "watch event", has("a", "b"))
	lists := func() int { return len(f.requests("GET "+policiesPath+"?")) - len(f.requests("watch=1")) }

	// A dropped stream resumes from the last version seen: no relist, and changes made
	// while disconnected are replayed.
	f.dropWatches()
	f.seed(policiesPath, named("c"))
	waitFor(t, "resumed watch", has("a", "b", "c"))
	if n := lists(); n != 1 {
		t.Fatalf("resume relisted: %d lists", n)
	}
	watches := f.requests("watch=1")
	if last := watches[len(watches)-1]; !strings.Contains(last, "resourceVersion=2") { // b was the last version seen
		t.Fatalf("resumed from the wrong version: %s", last)
	}

	// 410 Gone as an HTTP status: relist, and the relist drops objects deleted meanwhile.
	f.expire(policiesPath, "a")
	waitFor(t, "relist after HTTP 410", func() bool { return lists() == 2 && has("b", "c")() })

	// 410 Gone as an ERROR event inside the stream.
	waitFor(t, "watch open", func() bool { f.mu.Lock(); defer f.mu.Unlock(); return len(f.watchers) == 1 })
	f.sendGone()
	waitFor(t, "relist after ERROR 410", func() bool { return lists() == 3 })
}
