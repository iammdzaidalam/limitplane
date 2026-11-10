package kube

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// scripted serves one list and then one watch stream of the given lines, and records the watch query.
func scripted(t *testing.T, stream string) (*Client, <-chan url.Values) {
	queries := make(chan url.Values, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") == "1" {
			queries <- r.URL.Query()
			io.WriteString(w, stream)
			return
		}
		io.WriteString(w, `{"metadata":{"resourceVersion":"10"},"items":[
			{"metadata":{"name":"a","resourceVersion":"8"}},{"metadata":{"name":"b","resourceVersion":"9"}}]}`)
	}))
	t.Cleanup(srv.Close)
	return &Client{Base: srv.URL, Namespace: "ns", HTTP: srv.Client()}, queries
}

func TestWatchEvents(t *testing.T) {
	c, queries := scripted(t, `{"type":"ADDED","object":{"metadata":{"name":"c","resourceVersion":"11"}}}
{"type":"MODIFIED","object":{"metadata":{"name":"a","resourceVersion":"12","generation":2}}}
{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"20"}}}
{"type":"DELETED","object":{"metadata":{"name":"b","resourceVersion":"21"}}}
{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"30"}}}
`)
	changes := 0
	k := NewCache[RateLimitPolicy](c, Policies, func() { changes++ })
	ctx := context.Background()
	if err := k.list(ctx); err != nil || changes != 1 || k.rv != "10" || !k.Synced() {
		t.Fatalf("list: %v, %d changes, rv %s", err, changes, k.rv)
	}
	if err := k.watch(ctx); err != nil { // the stream ending is a normal close
		t.Fatal(err)
	}
	q := <-queries
	if q.Get("resourceVersion") != "10" || q.Get("allowWatchBookmarks") != "true" || q.Get("timeoutSeconds") == "" {
		t.Fatalf("watch query %v", q)
	}
	// Bookmarks move the cursor without a reconcile; the three real events each cause one.
	if changes != 4 || k.rv != "30" {
		t.Fatalf("%d changes, rv %s", changes, k.rv)
	}
	items := k.Items()
	if len(items) != 2 || items["a"].Metadata.Generation != 2 {
		t.Fatalf("items %v", items)
	}
	if _, ok := k.Get("b"); ok {
		t.Fatal("deleted object still cached")
	}
	items["zzz"] = RateLimitPolicy{} // Items is a copy
	if _, ok := k.Get("zzz"); ok {
		t.Fatal("Items shares the cache's map")
	}
}

func TestWatchErrors(t *testing.T) {
	for stream, check := range map[string]func(error) bool{
		`{"type":"ERROR","object":{"kind":"Status","code":410,"message":"too old"}}`: func(err error) bool { return errors.Is(err, errGone) },
		`{"type":"ERROR","object":{"kind":"Status","code":500,"message":"etcd"}}`:    func(err error) bool { return IsStatus(err, 500) },
		`{"type":"ADDED","object":{"metadata":`:                                      func(err error) bool { return err != nil && !errors.Is(err, errGone) },
		`{"type":"ADDED","object":{"metadata":{"name":7}}}`:                          func(err error) bool { return err != nil },
	} {
		c, _ := scripted(t, stream)
		k := NewCache[RateLimitPolicy](c, Policies, func() {})
		k.rv = "10"
		if err := k.watch(context.Background()); !check(err) {
			t.Errorf("%s: %v", stream, err)
		}
	}
}
