package limiter

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/redisx"
)

// clusterView is CLUSTER NODES: master id -> address, slot -> owner id.
type clusterView struct {
	addr  map[string]string
	owner [16384]string
}

func viewCluster(t *testing.T, admin *redisx.Client) *clusterView {
	v, err := admin.Do(ctx, "CLUSTER", "NODES")
	if err != nil {
		t.Fatal(err)
	}
	cv := &clusterView{addr: map[string]string{}}
	for _, line := range strings.Split(strings.TrimSpace(v.(string)), "\n") {
		f := strings.Fields(line)
		if len(f) < 8 || !strings.Contains(f[2], "master") {
			continue
		}
		cv.addr[f[0]], _, _ = strings.Cut(f[1], "@")
		for _, r := range f[8:] {
			if strings.HasPrefix(r, "[") { // a migration in progress
				continue
			}
			lo, hi, ok := strings.Cut(r, "-")
			if !ok {
				hi = lo
			}
			a, _ := strconv.Atoi(lo)
			b, _ := strconv.Atoi(hi)
			for s := a; s <= b; s++ {
				cv.owner[s] = f[0]
			}
		}
	}
	return cv
}

func other(cv *clusterView, id string) string {
	for o := range cv.addr {
		if o != id {
			return o
		}
	}
	return ""
}

// Runs against a real Cluster (docker-compose.cluster.yml):
//
//	LIMITPLANE_REDIS_CLUSTER=redis+cluster://10.207.7.11:6379,10.207.7.12:6379 go test ./internal/limiter -run Cluster
//
// Tenants spread over every master, and live resharding exercises MOVED, ASK and TRYAGAIN.
func TestRedisClusterIntegration(t *testing.T) {
	addr := os.Getenv("LIMITPLANE_REDIS_CLUSTER")
	if addr == "" {
		t.Skip("LIMITPLANE_REDIS_CLUSTER not set")
	}
	seeds := strings.Split(strings.TrimPrefix(addr, "redis+cluster://"), ",")
	cv := viewCluster(t, dialRedis(t, seeds[0]))
	node := map[string]*redisx.Client{}
	for id, a := range cv.addr {
		node[id] = dialRedis(t, a)
	}
	do := func(id string, args ...any) any {
		t.Helper()
		v, err := node[id].Do(ctx, args...)
		if err != nil {
			t.Fatalf("%s %v: %v", cv.addr[id], args, err)
		}
		return v
	}
	begin := func(slot int, src, dst string) {
		do(dst, "CLUSTER", "SETSLOT", slot, "IMPORTING", src)
		do(src, "CLUSTER", "SETSLOT", slot, "MIGRATING", dst)
	}
	finish := func(slot int, src, dst string) { // target, then source, then the rest
		do(dst, "CLUSTER", "SETSLOT", slot, "NODE", dst)
		do(src, "CLUSTER", "SETSLOT", slot, "NODE", dst)
		for id := range cv.addr {
			if id != src && id != dst {
				do(id, "CLUSTER", "SETSLOT", slot, "NODE", dst)
			}
		}
	}
	count := func(id string, slot int) int64 { return do(id, "CLUSTER", "COUNTKEYSINSLOT", slot).(int64) }

	c := dialRedis(t, addr)
	l := NewRedis(c, nil)

	// Every master gets tenants, and the two-key script never hits CROSSSLOT.
	owners := map[string]int{}
	for i := range 300 {
		key := uniq("t" + strconv.Itoa(i) + "-")
		if res := mustCheck(t, l, Request{Key: key, Rate: Rate{Limit: 1, Period: time.Minute, Burst: 2}, Cost: 1, Month: 10}); !res.Allowed || res.Used != 1 {
			t.Fatalf("%s: %+v", key, res)
		}
		owners[cv.owner[redisx.Slot(tag(key))]]++
	}
	if len(owners) != len(cv.addr) || len(owners) < 3 {
		t.Fatalf("tenants per master %v", owners)
	}

	// MOVED: move a live tenant's slot, keys and all, to another master between two requests.
	q := Request{Key: uniq("mv-"), Rate: Rate{Limit: 1, Period: time.Hour, Burst: 5}, Cost: 1, Month: 100}
	for range 3 {
		mustCheck(t, l, q)
	}
	slot := redisx.Slot(tag(q.Key))
	src := cv.owner[slot]
	dst := other(cv, src)
	begin(slot, src, dst)
	keys := do(src, "CLUSTER", "GETKEYSINSLOT", slot, 1000).([]any)
	h, p, _ := strings.Cut(cv.addr[dst], ":")
	do(src, append([]any{"MIGRATE", h, p, "", 0, 5000, "KEYS"}, keys...)...)
	finish(slot, src, dst)
	if res := mustCheck(t, l, q); !res.Allowed || res.Remaining != 1 || res.Used != 4 {
		t.Fatalf("after MOVED, state must carry over: %+v", res)
	}
	if count(dst, slot) < 2 || count(src, slot) != 0 {
		t.Fatalf("slot %d: src %d keys, dst %d", slot, count(src, slot), count(dst, slot))
	}

	// ASK: a fresh tenant in a slot that is mid-migration. Single-key commands follow ASK to the
	// importing node; the two-key script gets TRYAGAIN there (Redis won't run a multi-key command
	// on an importing slot until all its keys exist), which redisx reports as ErrNodeDown.
	var key2 string
	for i := 0; ; i++ {
		key2 = uniq("ask" + strconv.Itoa(i) + "-")
		if s := redisx.Slot(tag(key2)); count(cv.owner[s], s) == 0 {
			break
		}
	}
	slot2 := redisx.Slot(tag(key2))
	src2 := cv.owner[slot2]
	dst2 := other(cv, src2)
	begin(slot2, src2, dst2)
	if _, err := c.Do(ctx, "SET", tag(key2)+"x", "1", "PX", 60000); err != nil {
		t.Fatalf("SET via ASK: %v", err)
	}
	if n, err := l.Used(ctx, key2); err != nil || n != 0 {
		t.Fatalf("Used via ASK: %d %v", n, err)
	}
	if count(dst2, slot2) != 1 || count(src2, slot2) != 0 {
		t.Fatalf("ASK must write to the importing node: src %d dst %d", count(src2, slot2), count(dst2, slot2))
	}
	q2 := Request{Key: key2, Rate: Rate{Limit: 1, Period: time.Hour, Burst: 5}, Cost: 1, Month: 100}
	if _, err := l.Check(ctx, q2); !errors.Is(err, redisx.ErrNodeDown) || !strings.Contains(err.Error(), "TRYAGAIN") {
		t.Fatalf("want TRYAGAIN as ErrNodeDown, got %v", err)
	}
	// Behind the fallback that request degrades alone: the breaker stays closed for everyone else.
	fb := NewFallback(l, NewMemory(), nil)
	if res, err := fb.Check(ctx, q2); err != nil || !res.Degraded || !res.Allowed {
		t.Fatalf("migrating tenant: %+v %v", res, err)
	}
	if res, err := fb.Check(ctx, q); err != nil || res.Degraded {
		t.Fatalf("other tenant must stay shared: %+v %v", res, err)
	}
	finish(slot2, src2, dst2)
	if res := mustCheck(t, l, q2); !res.Allowed || res.Used != 1 {
		t.Fatalf("after migration: %+v", res)
	}
}
