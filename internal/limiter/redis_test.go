package limiter

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/redisx"
)

// fakeRedis answers every command with reply and records the args.
func fakeRedis(t *testing.T, reply string) (*redisx.Client, func() [][]string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var got [][]string
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer nc.Close()
				r := bufio.NewReader(nc)
				for {
					var args []string
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					n, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
					for range n {
						r.ReadString('\n') // $len
						a, _ := r.ReadString('\n')
						args = append(args, strings.TrimSuffix(a, "\r\n"))
					}
					mu.Lock()
					got = append(got, args)
					mu.Unlock()
					nc.Write([]byte(reply))
				}
			}()
		}
	}()
	c, err := redisx.Dial(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, func() [][]string { mu.Lock(); defer mu.Unlock(); return got }
}

func TestRedisAllowWire(t *testing.T) {
	c, log := fakeRedis(t, "*4\r\n:0\r\n:2\r\n:250000\r\n:1500000\r\n")
	res, err := NewRedis(c).Allow(ctx, "acme", Rate{Limit: 10, Period: time.Second, Burst: 5}, 3)
	if err != nil {
		t.Fatal(err)
	}
	want := Result{Limit: 5, Remaining: 2, RetryAfter: 250 * time.Millisecond, ResetAfter: 1500 * time.Millisecond}
	if res != want {
		t.Fatalf("%+v", res)
	}
	a := log()[0]
	if a[0] != "EVALSHA" || a[2] != "1" || a[3] != "lp:r:{acme}" || a[4] != "100000" || a[5] != "5" || a[6] != "3" {
		t.Fatalf("args %q", a)
	}
}

func TestRedisSpendWire(t *testing.T) {
	c, log := fakeRedis(t, "*2\r\n:9\r\n:0\r\n")
	used, ok, err := NewRedis(c).Spend(ctx, "acme:2026-10", 10, 2)
	if err != nil || ok || used != 9 {
		t.Fatalf("%d %v %v", used, ok, err)
	}
	if a := log()[0]; a[3] != "lp:q:{acme:2026-10}" || a[4] != "10" || a[5] != "2" {
		t.Fatalf("args %q", a)
	}
	c2, _ := fakeRedis(t, ":1\r\n")
	if _, err := NewRedis(c2).Allow(ctx, "k", Rate{Limit: 1, Period: time.Second}, 1); err == nil {
		t.Fatal("malformed reply must error")
	}
}

// Runs the real Lua: LIMITPLANE_REDIS=redis://localhost:6379 go test ./internal/limiter -run Integration
func TestRedisIntegration(t *testing.T) {
	addr := os.Getenv("LIMITPLANE_REDIS")
	if addr == "" {
		t.Skip("LIMITPLANE_REDIS not set")
	}
	c, err := redisx.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	l := NewRedis(c)
	key := "it-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	r := Rate{Limit: 1, Period: time.Minute, Burst: 3}
	for i, want := range []int64{2, 1, 0} {
		res := mustAllow(t, l, key, r, 1)
		if !res.Allowed || res.Remaining != want {
			t.Fatalf("req %d: %+v", i, res)
		}
	}
	res := mustAllow(t, l, key, r, 1)
	if res.Allowed || res.RetryAfter < 59*time.Second || res.RetryAfter > time.Minute {
		t.Fatalf("4th: %+v", res)
	}
	if ttl, _ := c.Do(ctx, "PTTL", rateKey(key)); ttl.(int64) <= 0 {
		t.Fatalf("key must expire, pttl %v", ttl)
	}
	qk := MonthKey(key, time.Now())
	if used, ok, _ := l.Spend(ctx, qk, 5, 4); !ok || used != 4 {
		t.Fatal(used, ok)
	}
	if used, ok, _ := l.Spend(ctx, qk, 5, 2); ok || used != 4 {
		t.Fatal("over limit must not spend", used, ok)
	}
}
