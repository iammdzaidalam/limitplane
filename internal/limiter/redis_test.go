package limiter

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/redisx"
)

// fakeRedisFunc answers each command with handle(args) and records the args.
func fakeRedisFunc(t *testing.T, handle func(args []string) string) (*redisx.Client, func() [][]string) {
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
					args, err := readCommand(r)
					if err != nil {
						return
					}
					mu.Lock()
					got = append(got, args)
					mu.Unlock()
					nc.Write([]byte(handle(args)))
				}
			}()
		}
	}()
	c, err := redisx.Dial(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, func() [][]string { mu.Lock(); defer mu.Unlock(); return slices.Clone(got) }
}

func fakeRedis(t *testing.T, reply string) (*redisx.Client, func() [][]string) {
	return fakeRedisFunc(t, func([]string) string { return reply })
}

// readCommand reads one RESP command array.
func readCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	n, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
	args := make([]string, 0, n)
	for range n {
		hdr, err := r.ReadString('\n') // $len
		if err != nil {
			return nil, err
		}
		size, _ := strconv.Atoi(strings.TrimSpace(hdr[1:]))
		b := make([]byte, size+2) // bulk strings may hold newlines (EVAL's script)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		args = append(args, string(b[:size]))
	}
	return args, nil
}

func bulk(s string) string { return fmt.Sprintf("$%d\r\n%s\r\n", len(s), s) }

func TestRedisCheckWire(t *testing.T) {
	c, log := fakeRedis(t, "*5\r\n:2\r\n:2\r\n:250000\r\n:1500000\r\n:7\r\n")
	l := NewRedis(c, nil)
	res, err := l.Check(ctx, Request{Client: "192.0.2.1", Key: "acme", Rate: Rate{Limit: 10, Period: time.Second, Burst: 5}, Cost: 3, Month: 100})
	if err != nil {
		t.Fatal(err)
	}
	want := Result{Reason: Burst, Limit: 5, Remaining: 2, RetryAfter: 250 * time.Millisecond, ResetAfter: 1500 * time.Millisecond, Used: 7}
	if res != want {
		t.Fatalf("%+v", res)
	}
	// One command per request, touching only the tenant's keys, which share the {acme} hash tag.
	if l := log(); len(l) != 1 {
		t.Fatalf("%d commands, want 1", len(l))
	}
	a := log()[0]
	if a[0] != "EVALSHA" || a[2] != "2" || a[3] != "lp:{acme}:r" || a[4] != "lp:{acme}:q:" ||
		a[5] != "100000" || a[6] != "5" || a[7] != "3" || a[8] != "100" {
		t.Fatalf("args %q", a)
	}
	if redisx.Slot(a[3]) != redisx.Slot(a[4]) {
		t.Fatal("tenant keys must share a Cluster slot")
	}
	// A banned client (here a CIDR) is answered in process: no Redis command at all.
	l.bans.set(Ban{Client: "192.0.2.0/24", Until: time.Now().Add(time.Minute)})
	if res := mustCheck(t, l, Request{Client: "192.0.2.1", Key: "acme", Rate: Rate{Limit: 1, Period: time.Second}, Cost: 1}); res.Reason != Banned {
		t.Fatalf("%+v", res)
	}
	if n := len(log()); n != 1 {
		t.Fatalf("banned check sent %d commands", n-1)
	}
	c2, _ := fakeRedis(t, ":1\r\n")
	if _, err := NewRedis(c2, nil).Allow(ctx, "k", Rate{Limit: 1, Period: time.Second}, 1); err == nil {
		t.Fatal("malformed reply must error")
	}
}

// fakeBanStore emulates the three ban scripts over the wire and can be taken down.
type fakeBanStore struct {
	mu   sync.Mutex
	m    map[string]string // client -> "ttl reason"
	down atomic.Bool
}

func (f *fakeBanStore) handle(args []string) string {
	if f.down.Load() {
		return "-LOADING Redis is loading the dataset in memory\r\n"
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case args[0] == "EVALSHA":
		return "-NOSCRIPT No matching script\r\n"
	case args[0] != "EVAL":
		return "-ERR unexpected\r\n"
	case strings.Contains(args[1], "HGETALL"):
		out := fmt.Sprintf("*%d\r\n", 3*len(f.m))
		for c, v := range f.m {
			ttl, reason, _ := strings.Cut(v, " ")
			out += bulk(c) + ":" + ttl + "\r\n" + bulk(reason)
		}
		return out
	case strings.Contains(args[1], "HSET"):
		f.m[args[4]] = args[5] + " " + args[6]
	case strings.Contains(args[1], "HDEL"):
		delete(f.m, args[4])
	}
	return ":1\r\n"
}

// Bans and unbans made while Redis is down are pushed, with their remaining TTL, before the next sync.
func TestRedisOutagePush(t *testing.T) {
	f := &fakeBanStore{m: map[string]string{"192.0.2.99": "60000 manual"}}
	c, log := fakeRedisFunc(t, f.handle)
	mem := NewMemory()
	red := NewRedis(c, mem.BanList)
	fb := NewFallback(red, mem, nil)
	if _, err := red.Bans(ctx); err != nil {
		t.Fatal(err)
	}

	f.down.Store(true)
	if err := fb.Ban(ctx, Ban{Client: "198.51.100.7", Until: time.Now().Add(time.Minute), Reason: "storm"}); err != nil {
		t.Fatal(err)
	}
	if err := fb.Unban(ctx, "192.0.2.99"); err != nil {
		t.Fatal(err)
	}
	mem.Ban(ctx, Ban{Client: "198.51.100.8", Until: time.Now().Add(5 * time.Millisecond)}) // expires before recovery
	if _, ok := mem.Banned("198.51.100.7", time.Now()); !ok {
		t.Fatal("degraded ban must apply locally")
	}
	if _, err := red.Bans(ctx); err == nil {
		t.Fatal("sync must fail while down")
	}
	time.Sleep(10 * time.Millisecond)

	f.down.Store(false)
	bans, err := red.Bans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	v, ok := f.m["198.51.100.7"]
	_, unbanned := f.m["192.0.2.99"]
	_, expired := f.m["198.51.100.8"]
	f.mu.Unlock()
	ttl, _ := strconv.Atoi(strings.Fields(v + " 0")[0])
	if !ok || !strings.HasSuffix(v, " storm") || ttl < 59000 || ttl > 60000 || unbanned || expired {
		t.Fatalf("redis after recovery: %v (ttl %d), 192.0.2.99 kept %v, expired pushed %v", f.m, ttl, unbanned, expired)
	}
	if len(bans) != 1 || bans[0].Client != "198.51.100.7" {
		t.Fatalf("bans %+v", bans)
	}
	if _, ok := mem.Banned("198.51.100.7", time.Now()); !ok {
		t.Fatal("recovered ban dropped by the sync")
	}
	n := len(log())
	red.Bans(ctx)
	if got := log()[n:]; len(got) != 2 { // EVALSHA + EVAL of the list, nothing pushed again
		t.Fatalf("second sync sent %d commands: %q", len(got), got)
	}
}

// Watch applies published bans and unbans without a sync.
func TestRedisWatch(t *testing.T) {
	c, _ := fakeRedisFunc(t, func(args []string) string {
		switch args[0] {
		case "SUBSCRIBE":
			return "*3\r\n" + bulk("subscribe") + bulk(args[1]) + ":1\r\n" +
				"*3\r\n" + bulk("message") + bulk(args[1]) + bulk("ban 192.0.2.7 60000 storm detected") +
				"*3\r\n" + bulk("message") + bulk(args[1]) + bulk("ban 10.1.0.0/16 60000 manual") +
				"*3\r\n" + bulk("message") + bulk(args[1]) + bulk("unban 192.0.2.8")
		case "EVALSHA": // the resync after subscribing: one ban, which the unban then lifts
			return "*3\r\n" + bulk("192.0.2.8") + ":60000\r\n" + bulk("manual")
		}
		return "-ERR\r\n"
	})
	l := NewRedis(c, nil)
	watching(t, l)
	eventually(t, func() bool {
		b, ok := l.bans.snap.Load().byClient["192.0.2.7"]
		_, cidr := l.bans.Banned("10.1.200.3", time.Now())
		_, lifted := l.bans.Banned("192.0.2.8", time.Now())
		return ok && b.Reason == "storm detected" && time.Until(b.Until) > 59*time.Second && cidr && !lifted
	})
}

// watching starts l.Watch and waits until it has subscribed and resynced.
func watching(t *testing.T, l *Redis) {
	ready := make(chan struct{}, 1)
	l.ready = func() {
		select {
		case ready <- struct{}{}:
		default:
		}
	}
	wctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() { cancel(); <-done })
	go func() { l.Watch(wctx); close(done) }()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("Watch never subscribed")
	}
}

// eventually polls cond for up to 2s and returns how long it took.
func eventually(t *testing.T, cond func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for !cond() {
		if time.Since(start) > 2*time.Second {
			t.Fatal("condition not met in 2s")
		}
		time.Sleep(time.Millisecond)
	}
	return time.Since(start)
}

// forEachRedis runs f against LIMITPLANE_REDIS (one server) and LIMITPLANE_REDIS_CLUSTER
// (redis+cluster://h1:6379,h2:6379,...), whichever are set:
//
//	LIMITPLANE_REDIS=redis://localhost:16379 go test ./internal/limiter -run Integration
func forEachRedis(t *testing.T, f func(t *testing.T, addr string)) {
	ran := false
	for _, env := range []string{"LIMITPLANE_REDIS", "LIMITPLANE_REDIS_CLUSTER"} {
		if addr := os.Getenv(env); addr != "" {
			ran = true
			t.Run(env, func(t *testing.T) { f(t, addr) })
		}
	}
	if !ran {
		t.Skip("LIMITPLANE_REDIS / LIMITPLANE_REDIS_CLUSTER not set")
	}
}

func isCluster(addr string) bool { return strings.Contains(addr, "+cluster://") }

func dialRedis(t *testing.T, addr string) *redisx.Client {
	c, err := redisx.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func uniq(p string) string { return p + strconv.FormatInt(time.Now().UnixNano(), 36) }

func TestRedisIntegration(t *testing.T) {
	forEachRedis(t, func(t *testing.T, addr string) {
		c := dialRedis(t, addr)
		l := NewRedis(c, nil)
		key := uniq("it-")
		r := Rate{Limit: 1, Period: time.Minute, Burst: 3}
		for i, want := range []int64{2, 1, 0} {
			res := mustAllow(t, l, key, r, 1)
			if !res.Allowed || res.Remaining != want {
				t.Fatalf("req %d: %+v", i, res)
			}
		}
		res := mustAllow(t, l, key, r, 1)
		if res.Allowed || res.Reason != Burst || res.RetryAfter < 59*time.Second || res.RetryAfter > time.Minute {
			t.Fatalf("4th: %+v", res)
		}
		if ttl, _ := c.Do(ctx, "PTTL", tag(key)+"r"); ttl.(int64) <= 0 {
			t.Fatalf("key must expire, pttl %v", ttl)
		}
	})
}

func TestRedisIntegrationSpendsOnlyWhenAllPass(t *testing.T) {
	forEachRedis(t, func(t *testing.T, addr string) {
		c := dialRedis(t, addr)
		l := NewRedis(c, nil)
		q := Request{Key: uniq("it-"), Rate: Rate{Limit: 1, Period: time.Hour, Burst: 10}, Cost: 4, Month: 6}
		if res := mustCheck(t, l, q); !res.Allowed || res.Used != 4 || res.Remaining != 6 {
			t.Fatalf("first: %+v", res)
		}
		if res := mustCheck(t, l, q); res.Reason != Monthly || res.Used != 4 {
			t.Fatalf("want monthly: %+v", res)
		}
		q.Cost, q.Month = 6, 100
		if res := mustCheck(t, l, q); !res.Allowed || res.Remaining != 0 || res.Used != 10 {
			t.Fatalf("monthly reject spent burst: %+v", res)
		}
		q.Cost = 1
		if res := mustCheck(t, l, q); res.Reason != Burst || res.Used != 10 {
			t.Fatalf("want burst: %+v", res)
		}
		if n, err := l.Used(ctx, q.Key); n != 10 || err != nil {
			t.Fatalf("burst reject billed the month: %d %v", n, err)
		}
		month := time.Now().UTC().Format("2006-01") // only the test reads the app clock
		if ttl, _ := c.Do(ctx, "PTTL", tag(q.Key)+"q:"+month); ttl.(int64) < 34*24*3600*1000 {
			t.Fatalf("quota key ttl %v", ttl)
		}
	})
}

// Two gateways: bans and unbans (IPs and CIDRs) reach the other one through pub/sub, with no sync.
func TestRedisIntegrationSharedBans(t *testing.T) {
	forEachRedis(t, func(t *testing.T, addr string) {
		a, b := NewRedis(dialRedis(t, addr), nil), NewRedis(dialRedis(t, addr), nil)
		watching(t, a)
		watching(t, b)
		ip := "198.51.100." + strconv.Itoa(int(time.Now().UnixNano()%250)+1)
		q := Request{Client: ip, Key: uniq("it-"), Rate: Rate{Limit: 10, Period: time.Second, Burst: 10}, Cost: 1}
		if res := mustCheck(t, b, q); !res.Allowed {
			t.Fatalf("before ban: %+v", res)
		}
		if err := a.Ban(ctx, Ban{Client: ip, Until: time.Now().Add(time.Minute), Reason: "manual"}); err != nil {
			t.Fatal(err)
		}
		lag := eventually(t, func() bool { res, _ := b.Check(ctx, q); return res.Reason == Banned })
		res := mustCheck(t, b, q)
		if res.RetryAfter < 59*time.Second || res.RetryAfter > time.Minute {
			t.Fatalf("ban via a on b: %+v", res)
		}
		t.Logf("ban reached the other gateway in %v", lag)
		bans, err := b.Bans(ctx)
		if err != nil || !slices.ContainsFunc(bans, func(x Ban) bool { return x.Client == ip && x.Reason == "manual" }) {
			t.Fatalf("b lists %v %v", bans, err)
		}
		if err := b.Unban(ctx, ip); err != nil {
			t.Fatal(err)
		}
		eventually(t, func() bool { res, _ := a.Check(ctx, q); return res.Allowed })

		cidr := "100.64." + strconv.Itoa(int(time.Now().UnixNano()%250)) + ".0/24"
		if err := a.Ban(ctx, Ban{Client: cidr, Until: time.Now().Add(time.Minute), Reason: "manual"}); err != nil {
			t.Fatal(err)
		}
		defer a.Unban(ctx, cidr)
		q.Client = strings.Replace(cidr, ".0/24", ".77", 1)
		lag = eventually(t, func() bool { res, _ := b.Check(ctx, q); return res.Reason == Banned })
		t.Logf("cidr ban reached the other gateway in %v", lag)
	})
}

// Without Watch, the periodic sync (Bans) is what spreads a ban.
func TestRedisIntegrationSyncRepairs(t *testing.T) {
	forEachRedis(t, func(t *testing.T, addr string) {
		a, b := NewRedis(dialRedis(t, addr), nil), NewRedis(dialRedis(t, addr), nil)
		ip := "203.0.113." + strconv.Itoa(int(time.Now().UnixNano()%250)+1)
		q := Request{Client: ip, Key: uniq("it-"), Rate: Rate{Limit: 10, Period: time.Second, Burst: 10}, Cost: 1}
		a.Ban(ctx, Ban{Client: ip, Until: time.Now().Add(time.Minute), Reason: "manual"})
		defer a.Unban(ctx, ip)
		if res := mustCheck(t, b, q); !res.Allowed {
			t.Fatalf("b has no sync or watch yet: %+v", res)
		}
		b.Bans(ctx)
		if res := mustCheck(t, b, q); res.Reason != Banned {
			t.Fatalf("after sync: %+v", res)
		}
	})
}

// flakyProxy forwards to addr; set(true) drops every connection and refuses new ones.
func flakyProxy(t *testing.T, addr string) (string, func(down bool)) {
	if u, err := url.Parse(addr); err == nil && u.Host != "" {
		addr = u.Host
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var down bool
	var open []net.Conn
	go func() {
		for {
			in, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if down {
				mu.Unlock()
				in.Close()
				continue
			}
			out, err := net.Dial("tcp", addr)
			if err != nil {
				mu.Unlock()
				in.Close()
				continue
			}
			open = append(open, in, out)
			mu.Unlock()
			go func() { io.Copy(in, out); in.Close() }()
			go func() { io.Copy(out, in); out.Close() }()
		}
	}()
	return ln.Addr().String(), func(d bool) {
		mu.Lock()
		defer mu.Unlock()
		down = d
		if d {
			for _, c := range open {
				c.Close()
			}
			open = nil
		}
	}
}

// A ban made while this gateway can't reach Redis is pushed on recovery, so the fleet gets it.
func TestRedisIntegrationOutageRecovery(t *testing.T) {
	addr := os.Getenv("LIMITPLANE_REDIS")
	if addr == "" {
		t.Skip("LIMITPLANE_REDIS not set (the proxy needs one server)")
	}
	proxy, set := flakyProxy(t, addr)
	mem := NewMemory()
	red := NewRedis(dialRedis(t, proxy), mem.BanList)
	fb := NewFallback(red, mem, nil)
	other := NewRedis(dialRedis(t, addr), nil)
	ip := "192.0.2." + strconv.Itoa(int(time.Now().UnixNano()%250)+1)
	defer other.Unban(ctx, ip)

	set(true)
	if err := fb.Ban(ctx, Ban{Client: ip, Until: time.Now().Add(time.Minute), Reason: "storm"}); err != nil {
		t.Fatal(err)
	}
	if res := mustCheck(t, fb, Request{Client: ip, Key: uniq("it-"), Rate: Rate{Limit: 1, Period: time.Second}, Cost: 1}); res.Reason != Banned {
		t.Fatalf("degraded: %+v", res)
	}
	set(false)
	if _, err := red.Bans(ctx); err != nil { // the sync that runs on recovery
		t.Fatal(err)
	}
	bans, err := other.Bans(ctx)
	i := slices.IndexFunc(bans, func(b Ban) bool { return b.Client == ip })
	if err != nil || i < 0 || bans[i].Reason != "storm" || time.Until(bans[i].Until) < 58*time.Second {
		t.Fatalf("other gateway sees %+v %v", bans, err)
	}
}

// countingProxy forwards to addr and counts the commands clients send.
func countingProxy(t *testing.T, addr string) (string, *atomic.Int64) {
	u, err := url.Parse(addr)
	if err == nil && u.Host != "" {
		addr = u.Host
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var n atomic.Int64
	go func() {
		for {
			in, err := ln.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("tcp", addr)
			if err != nil {
				in.Close()
				continue
			}
			go func() { io.Copy(in, out); in.Close() }()
			go func() {
				defer out.Close()
				r := bufio.NewReader(in)
				for {
					args, err := readCommand(r)
					if err != nil {
						return
					}
					n.Add(1)
					var b []byte
					b = fmt.Appendf(b, "*%d\r\n", len(args))
					for _, a := range args {
						b = fmt.Appendf(b, "$%d\r\n%s\r\n", len(a), a)
					}
					out.Write(b)
				}
			}()
		}
	}()
	return ln.Addr().String(), &n
}

func TestRedisIntegrationOneRoundTrip(t *testing.T) {
	addr := os.Getenv("LIMITPLANE_REDIS")
	if addr == "" {
		t.Skip("LIMITPLANE_REDIS not set (the proxy needs one server)")
	}
	proxy, n := countingProxy(t, addr)
	l := NewRedis(dialRedis(t, proxy), nil)
	q := Request{Client: "192.0.2.9", Key: uniq("it-"), Rate: Rate{Limit: 100, Period: time.Second, Burst: 100}, Cost: 1, Month: 1000}
	mustCheck(t, l, q) // may load the script (NOSCRIPT, then EVAL)
	before := n.Load()
	for range 10 {
		if res := mustCheck(t, l, q); !res.Allowed {
			t.Fatalf("%+v", res)
		}
	}
	if got := n.Load() - before; got != 10 {
		t.Fatalf("%d commands for 10 metered requests, want 10", got)
	}
	l.bans.set(Ban{Client: q.Client, Until: time.Now().Add(time.Minute)})
	before = n.Load()
	for range 10 {
		mustCheck(t, l, q)
	}
	if got := n.Load() - before; got != 0 {
		t.Fatalf("a banned flood sent %d commands to Redis", got)
	}
}

// The script's calendar math agrees with Go's, including leap days and centuries.
func TestRedisMonthLua(t *testing.T) {
	forEachRedis(t, func(t *testing.T, addr string) {
		c := dialRedis(t, addr)
		s := redisx.NewScript(monthLua + "return month(tonumber(ARGV[1]))")
		var ts []int64
		for _, d := range []string{"1970-01-01T00:00:00Z", "2000-02-29T23:59:59Z", "2000-03-01T00:00:00Z", "2024-12-31T23:59:59Z",
			"2026-01-31T23:59:59Z", "2026-02-01T00:00:00Z", "2100-02-28T12:00:00Z", "2100-03-01T00:00:00Z"} {
			tm, _ := time.Parse(time.RFC3339, d)
			ts = append(ts, tm.Unix(), tm.Unix()-1)
		}
		for s := int64(0); s < 5_000_000_000; s += 7_777_777 {
			ts = append(ts, s)
		}
		for _, sec := range ts {
			v, err := c.Eval(ctx, s, nil, sec)
			if want := time.Unix(sec, 0).UTC().Format("2006-01"); err != nil || v != want {
				t.Fatalf("%d: lua %v (%v), go %s", sec, v, err, want)
			}
		}
	})
}
