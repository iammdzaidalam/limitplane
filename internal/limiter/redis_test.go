package limiter

import (
	"bufio"
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
					args, err := readCommand(r)
					if err != nil {
						return
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

func TestRedisCheckWire(t *testing.T) {
	c, log := fakeRedis(t, "*5\r\n:2\r\n:2\r\n:250000\r\n:1500000\r\n:7\r\n")
	res, err := NewRedis(c, nil).Check(ctx, Request{Client: "192.0.2.1", Key: "acme", Rate: Rate{Limit: 10, Period: time.Second, Burst: 5}, Cost: 3, Month: 100})
	if err != nil {
		t.Fatal(err)
	}
	want := Result{Reason: Burst, Limit: 5, Remaining: 2, RetryAfter: 250 * time.Millisecond, ResetAfter: 1500 * time.Millisecond, Used: 7}
	if res != want {
		t.Fatalf("%+v", res)
	}
	// One command per request, and the tenant's keys share the {acme} hash tag.
	if l := log(); len(l) != 1 {
		t.Fatalf("%d commands, want 1", len(l))
	}
	a := log()[0]
	if a[0] != "EVALSHA" || a[2] != "3" || a[3] != "lp:ban:192.0.2.1" || a[4] != "lp:{acme}:r" || a[5] != "lp:{acme}:q:" ||
		a[6] != "100000" || a[7] != "5" || a[8] != "3" || a[9] != "100" {
		t.Fatalf("args %q", a)
	}
	c2, _ := fakeRedis(t, ":1\r\n")
	if _, err := NewRedis(c2, nil).Allow(ctx, "k", Rate{Limit: 1, Period: time.Second}, 1); err == nil {
		t.Fatal("malformed reply must error")
	}
}

func testRedis(t *testing.T) string {
	addr := os.Getenv("LIMITPLANE_REDIS")
	if addr == "" {
		t.Skip("LIMITPLANE_REDIS not set")
	}
	return addr
}

func dialRedis(t *testing.T, addr string) *redisx.Client {
	c, err := redisx.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func uniq(p string) string { return p + strconv.FormatInt(time.Now().UnixNano(), 36) }

// Runs the real Lua: LIMITPLANE_REDIS=redis://localhost:16379 go test ./internal/limiter -run Integration
func TestRedisIntegration(t *testing.T) {
	c := dialRedis(t, testRedis(t))
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
}

func TestRedisIntegrationSpendsOnlyWhenAllPass(t *testing.T) {
	c := dialRedis(t, testRedis(t))
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
}

// Two gateways on one Redis: a ban written through one blocks on the other.
func TestRedisIntegrationSharedBans(t *testing.T) {
	addr := testRedis(t)
	a, b := NewRedis(dialRedis(t, addr), nil), NewRedis(dialRedis(t, addr), nil)
	ip := "198.51.100." + strconv.Itoa(int(time.Now().UnixNano()%250)+1)
	q := Request{Client: ip, Key: uniq("it-"), Rate: Rate{Limit: 10, Period: time.Second, Burst: 10}, Cost: 1}
	if res := mustCheck(t, b, q); !res.Allowed {
		t.Fatalf("before ban: %+v", res)
	}
	if err := a.Ban(ctx, Ban{Client: ip, Until: time.Now().Add(time.Minute), Reason: "manual"}); err != nil {
		t.Fatal(err)
	}
	res := mustCheck(t, b, q)
	if res.Reason != Banned || res.RetryAfter < 59*time.Second || res.RetryAfter > time.Minute {
		t.Fatalf("ban via a not enforced on b: %+v", res)
	}
	bans, err := b.Bans(ctx)
	if err != nil || !slices.ContainsFunc(bans, func(x Ban) bool { return x.Client == ip && x.Reason == "manual" }) {
		t.Fatalf("b lists %v %v", bans, err)
	}
	if err := b.Unban(ctx, ip); err != nil {
		t.Fatal(err)
	}
	if res := mustCheck(t, a, q); !res.Allowed {
		t.Fatalf("unban via b not seen by a: %+v", res)
	}

	// CIDR bans reach the other replica on its next sync (Bans).
	cidr := "100.64." + strconv.Itoa(int(time.Now().UnixNano()%250)) + ".0/24"
	a.Ban(ctx, Ban{Client: cidr, Until: time.Now().Add(time.Minute), Reason: "manual"})
	defer a.Unban(ctx, cidr)
	q.Client = strings.Replace(cidr, ".0/24", ".77", 1)
	if res := mustCheck(t, a, q); res.Reason != Banned {
		t.Fatalf("cidr on a: %+v", res)
	}
	b.Bans(ctx)
	if res := mustCheck(t, b, q); res.Reason != Banned {
		t.Fatalf("cidr on b after sync: %+v", res)
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
	proxy, n := countingProxy(t, testRedis(t))
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
}

// The script's calendar math agrees with Go's, including leap days and centuries.
func TestRedisMonthLua(t *testing.T) {
	c := dialRedis(t, testRedis(t))
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
}
