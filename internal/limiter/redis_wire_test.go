package limiter

import (
	"bufio"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/redisx"
)

// Bad input is refused before a command is built.
func TestRedisInvalidNeverSent(t *testing.T) {
	c, log := fakeRedis(t, "-ERR should not be called\r\n")
	l := NewRedis(c, nil)
	for _, q := range []Request{
		{Key: "k", Rate: Rate{}, Cost: 1},
		{Key: "k", Rate: Rate{Limit: 1, Period: time.Second}, Cost: 0},
		{Key: "k", Rate: Rate{Limit: 10, Period: 5}, Cost: 1},
	} {
		if _, err := l.Check(ctx, q); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: %v", q, err)
		}
	}
	if err := l.Ban(ctx, Ban{Client: "::ffff:0:0/64", Until: time.Now().Add(time.Hour)}); !errors.Is(err, ErrBadBan) {
		t.Errorf("bad ban: %v", err)
	}
	if err := l.Unban(ctx, "::ffff:0:0/64"); !errors.Is(err, ErrBadBan) {
		t.Errorf("bad unban: %v", err)
	}
	if err := l.Ban(ctx, Ban{Client: "192.0.2.1", Until: time.Now().Add(-time.Second)}); err != nil {
		t.Errorf("expired ban: %v", err)
	}
	if n := len(log()); n != 0 {
		t.Fatalf("%d commands sent: %q", n, log())
	}
}

func TestRedisCheckReplies(t *testing.T) {
	var reply atomic.Value
	c, log := fakeRedisFunc(t, func([]string) string { return reply.Load().(string) })
	l := NewRedis(c, nil)
	q := Request{Key: "acme", Rate: Rate{Limit: 10_000_000, Period: time.Second}, Cost: 1, Month: -5}

	reply.Store("*5\r\n:0\r\n:9\r\n:0\r\n:100\r\n:0\r\n")
	res := mustCheck(t, l, q)
	if !res.Allowed || res.Reason != OK || res.Limit != 10_000_000 || res.Remaining != 9 || res.ResetAfter != 100*time.Microsecond {
		t.Fatalf("ok: %+v", res)
	}
	// A sub-microsecond interval is sent as 1us (the script's unit), and a negative cap as none.
	if a := log()[0]; a[5] != "1" || a[8] != "0" {
		t.Fatalf("args %q", a)
	}

	reply.Store("*5\r\n:3\r\n:0\r\n:0\r\n:0\r\n:42\r\n")
	if res := mustCheck(t, l, q); res.Allowed || res.Reason != Monthly || res.Limit != 0 || res.Used != 42 {
		t.Fatalf("monthly: %+v", res)
	}

	for _, bad := range []string{"*5\r\n:0\r\n:0\r\n$1\r\nx\r\n:0\r\n:0\r\n", "*4\r\n:0\r\n:0\r\n:0\r\n:0\r\n", "$2\r\nok\r\n", "-BUSY script\r\n"} {
		reply.Store(bad)
		if _, err := l.Check(ctx, q); err == nil {
			t.Errorf("reply %q: want error", bad)
		}
	}

	reply.Store(":17\r\n")
	if n, err := l.Used(ctx, "acme"); err != nil || n != 17 {
		t.Fatalf("Used %d %v", n, err)
	}
	if a := log()[len(log())-1]; a[3] != "lp:{acme}:q:" {
		t.Fatalf("Used args %q", a)
	}
	for _, bad := range []string{"$2\r\n17\r\n", "-ERR x\r\n"} {
		reply.Store(bad)
		if _, err := l.Used(ctx, "acme"); err == nil {
			t.Errorf("Used reply %q: want error", bad)
		}
	}
	for _, bad := range []string{"*2\r\n$1\r\na\r\n:1\r\n", ":1\r\n", "-ERR x\r\n"} {
		reply.Store(bad)
		if _, err := l.Bans(ctx); err == nil {
			t.Errorf("Bans reply %q: want error", bad)
		}
	}
}

// Bans go to Redis in canonical form, so every replica and every spelling agree.
func TestRedisBanCanonical(t *testing.T) {
	c, log := fakeRedis(t, ":1\r\n")
	l := NewRedis(c, nil)
	if err := l.Ban(ctx, Ban{Client: "::ffff:10.1.2.3/120", Until: time.Now().Add(time.Minute), Reason: "storm"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Unban(ctx, "::ffff:192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	cmds := log()
	if len(cmds) != 2 || cmds[0][4] != "10.1.2.0/24" || cmds[0][6] != "storm" || cmds[1][4] != "192.0.2.1" {
		t.Fatalf("commands %q", cmds)
	}
	if ms := cmds[0][5]; ms < "59000" || ms > "60000" || len(ms) != 5 {
		t.Fatalf("ttl %s", ms)
	}
	if _, ok := l.bans.Banned("10.1.2.200", time.Now()); !ok {
		t.Fatal("a ban applies locally at once")
	}
	// A failed write is not applied locally: the caller (the fallback) records it instead.
	c2, _ := fakeRedis(t, "-READONLY You can't write against a read only replica.\r\n")
	l2 := NewRedis(c2, nil)
	if err := l2.Ban(ctx, Ban{Client: "192.0.2.9", Until: time.Now().Add(time.Minute)}); err == nil {
		t.Fatal("want the Redis error")
	}
	if _, ok := l2.bans.Banned("192.0.2.9", time.Now()); ok {
		t.Fatal("failed ban applied locally")
	}
}

// Published messages from peers: well-formed ones apply, anything else is ignored.
func TestRedisApply(t *testing.T) {
	c, err := redisx.New("127.0.0.1:1") // never dialled: apply only touches the local list
	if err != nil {
		t.Fatal(err)
	}
	l := NewRedis(c, nil)
	for _, m := range []string{
		"ban 192.0.2.1 60000 storm from 3 regions", // reasons may hold spaces
		"ban ::ffff:192.0.2.2 60000 manual",
		"ban 192.0.2.3 soon manual",
		"ban 192.0.2.4",
		"ban",
		"",
		"reset everything",
		"ban 192.0.2.5 60000 x",
		"unban 192.0.2.5",
		"unban",
	} {
		l.apply(m)
	}
	snap := l.bans.snap.Load().byClient
	if len(snap) != 2 || snap["192.0.2.1"].Reason != "storm from 3 regions" || snap["192.0.2.2"].Client != "192.0.2.2" {
		t.Fatalf("bans %+v", snap)
	}
}

// flakySubs is a RESP server whose first subscription is cut right after the confirmation.
// Later ones stay up and carry one ban.
type flakySubs struct {
	ln          net.Listener
	mu          sync.Mutex
	subs, syncs int
}

func (f *flakySubs) serve() {
	for {
		nc, err := f.ln.Accept()
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
				f.mu.Lock()
				switch args[0] {
				case "SUBSCRIBE":
					f.subs++
					n := f.subs
					f.mu.Unlock()
					nc.Write([]byte("*3\r\n" + bulk("subscribe") + bulk(args[1]) + ":1\r\n"))
					if n == 1 {
						return // dropped: the client must resubscribe and resync
					}
					nc.Write([]byte("*3\r\n" + bulk("message") + bulk(args[1]) + bulk("ban 192.0.2.77 60000 live")))
					continue
				case "EVALSHA":
					f.syncs++
					f.mu.Unlock()
					// Published while the subscription was down: only the resync can deliver it.
					nc.Write([]byte("*3\r\n" + bulk("198.51.100.7") + ":60000\r\n" + bulk("missed")))
					continue
				}
				f.mu.Unlock()
				nc.Write([]byte("-ERR unexpected " + strings.ToLower(args[0]) + "\r\n"))
			}
		}()
	}
}

// Takes about a second: Watch backs off 1s before resubscribing.
func TestRedisWatchResubscribes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &flakySubs{ln: ln}
	go f.serve()
	c, err := redisx.New(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	l := NewRedis(c, nil)
	watching(t, l)
	eventually3(t, func() bool {
		_, live := l.bans.Banned("192.0.2.77", time.Now())
		_, missed := l.bans.Banned("198.51.100.7", time.Now())
		return live && missed
	})
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.subs != 2 || f.syncs != 2 {
		t.Fatalf("%d subscribes, %d resyncs; want 2 of each", f.subs, f.syncs)
	}
}

// eventually3 is eventually with room for Watch's 1s backoff.
func eventually3(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in 3s")
		}
	}
}
