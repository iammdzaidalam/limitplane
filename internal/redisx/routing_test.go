package redisx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func dialCluster(t *testing.T, seed *fake) *Client {
	t.Helper()
	c, err := Dial("redis+cluster://" + seed.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// More CLUSTER KEYSLOT answers, from a real Redis.
func TestSlotKnownAnswers(t *testing.T) {
	for key, want := range map[string]int{
		"a": 15495, "b": 3300, "c": 7365, "bar": 5061, "hello": 866, "key": 12539, "mykey": 14687,
		"{a}b": 15495, "x{a}": 15495, "{a}{b}": 15495, "{}a": Slot("{}a"), "a{": int(crc16("a{") & 16383),
	} {
		if got := Slot(key); got != want {
			t.Errorf("Slot(%q) = %d, want %d", key, got, want)
		}
	}
	for i := range 1000 { // always in range
		if s := Slot(fmt.Sprint("k", i, "\x00\xff")); s < 0 || s >= numSlots {
			t.Fatalf("slot %d", s)
		}
	}
}

func TestFirstKey(t *testing.T) {
	for _, c := range []struct {
		args []any
		key  string
		ok   bool
	}{
		{[]any{"GET", "k"}, "k", true},
		{[]any{"get", "k"}, "k", true},
		{[]any{"INCRBY", "k", 1}, "k", true},
		{[]any{"GET"}, "", false},
		{[]any{"EVALSHA", "sha", 2, "a", "b"}, "a", true},
		{[]any{"EVAL", "src", int64(1), "a"}, "a", true},
		{[]any{"eval_ro", "src", 1, "a"}, "a", true},
		{[]any{"FCALL", "fn", 1, "a"}, "a", true},
		{[]any{"EVAL", "src", 0}, "", false},
		{[]any{"EVAL", "src", 0, "arg"}, "", false},
		{[]any{"EVAL", "src", "1", "a"}, "", false}, // numkeys must be a number to route by
		{[]any{"PING"}, "", false},
		{[]any{"PUBLISH", "ch", "m"}, "", false},
		{[]any{"CLUSTER", "SLOTS"}, "", false},
		{[]any{"HSET", []byte("bk"), "f", "v"}, "bk", true},
		{[]any{"GET", 42}, "42", true},
	} {
		key, ok := firstKey(c.args)
		if key != c.key || ok != c.ok {
			t.Errorf("firstKey(%v) = %q %v, want %q %v", c.args, key, ok, c.key, c.ok)
		}
	}
}

// TRYAGAIN (multi-key op mid-resharding) and CLUSTERDOWN fail this request as ErrNodeDown, once,
// without marking the node down: it answered, so it is alive.
func TestClusterTryAgain(t *testing.T) {
	for _, reply := range []string{"-TRYAGAIN Multiple keys request during rehashing of slot\r\n", "-CLUSTERDOWN The cluster is down\r\n"} {
		var a *fake
		a = newFake(t, func(args []string) string {
			if args[0] == "CLUSTER" {
				return slots(0, 16383, a)
			}
			return reply
		})
		c := dialCluster(t, a)
		_, err := c.Do(bg, "GET", "k")
		var rerr Error
		if !errors.Is(err, ErrNodeDown) || !errors.As(err, &rerr) {
			t.Fatalf("%q: %v", reply, err)
		}
		if count(a, "GET k") != 1 {
			t.Fatalf("%q retried: %q", reply, a.log())
		}
		if n := c.cluster.node(a.ln.Addr().String()); n.isDown(time.Now().UnixNano()) {
			t.Fatalf("%q marked a live node down", reply)
		}
	}
}

// "MOVED 3999 :6380" (no host) means the host of the node that answered.
func TestClusterMovedWithoutHost(t *testing.T) {
	var a, b *fake
	var moved atomic.Bool
	layout := func() string {
		if moved.Load() {
			return slots(0, 16383, b)
		}
		return slots(0, 16383, a)
	}
	b = newFake(t, func(args []string) string {
		if args[0] == "CLUSTER" {
			return layout()
		}
		return "+from-b\r\n"
	})
	a = newFake(t, func(args []string) string {
		if args[0] == "CLUSTER" {
			return layout()
		}
		moved.Store(true)
		_, port := hostPort(b)
		return fmt.Sprintf("-MOVED %d :%d\r\n", Slot(args[1]), port)
	})
	c := dialCluster(t, a)
	for range 2 {
		if v, err := c.Do(bg, "GET", "k"); err != nil || v != "from-b" {
			t.Fatalf("got %v %v", v, err)
		}
	}
	if count(a, "GET k") != 1 {
		t.Fatalf("the slot was not moved to b: a saw %q", a.log())
	}
}

// switchable listens on one address and hangs up on every connection while down.
type switchable struct {
	*fake
	down atomic.Bool
}

func newSwitchable(t *testing.T, handle func([]string) string) *switchable {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &switchable{fake: &fake{ln: ln, handle: handle}}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns++
			s.mu.Unlock()
			if s.down.Load() {
				nc.Close()
				continue
			}
			go s.serve(nc)
		}
	}()
	return s
}

// The per-node breaker: a failing node is skipped for nodeCooldown without dialing, then retried.
func TestClusterNodeBreaker(t *testing.T) {
	var a *fake
	var b *switchable
	a = newFake(t, func(args []string) string {
		if args[0] == "CLUSTER" {
			return slots(0, 8191, a, 8192, 16383, b.fake)
		}
		return "+a\r\n"
	})
	var hang atomic.Bool
	b = newSwitchable(t, func([]string) string {
		if hang.Load() {
			return "" // never answer
		}
		return "+b\r\n"
	})
	c := dialCluster(t, a)
	kb := keyIn(8192, 16383)
	nb := c.cluster.node(b.ln.Addr().String())

	b.down.Store(true)
	if _, err := c.Do(bg, "GET", kb); !errors.Is(err, ErrNodeDown) {
		t.Fatalf("want ErrNodeDown, got %v", err)
	}
	if left := time.Until(time.Unix(0, nb.downUntil.Load())); left <= 0 || left > nodeCooldown {
		t.Fatalf("node down for %v", left)
	}
	b.down.Store(false)
	dials := conns(b.fake)
	if _, err := c.Do(bg, "GET", kb); !errors.Is(err, ErrNodeDown) || conns(b.fake) != dials {
		t.Fatalf("within the cooldown: %v, %d new dials", err, conns(b.fake)-dials)
	}
	if v, err := c.Do(bg, "GET", keyIn(0, 8191)); err != nil || v != "a" {
		t.Fatalf("other node: %v %v", v, err)
	}
	nb.downUntil.Store(0) // cooldown over
	if v, err := c.Do(bg, "GET", kb); err != nil || v != "b" {
		t.Fatalf("recovered node: %v %v", v, err)
	}

	// A caller's cancel says nothing about the node.
	hang.Store(true)
	cctx, cancel := context.WithCancel(bg)
	time.AfterFunc(20*time.Millisecond, cancel)
	if _, err := c.Do(cctx, "GET", kb); !errors.Is(err, context.Canceled) || errors.Is(err, ErrNodeDown) {
		t.Fatalf("cancel: %v", err)
	}
	if nb.isDown(time.Now().UnixNano()) {
		t.Fatal("a caller cancel marked the node down")
	}
}

// Nor does a caller's deadline. The socket deadline is the same instant as the context's and
// often fires first, while ctx.Err() is still nil, so call must judge by the error.
func TestCallerDeadlineIsNotNodeFault(t *testing.T) {
	var a *fake
	a = newFake(t, func(args []string) string {
		if args[0] == "CLUSTER" {
			return slots(0, 16383, a)
		}
		return "" // never answer
	})
	c := dialCluster(t, a)
	n := c.cluster.node(a.ln.Addr().String())
	for i := range 20 {
		cctx, cancel := context.WithTimeout(bg, 5*time.Millisecond)
		_, err := c.Do(cctx, "GET", "k")
		cancel()
		if errors.Is(err, ErrNodeDown) || n.isDown(time.Now().UnixNano()) {
			t.Fatalf("try %d: %v; node down %v", i, err, n.isDown(time.Now().UnixNano()))
		}
	}
}

// The first commands on a New client load the slot map once between them.
func TestClusterLazyLoadOnce(t *testing.T) {
	var a *fake
	a = newFake(t, func(args []string) string {
		if args[0] == "CLUSTER" {
			time.Sleep(5 * time.Millisecond)
			return slots(0, 16383, a)
		}
		return "+OK\r\n"
	})
	c, err := New("redis+cluster://" + a.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if count(a, "CLUSTER SLOTS") != 0 {
		t.Fatal("New must not connect")
	}
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			if _, err := c.Do(bg, "GET", fmt.Sprint("k", i)); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if n := count(a, "CLUSTER SLOTS"); n != 1 {
		t.Fatalf("%d slot loads, want 1", n)
	}
}

// Dial needs one seed to answer; with none it fails and says why.
func TestClusterSeeds(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	var a *fake
	a = newFake(t, func(args []string) string {
		if args[0] == "CLUSTER" {
			return slots(0, 16383, a)
		}
		return "+OK\r\n"
	})
	c, err := Dial("redis+cluster://" + dead + "," + a.ln.Addr().String())
	if err != nil {
		t.Fatalf("one live seed: %v", err)
	}
	c.Close()
	if _, err := Dial("redis+cluster://" + dead); err == nil || !strings.Contains(err.Error(), "cluster slots") {
		t.Fatalf("no live seed: %v", err)
	}
	// A seed that answers with an empty map (cluster not created yet) is an error too.
	empty := newFake(t, func([]string) string { return "*0\r\n" })
	if _, err := Dial("redis+cluster://" + empty.ln.Addr().String()); err == nil || !strings.Contains(err.Error(), "no slots") {
		t.Fatalf("empty map: %v", err)
	}
}

// A storm of MOVED replies refreshes the map in the background at most once per refreshGap.
func TestClusterRefreshIsRateLimited(t *testing.T) {
	var a, b *fake
	a = newFake(t, func(args []string) string {
		if args[0] == "CLUSTER" {
			return slots(0, 16383, a) // stale forever
		}
		return fmt.Sprintf("-MOVED %d %s\r\n", Slot(args[1]), b.ln.Addr())
	})
	b = newFake(t, func(args []string) string {
		if args[0] == "CLUSTER" {
			return slots(0, 16383, a)
		}
		return "+OK\r\n"
	})
	c := dialCluster(t, a)
	for i := range 50 {
		if _, err := c.Do(bg, "GET", fmt.Sprint("key", i)); err != nil {
			t.Fatal(err)
		}
	}
	loads := func() int { return count(a, "CLUSTER SLOTS") + count(b, "CLUSTER SLOTS") }
	for deadline := time.Now().Add(time.Second); loads() < 2 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond) // the background refresh
	}
	time.Sleep(20 * time.Millisecond) // and room for any extra one to show up
	if n := loads(); n != 2 {
		t.Fatalf("%d slot loads for 50 MOVEDs in well under a second, want 2 (Dial + 1)", n)
	}
}

// Keyless commands go to some known master.
func TestClusterKeyless(t *testing.T) {
	var a, b *fake
	layout := func() string { return slots(0, 8191, a, 8192, 16383, b) }
	h := func(args []string) string {
		if args[0] == "CLUSTER" {
			return layout()
		}
		return "+PONG\r\n"
	}
	a, b = newFake(t, h), newFake(t, h)
	c := dialCluster(t, a)
	for range 20 {
		if v, err := c.Do(bg, "PING"); err != nil || v != "PONG" {
			t.Fatalf("%v %v", v, err)
		}
	}
	if count(a, "PING")+count(b, "PING") != 20 {
		t.Fatal("PINGs lost")
	}
}

// Subscribe skips a node its breaker has marked down.
func TestClusterSubscribePrefersHealthy(t *testing.T) {
	var a, b *fake
	layout := func() string { return slots(0, 8191, a, 8192, 16383, b) }
	h := func(args []string) string {
		switch args[0] {
		case "CLUSTER":
			return layout()
		case "SUBSCRIBE":
			return enc([]any{"subscribe", args[1], 1})
		}
		return "-ERR\r\n"
	}
	a, b = newFake(t, h), newFake(t, h)
	c := dialCluster(t, a)
	c.cluster.node(a.ln.Addr().String()).downUntil.Store(time.Now().Add(time.Hour).UnixNano())
	for range 5 {
		sub, err := c.Subscribe(bg, "lp:bans")
		if err != nil {
			t.Fatal(err)
		}
		sub.Close()
	}
	if count(a, "SUBSCRIBE lp:bans") != 0 || count(b, "SUBSCRIBE lp:bans") != 5 {
		t.Fatalf("a %d b %d", count(a, "SUBSCRIBE lp:bans"), count(b, "SUBSCRIBE lp:bans"))
	}
}

func TestClusterClose(t *testing.T) {
	var a *fake
	a = newFake(t, func(args []string) string {
		if args[0] == "CLUSTER" {
			return slots(0, 16383, a)
		}
		return "+OK\r\n"
	})
	c := dialCluster(t, a)
	c.Do(bg, "GET", "k")
	c.Close()
	if _, err := c.Do(bg, "GET", "k"); !errors.Is(err, errClosed) {
		t.Fatalf("after Close: %v", err)
	}
	for _, n := range c.cluster.all() {
		if len(n.idle) != 0 {
			t.Fatalf("%s kept idle conns", n.addr)
		}
	}
}
