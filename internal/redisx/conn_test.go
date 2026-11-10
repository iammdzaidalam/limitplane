package redisx

import (
	"bufio"
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func dialFake(t *testing.T, f *fake) *Client {
	t.Helper()
	c, err := Dial(f.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func conns(f *fake) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns
}

func echo(args []string) string {
	if args[0] == "ECHO" {
		return enc(args[1])
	}
	return "+PONG\r\n"
}

func TestPoolReusesConn(t *testing.T) {
	f := newFake(t, echo)
	c := dialFake(t, f)
	for i := range 50 {
		if v, err := c.Do(bg, "ECHO", strconv.Itoa(i)); err != nil || v != strconv.Itoa(i) {
			t.Fatalf("%d: %v %v", i, v, err)
		}
	}
	if n := conns(f); n != 1 {
		t.Fatalf("%d conns for sequential commands, want 1", n)
	}
}

// Replies stay paired with their commands under concurrency, and the pool keeps at most poolSize idle.
func TestConcurrentCommands(t *testing.T) {
	f := newFake(t, func(args []string) string {
		time.Sleep(time.Millisecond) // overlap the callers so the pool has to grow
		return echo(args)
	})
	c := dialFake(t, f)
	var wg sync.WaitGroup
	var bad atomic.Int64
	for g := range 48 {
		wg.Go(func() {
			for i := range 20 {
				want := strconv.Itoa(g) + " \r\n " + strconv.Itoa(i)
				if v, err := c.Do(bg, "ECHO", want); err != nil || v != want {
					bad.Add(1)
				}
			}
		})
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d mismatched replies", bad.Load())
	}
	if n := len(c.node.idle); n > poolSize || n == 0 {
		t.Fatalf("%d idle conns, want 1..%d", n, poolSize)
	}
	if n := conns(f); n <= 1 {
		t.Fatalf("%d conns: callers never overlapped", n)
	}
}

// Every argument type reaches the server byte for byte.
func TestArgEncoding(t *testing.T) {
	got := make(chan []string, 1)
	f := newFake(t, func(args []string) string { got <- args; return "+OK\r\n" })
	c := dialFake(t, f)
	if _, err := c.Do(bg, "SET", "a b\r\nc", []byte{0, 255, '\n'}, 42, int64(-7), 1.5, true, ""); err != nil {
		t.Fatal(err)
	}
	want := []string{"SET", "a b\r\nc", "\x00\xff\n", "42", "-7", "1.5", "true", ""}
	if a := <-got; !reflect.DeepEqual(a, want) {
		t.Fatalf("server saw %q, want %q", a, want)
	}
}

func TestMalformedReplies(t *testing.T) {
	for _, in := range []string{
		"", "\r\n", "+OK\n", ":12x\r\n", "$abc\r\n", "$5\r\nab", "*2\r\n:1\r\n", "*x\r\n", "!3\r\nfoo\r\n",
	} {
		v, err := readReply(bufio.NewReader(strings.NewReader(in)))
		if err == nil {
			t.Errorf("%q: got %#v, want error", in, v)
		}
	}
	// Over the wire, a garbled reply drops the conn: the next command gets a clean one.
	var garble atomic.Bool
	garble.Store(true)
	f := newFake(t, func(args []string) string {
		if garble.Swap(false) {
			return "?garbage\r\n"
		}
		return "+PONG\r\n"
	})
	c, err := New(f.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Do(bg, "PING"); err == nil || errors.As(err, new(Error)) {
		t.Fatalf("garbled reply: %v", err)
	}
	if v, err := c.Do(bg, "PING"); err != nil || v != "PONG" || conns(f) != 2 {
		t.Fatalf("after garbage: %v %v, %d conns", v, err, conns(f))
	}
}

// hangUpAfter is a server that closes each connection after n replies, the way an idle timeout
// on Redis or a load balancer drops a pooled connection.
func hangUpAfter(t *testing.T, n int) *fake {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fake{ln: ln}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns++
			f.mu.Unlock()
			go func() {
				defer nc.Close()
				r := bufio.NewReader(nc)
				for range n {
					if _, err := readReply(r); err != nil {
						return
					}
					nc.Write([]byte("+PONG\r\n"))
				}
			}()
		}
	}()
	return f
}

// A conn that fails is closed, never pooled. Only a pooled conn is retried: a server that hangs
// up on every new conn costs one dial per command, not a loop.
func TestBrokenConnDropped(t *testing.T) {
	f := hangUpAfter(t, 0)
	c, err := New(f.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for range 2 {
		if _, err := c.Do(bg, "PING"); !errors.Is(err, errDead) {
			t.Fatalf("want errDead, got %v", err)
		}
	}
	if n := conns(f); n != 2 {
		t.Fatalf("%d conns, want 2", n)
	}
}

// Managed Redis and cloud load balancers close idle connections (Azure Cache: 10 min). The first
// command on each stale pooled conn then fails, the fallback trips and serves degraded for a second.
func TestStaleConnRetried(t *testing.T) {
	f := hangUpAfter(t, 1)
	c, err := New(f.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Do(bg, "PING")
	time.Sleep(10 * time.Millisecond)
	if _, err := c.Do(bg, "PING"); err != nil {
		t.Fatalf("stale pooled conn surfaced as an error: %v", err)
	}
}

// A conn idle past maxIdle is closed rather than risked: whatever dropped it may not send a FIN.
func TestIdleConnExpires(t *testing.T) {
	f := newFake(t, echo)
	c := dialFake(t, f)
	cn := <-c.node.idle
	cn.idle = time.Now().Add(-maxIdle)
	c.node.idle <- cn
	if v, err := c.Do(bg, "PING"); err != nil || v != "PONG" {
		t.Fatalf("%v %v", v, err)
	}
	if n := conns(f); n != 2 {
		t.Fatalf("%d conns, want 2: the expired one must not be reused", n)
	}
}

func TestCloseIsFinal(t *testing.T) {
	f := newFake(t, echo)
	c := dialFake(t, f)
	c.Close()
	c.Close() // idempotent
	if _, err := c.Do(bg, "PING"); !errors.Is(err, errClosed) {
		t.Fatalf("Do after Close: %v", err)
	}
	if _, err := c.Eval(bg, NewScript("return 1"), nil); !errors.Is(err, errClosed) {
		t.Fatalf("Eval after Close: %v", err)
	}
	if _, err := c.Subscribe(bg, "ch"); !errors.Is(err, errClosed) {
		t.Fatalf("Subscribe after Close: %v", err)
	}
	if len(c.node.idle) != 0 {
		t.Fatal("Close left idle conns open")
	}
	// A command in flight during Close doesn't park its conn in the drained pool.
	cn, err := c.node.dial(bg)
	if err != nil {
		t.Fatal(err)
	}
	c.node.put(cn)
	if len(c.node.idle) != 0 {
		t.Fatal("put after Close pooled the conn")
	}
}

func TestAuthUserAndSelect(t *testing.T) {
	var seen sync.Map
	f := newFake(t, func(args []string) string {
		seen.Store(strings.Join(args, " "), true)
		if args[0] == "SELECT" && args[1] == "99" {
			return "-ERR DB index is out of range\r\n"
		}
		return "+OK\r\n"
	})
	addr := f.ln.Addr().String()
	c, err := Dial("redis://alice:pw@" + addr + "/3")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	for _, want := range []string{"AUTH alice pw", "SELECT 3"} {
		if _, ok := seen.Load(want); !ok {
			t.Errorf("never sent %q", want)
		}
	}
	if _, err := Dial("redis://" + addr + "/99"); err == nil || !strings.Contains(err.Error(), "SELECT") {
		t.Fatalf("bad db: %v", err)
	}
	if _, err := New("redis://" + addr + "/x"); err == nil {
		t.Fatal("non-numeric db must fail at New")
	}
}

// Only NOSCRIPT falls back to EVAL; other errors come back as they are, after one command.
func TestEvalErrors(t *testing.T) {
	f := newFake(t, func(args []string) string {
		if args[0] == "EVALSHA" {
			return "-BUSY Redis is busy running a script\r\n"
		}
		return "+OK\r\n"
	})
	c := dialFake(t, f)
	if _, err := c.Eval(bg, NewScript("return 1"), []string{"k"}); err == nil || !strings.HasPrefix(err.Error(), "BUSY") {
		t.Fatalf("got %v", err)
	}
	if n := count(f, "EVAL return 1 1 k"); n != 0 {
		t.Fatal("non-NOSCRIPT error fell back to EVAL")
	}
	if s := NewScript("return 1"); s.sha != "e0e1f9fabfc9d4800c877a703b823ac0578ff8db" {
		t.Fatalf("sha1 %s", s.sha) // what SCRIPT LOAD returns for "return 1"
	}
}

func TestSubscribeErrors(t *testing.T) {
	var mode atomic.Value
	f := newFake(t, func(args []string) string { return mode.Load().(string) })
	c, err := New(f.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, reply := range []string{"-NOPERM no access to channel\r\n", "+OK\r\n", enc([]any{"message", "ch", "early"})} {
		mode.Store(reply)
		if _, err := c.Subscribe(bg, "ch"); err == nil {
			t.Errorf("SUBSCRIBE answered %q: want error", reply)
		}
	}
	// A push that is not an array, or one cut in half, is an error from Receive.
	for _, tail := range []string{":5\r\n", "*3\r\n$7\r\nmessage\r\n"} {
		mode.Store(enc([]any{"subscribe", "ch", 1}) + tail)
		sub, err := c.Subscribe(bg, "ch")
		if err != nil {
			t.Fatal(err)
		}
		if tail != ":5\r\n" {
			go func() { time.Sleep(20 * time.Millisecond); sub.Close() }()
		}
		if _, err := sub.Receive(time.Second); err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("push %q: %v", tail, err)
		}
		sub.Close()
	}
	// Ping on a closed subscription fails, so Watch notices a dead one.
	mode.Store(enc([]any{"subscribe", "ch", 1}))
	sub, err := c.Subscribe(bg, "ch")
	if err != nil {
		t.Fatal(err)
	}
	sub.Close()
	if err := sub.Ping(); err == nil {
		t.Fatal("Ping on a closed sub must fail")
	}
}
