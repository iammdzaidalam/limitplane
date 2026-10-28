package redisx

import (
	"bufio"
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// fake is an in-process RESP server. handle returns a raw RESP reply, or "" to never answer.
type fake struct {
	ln     net.Listener
	mu     sync.Mutex
	cmds   []string
	conns  int
	handle func(args []string) string
}

func newFake(t *testing.T, handle func(args []string) string) *fake {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fake{ln: ln, handle: handle}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns++
			f.mu.Unlock()
			go f.serve(nc)
		}
	}()
	return f
}

func (f *fake) serve(nc net.Conn) {
	defer nc.Close()
	r := bufio.NewReader(nc)
	for {
		v, err := readReply(r) // commands are arrays of bulk strings, same grammar
		if err != nil {
			return
		}
		var args []string
		for _, a := range v.([]any) {
			args = append(args, a.(string))
		}
		f.mu.Lock()
		f.cmds = append(f.cmds, strings.Join(args, " "))
		f.mu.Unlock()
		if out := f.handle(args); out != "" {
			nc.Write([]byte(out))
		}
	}
}

func (f *fake) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cmds...)
}

func TestReadReply(t *testing.T) {
	cases := []struct {
		in   string
		want any
		err  string
	}{
		{"+OK\r\n", "OK", ""},
		{":-42\r\n", int64(-42), ""},
		{"$5\r\nhe\r\no\r\n", "he\r\no", ""},
		{"$-1\r\n", nil, ""},
		{"*-1\r\n", nil, ""},
		{"-ERR boom\r\n", nil, "ERR boom"},
		{"*3\r\n:1\r\n*1\r\n$1\r\nx\r\n-WRONG\r\n", []any{int64(1), []any{"x"}, Error("WRONG")}, ""},
		{"?\r\n", nil, "unknown"},
	}
	for _, c := range cases {
		got, err := readReply(bufio.NewReader(strings.NewReader(c.in)))
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%q: err %v, want %q", c.in, err, c.err)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: got %#v %v, want %#v", c.in, got, err, c.want)
		}
	}
}

func TestAuthFromURLAndPool(t *testing.T) {
	f := newFake(t, func(a []string) string {
		switch a[0] {
		case "AUTH":
			if a[1] == "s3cret" {
				return "+OK\r\n"
			}
			return "-WRONGPASS bad\r\n"
		case "SELECT":
			return "+OK\r\n"
		case "INCRBY":
			return ":7\r\n"
		}
		return "-ERR unknown\r\n"
	})
	addr := f.ln.Addr().String()
	if _, err := Dial("redis://:nope@" + addr); err == nil || !strings.Contains(err.Error(), "WRONGPASS") {
		t.Fatalf("wrong password: %v", err)
	}
	c, err := Dial("redis://:s3cret@" + addr + "/2")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for range 5 {
		v, err := c.Do(context.Background(), "INCRBY", "k", int64(3))
		if err != nil || v != int64(7) {
			t.Fatalf("got %v %v", v, err)
		}
	}
	if _, err := c.Do(context.Background(), "NOPE"); !errors.As(err, new(Error)) {
		t.Fatalf("want server Error, got %v", err)
	}
	if _, err := c.Do(context.Background(), "INCRBY", "k", 1); err != nil {
		t.Fatal("conn should survive an error reply:", err)
	}
	f.mu.Lock()
	conns := f.conns
	f.mu.Unlock()
	if conns != 2 { // the failed AUTH dial + one pooled conn
		t.Fatalf("conns = %d, want 2", conns)
	}
	want := []string{"AUTH nope", "AUTH s3cret", "SELECT 2", "INCRBY k 3"}
	if got := f.log()[:4]; !reflect.DeepEqual(got, want) {
		t.Fatalf("log %v, want %v", got, want)
	}
}

func TestEvalNoScriptFallback(t *testing.T) {
	var mu sync.Mutex
	loaded := false
	f := newFake(t, func(a []string) string {
		mu.Lock()
		defer mu.Unlock()
		switch a[0] {
		case "EVALSHA":
			if !loaded {
				return "-NOSCRIPT No matching script\r\n"
			}
			return ":1\r\n"
		case "EVAL":
			loaded = true
			return ":1\r\n"
		}
		return "-ERR\r\n"
	})
	c, err := Dial(f.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s := NewScript("return 1")
	for range 2 {
		if v, err := c.Eval(context.Background(), s, []string{"k"}, 5); err != nil || v != int64(1) {
			t.Fatalf("got %v %v", v, err)
		}
	}
	want := []string{"EVALSHA " + s.sha + " 1 k 5", "EVAL return 1 1 k 5", "EVALSHA " + s.sha + " 1 k 5"}
	if got := f.log(); !reflect.DeepEqual(got, want) {
		t.Fatalf("log %q", got)
	}
}

func TestDeadlineDropsConn(t *testing.T) {
	f := newFake(t, func(a []string) string {
		if a[0] == "HANG" {
			return ""
		}
		return "+PONG\r\n"
	})
	c, err := Dial(f.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Do(ctx, "HANG"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("deadline not honoured")
	}
	// the hung conn must not be reused, or PING would read nothing
	if v, err := c.Do(context.Background(), "PING"); err != nil || v != "PONG" {
		t.Fatalf("got %v %v", v, err)
	}
}

func TestCancel(t *testing.T) {
	f := newFake(t, func(a []string) string { return "" })
	c, err := Dial(f.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	if _, err := c.Do(ctx, "HANG"); !errors.Is(err, context.Canceled) {
		t.Fatalf("want canceled, got %v", err)
	}
}

// New only parses, so a gateway can start before Redis does; commands then dial on demand.
func TestNewDoesNotConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listening yet
	c, err := New(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Do(context.Background(), "PING"); err == nil {
		t.Fatal("PING with no server must fail")
	}
	if _, err := Dial(addr); err == nil {
		t.Fatal("Dial still checks the server")
	}
	if _, err := New("http://x"); err == nil {
		t.Fatal("bad scheme must fail at New")
	}
}
