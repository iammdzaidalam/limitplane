package redisx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var bg = context.Background()

// enc writes v as RESP: int, string (bulk), []any.
func enc(v any) string {
	switch v := v.(type) {
	case int:
		return fmt.Sprintf(":%d\r\n", v)
	case string:
		return fmt.Sprintf("$%d\r\n%s\r\n", len(v), v)
	case []any:
		s := fmt.Sprintf("*%d\r\n", len(v))
		for _, x := range v {
			s += enc(x)
		}
		return s
	}
	panic(fmt.Sprintf("enc %T", v))
}

func hostPort(f *fake) (string, int) {
	a := f.ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

// slots builds a CLUSTER SLOTS reply from start, end, owner triples.
func slots(rs ...any) string {
	var rows []any
	for i := 0; i < len(rs); i += 3 {
		h, p := hostPort(rs[i+2].(*fake))
		rows = append(rows, []any{rs[i], rs[i+1], []any{h, p, "id" + strconv.Itoa(p)}})
	}
	return enc(rows)
}

func count(f *fake, cmd string) int {
	n := 0
	for _, c := range f.log() {
		if c == cmd {
			n++
		}
	}
	return n
}

// keyIn finds a key whose slot is in [lo, hi].
func keyIn(lo, hi int) string {
	for i := 0; ; i++ {
		k := "k" + strconv.Itoa(i)
		if s := Slot(k); s >= lo && s <= hi {
			return k
		}
	}
}

// Vectors from the Redis Cluster spec and CLUSTER KEYSLOT docs.
func TestSlot(t *testing.T) {
	if got := crc16("123456789"); got != 0x31C3 {
		t.Fatalf("crc16 = %#x, want 0x31C3", got)
	}
	for key, want := range map[string]int{
		"123456789": 0x31C3, "somekey": 11058, "foo{hash_tag}": 2515, "foo": 12182, "": 0,
		"{user1000}.following": 3443, // checked against CLUSTER KEYSLOT on redis 7
	} {
		if got := Slot(key); got != want {
			t.Errorf("Slot(%q) = %d, want %d", key, got, want)
		}
	}
	same := [][2]string{
		{"{user1000}.following", "{user1000}.followers"},
		{"{user1000}.following", "user1000"},
		{"foo{{bar}}zap", "{bar"},       // tag is "{bar"
		{"foo{bar}{zap}", "bar"},        // first tag only
		{"foo{}{bar}", "foo{}{bar}"},    // empty tag: whole key
		{"lp:{acme}:r", "lp:{acme}:q:"}, // a tenant's keys
	}
	for _, p := range same {
		if Slot(p[0]) != Slot(p[1]) {
			t.Errorf("%q and %q should share a slot", p[0], p[1])
		}
	}
	if Slot("foo{}{bar}") == Slot("bar") || Slot("foo{") != int(crc16("foo{")&16383) {
		t.Error("an empty or unclosed tag must hash the whole key")
	}
}

func TestParseSlots(t *testing.T) {
	v := []any{
		[]any{int64(0), int64(5460), []any{"10.0.0.1", int64(6379), "a"}, []any{"10.0.0.4", int64(6379), "d"}},
		[]any{int64(5461), int64(10922), []any{"", int64(6380), "b"}},
		[]any{int64(10923), int64(16383), []any{"?", int64(6381), "c"}},
	}
	got, err := parseSlots(v, "10.0.0.9")
	want := []slotRange{{0, 5460, "10.0.0.1:6379"}, {5461, 10922, "10.0.0.9:6380"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v %v", got, err)
	}
	for _, bad := range []any{
		"x", []any{}, []any{[]any{int64(0)}},
		[]any{[]any{int64(5), int64(1), []any{"h", int64(1)}}},
		[]any{[]any{int64(0), int64(16384), []any{"h", int64(1)}}},
		[]any{[]any{int64(0), int64(1), []any{"h", "port"}}},
	} {
		if _, err := parseSlots(bad, "h"); err == nil {
			t.Errorf("%v: want error", bad)
		}
	}
}

func TestParseURL(t *testing.T) {
	c, err := New("redis+cluster://:pw@h1:7001,h2")
	if err != nil || c.node != nil || c.pass != "pw" || c.tls != nil {
		t.Fatalf("%+v %v", c, err)
	}
	var addrs []string
	for _, n := range c.cluster.all() {
		addrs = append(addrs, n.addr)
	}
	slices.Sort(addrs)
	if !reflect.DeepEqual(addrs, []string{"h1:7001", "h2:6379"}) {
		t.Fatalf("seeds %v", addrs)
	}
	c, err = New("rediss+cluster://u:p@[::1]:7000,10.0.0.2")
	if err != nil || c.tls == nil || c.user != "u" || len(c.cluster.all()) != 2 {
		t.Fatalf("%+v %v", c, err)
	}
	c, err = New("redis://:pw@host")
	if err != nil || c.node.addr != "host:6379" || c.cluster != nil {
		t.Fatalf("%+v %v", c, err)
	}
	for _, bad := range []string{"redis+cluster://h1/2", "redis://h1,h2", "redis+cluster://", "mongodb://h"} {
		if _, err := New(bad); err == nil {
			t.Errorf("%s: want error", bad)
		}
	}
}

// MOVED: follow it, remember the new owner, and refresh the map in the background.
func TestClusterMoved(t *testing.T) {
	var a, b *fake
	var mu sync.Mutex
	moved := false
	layout := func() string {
		mu.Lock()
		defer mu.Unlock()
		if moved {
			return slots(0, 16383, b)
		}
		return slots(0, 16383, a)
	}
	b = newFake(t, func(args []string) string {
		if args[0] == "CLUSTER" {
			return layout()
		}
		return "$1\r\nv\r\n"
	})
	a = newFake(t, func(args []string) string {
		if args[0] == "CLUSTER" {
			return layout()
		}
		mu.Lock()
		moved = true
		mu.Unlock()
		return fmt.Sprintf("-MOVED %d %s\r\n", Slot(args[1]), b.ln.Addr())
	})
	c, err := Dial("redis+cluster://" + a.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for range 3 {
		if v, err := c.Do(bg, "GET", "k"); err != nil || v != "v" {
			t.Fatalf("got %v %v", v, err)
		}
	}
	if count(a, "GET k") != 1 || count(b, "GET k") != 3 {
		t.Fatalf("a %q b %q", a.log(), b.log())
	}
	deadline := time.Now().Add(time.Second)
	for count(a, "CLUSTER SLOTS")+count(b, "CLUSTER SLOTS") < 2 { // Dial's, then the background one
		if time.Now().After(deadline) {
			t.Fatal("MOVED did not refresh the slot map")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ASK: retry once on the target with ASKING first, and keep the map (the slot is mid-migration).
func TestClusterAsk(t *testing.T) {
	var a, b *fake
	asked := false
	b = newFake(t, func(args []string) string {
		switch args[0] {
		case "ASKING":
			asked = true
			return "+OK\r\n"
		case "GET":
			if !asked {
				return fmt.Sprintf("-MOVED %d %s\r\n", Slot(args[1]), a.ln.Addr())
			}
			asked = false
			return "$3\r\nnew\r\n"
		}
		return "-ERR\r\n"
	})
	a = newFake(t, func(args []string) string {
		if args[0] == "CLUSTER" {
			return slots(0, 16383, a)
		}
		return fmt.Sprintf("-ASK %d %s\r\n", Slot(args[1]), b.ln.Addr())
	})
	c, err := Dial("redis+cluster://" + a.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for range 2 {
		if v, err := c.Do(bg, "GET", "k"); err != nil || v != "new" {
			t.Fatalf("got %v %v", v, err)
		}
	}
	if got := b.log(); !reflect.DeepEqual(got, []string{"ASKING", "GET k", "ASKING", "GET k"}) {
		t.Fatalf("b %q", got)
	}
	if count(a, "GET k") != 2 {
		t.Fatalf("ASK must not move the slot: a %q", a.log())
	}
}

func TestClusterRedirectLimit(t *testing.T) {
	var a, b *fake
	a = newFake(t, func(args []string) string {
		if args[0] == "CLUSTER" {
			return slots(0, 16383, a)
		}
		return fmt.Sprintf("-MOVED %d %s\r\n", Slot(args[1]), b.ln.Addr())
	})
	b = newFake(t, func(args []string) string {
		return fmt.Sprintf("-MOVED %d %s\r\n", Slot(args[1]), a.ln.Addr())
	})
	c, err := Dial("redis+cluster://" + a.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Do(bg, "GET", "k"); !errors.Is(err, ErrNodeDown) || !strings.Contains(err.Error(), "redirects") {
		t.Fatalf("want bounded redirects, got %v", err)
	}
	if n := count(a, "GET k") + count(b, "GET k"); n != maxRedirects+1 {
		t.Fatalf("%d tries, want %d", n, maxRedirects+1)
	}
}

// Each node loads a script the first time a key routes there.
func TestClusterNoScriptPerNode(t *testing.T) {
	var a, b *fake
	layout := func() string { return slots(0, 8191, a, 8192, 16383, b) }
	node := func() func(args []string) string {
		var mu sync.Mutex
		loaded := false
		return func(args []string) string {
			mu.Lock()
			defer mu.Unlock()
			switch args[0] {
			case "CLUSTER":
				return layout()
			case "EVALSHA":
				if !loaded {
					return "-NOSCRIPT No matching script\r\n"
				}
			case "EVAL":
				loaded = true
			}
			return ":1\r\n"
		}
	}
	a, b = newFake(t, node()), newFake(t, node())
	c, err := Dial("redis+cluster://" + a.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s := NewScript("return 1")
	ka, kb := keyIn(0, 8191), keyIn(8192, 16383)
	for range 2 {
		for _, k := range []string{ka, kb} {
			if v, err := c.Eval(bg, s, []string{k}); err != nil || v != int64(1) {
				t.Fatalf("%s: %v %v", k, v, err)
			}
		}
	}
	for f, k := range map[*fake]string{a: ka, b: kb} {
		sha, ev := "EVALSHA "+s.sha+" 1 "+k, "EVAL return 1 1 "+k
		if count(f, sha) != 2 || count(f, ev) != 1 {
			t.Fatalf("%s: %q", k, f.log())
		}
	}
}

// A dead master fails its slots fast with ErrNodeDown; the other node keeps serving.
func TestClusterNodeDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := &fake{ln: ln}
	ln.Close()
	var a *fake
	a = newFake(t, func(args []string) string {
		if args[0] == "CLUSTER" {
			return slots(0, 8191, a, 8192, 16383, dead)
		}
		return "+OK\r\n"
	})
	c, err := Dial("redis+cluster://" + a.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	kd := keyIn(8192, 16383)
	if _, err := c.Do(bg, "GET", kd); !errors.Is(err, ErrNodeDown) {
		t.Fatalf("want ErrNodeDown, got %v", err)
	}
	start := time.Now()
	if _, err := c.Do(bg, "GET", kd); !errors.Is(err, ErrNodeDown) || time.Since(start) > 50*time.Millisecond {
		t.Fatalf("second call must fail fast: %v after %v", err, time.Since(start))
	}
	if v, err := c.Do(bg, "GET", keyIn(0, 8191)); err != nil || v != "OK" {
		t.Fatalf("live node: %v %v", v, err)
	}
}

func TestSubscribe(t *testing.T) {
	f := newFake(t, func(args []string) string {
		switch args[0] {
		case "SUBSCRIBE":
			return enc([]any{"subscribe", args[1], 1}) + enc([]any{"message", args[1], "hello"})
		case "PING":
			return enc([]any{"pong", ""})
		}
		return "-ERR\r\n"
	})
	c, err := New(f.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sub, err := c.Subscribe(bg, "ch")
	if err != nil {
		t.Fatal(err)
	}
	if m, err := sub.Receive(time.Second); err != nil || m != (Message{"message", "ch", "hello"}) {
		t.Fatalf("got %+v %v", m, err)
	}
	if _, err := sub.Receive(30 * time.Millisecond); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("want timeout, got %v", err)
	}
	if err := sub.Ping(); err != nil {
		t.Fatal(err)
	}
	if m, err := sub.Receive(time.Second); err != nil || m.Kind != "pong" {
		t.Fatalf("got %+v %v", m, err)
	}
	sub.Close()
	if _, err := sub.Receive(time.Second); err == nil {
		t.Fatal("closed sub must error")
	}
}

// The routing a Cluster adds to every metered request: find the key, hash its tag.
func BenchmarkRoute(b *testing.B) {
	args := []any{"EVALSHA", "0123456789abcdef0123456789abcdef01234567", 2, "lp:{acme}:r", "lp:{acme}:q:", int64(100000), int64(5), int64(1), int64(0)}
	b.ReportAllocs()
	for b.Loop() {
		k, _ := firstKey(args)
		_ = Slot(k)
	}
}
