package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

func TestEnvHelpers(t *testing.T) {
	t.Setenv("LP_TEST_S", "")
	t.Setenv("LP_TEST_N", "")
	if env("LP_TEST_S", "d") != "d" || envInt("LP_TEST_N", 3) != 3 {
		t.Fatal("unset must give the default")
	}
	t.Setenv("LP_TEST_S", "v")
	t.Setenv("LP_TEST_N", "7")
	if env("LP_TEST_S", "d") != "v" || envInt("LP_TEST_N", 3) != 7 {
		t.Fatal("set must win")
	}
	t.Setenv("LP_TEST_N", "seven")
	if envInt("LP_TEST_N", 3) != 3 {
		t.Fatal("garbage must give the default")
	}
}

const testPolicy = `{"tiers":{"free":{"rate":{"limit":5,"period":"1s","burst":BURST}}},"anonymous":"free"}`

func writePolicy(t *testing.T, path, burst string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Replace(testPolicy, "BURST", burst, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.json")
	writePolicy(t, path, "7")
	if c, err := loadConfig(path); err != nil || c.Tiers["free"].Rate.Burst != 7 {
		t.Fatalf("%+v %v", c, err)
	}
	writePolicy(t, path, "-1")
	if _, err := loadConfig(path); err == nil {
		t.Fatal("invalid file must fail at startup")
	}
	if _, err := loadConfig(path + ".missing"); err == nil {
		t.Fatal("missing file must fail at startup")
	}
}

func TestNewBackendMemory(t *testing.T) {
	for _, failClosed := range []bool{false, true} {
		b, red, err := newBackend("", failClosed, nil)
		if _, ok := b.(*limiter.Memory); err != nil || red != nil || !ok {
			t.Fatalf("no Redis URL must mean in-process limits: %T %v %v", b, red, err)
		}
	}
}

// runWith runs the command with args, as if from the shell, with the env it reads cleared. It
// listens on a random loopback port unless args say otherwise, and a bad flag is an error
// instead of the os.Exit the real binary does.
func runWith(t *testing.T, args ...string) (err error) {
	for _, k := range []string{"PORT", "REDIS_URL", "LIMITPLANE_ADMIN_KEY", "LIMITPLANE_METRICS_KEY", "LIMITPLANE_KUBE", "LIMITPLANE_REPLICAS", "LIMITPLANE_AUTHZ_ADDR", "KUBERNETES_SERVICE_HOST"} {
		t.Setenv(k, "")
	}
	oldArgs, oldFlags := os.Args, flag.CommandLine
	t.Cleanup(func() { os.Args, flag.CommandLine = oldArgs, oldFlags })
	os.Args = append([]string{"limitplane", "-addr", "127.0.0.1:0", "-admin-key", "test"}, args...)
	flag.CommandLine = flag.NewFlagSet("limitplane", flag.PanicOnError)
	flag.CommandLine.SetOutput(io.Discard)
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	return run()
}

// Startup mistakes are errors before anything listens.
func TestRunRejectsBadFlags(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.json")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"-config", missing}, "no such file"},
		{[]string{"-redis", "memcached://x"}, "redis:"},
		{[]string{"-upstream", "localhost:9000"}, "bad --upstream"}, // no scheme
		{[]string{"-upstream", "http://"}, "bad --upstream"},
		{[]string{"-kube"}, "not running in a cluster"},
		{[]string{"-addr", "256.0.0.1:1"}, "256.0.0.1"},
		{[]string{"-no-such-flag"}, "not defined"},
	} {
		errc := make(chan error, 1)
		go func() { errc <- runWith(t, c.args...) }()
		var err error
		select {
		case err = <-errc:
		case <-time.After(5 * time.Second):
			t.Fatalf("%v: still running, want a startup error", c.args)
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v, want %q", c.args, err, c.want)
		}
	}
}

func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// The whole binary: serve, reload the policy on SIGHUP, shut down cleanly on SIGTERM.
func TestRunServesReloadsAndStops(t *testing.T) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP) // so an early SIGHUP can never kill the test binary
	defer signal.Stop(hup)
	path := filepath.Join(t.TempDir(), "p.json")
	writePolicy(t, path, "10")
	addr := freeAddr(t)
	errc := make(chan error, 1)
	go func() { errc <- runWith(t, "-addr", addr, "-config", path) }()

	burst := func() string {
		res, err := http.Get("http://" + addr + "/v1/ping")
		if err != nil {
			return ""
		}
		res.Body.Close()
		return res.Header.Get("Ratelimit-Limit")
	}
	deadline := time.Now().Add(5 * time.Second)
	for burst() != "10" {
		if time.Now().After(deadline) {
			t.Fatal("server never answered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	writePolicy(t, path, "20")
	for burst() != "20" { // SIGHUP, or the 2s file watch if it gets there first
		if time.Now().After(deadline) {
			t.Fatal("policy never reloaded")
		}
		syscall.Kill(os.Getpid(), syscall.SIGHUP)
		time.Sleep(20 * time.Millisecond)
	}
	syscall.Kill(os.Getpid(), syscall.SIGTERM) // run's NotifyContext is in place: it's serving
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("clean shutdown returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no shutdown after SIGTERM")
	}
	if _, err := http.Get("http://" + addr + "/healthz"); err == nil {
		t.Fatal("still listening after shutdown")
	}
}

// A SIGHUP with a broken file keeps the running policy.
func TestReloadOnHUPKeepsLastGood(t *testing.T) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	path := filepath.Join(t.TempDir(), "p.json")
	writePolicy(t, path, "10")
	c, _ := loadConfig(path)
	store := policy.NewStore(c)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { reloadOnHUP(ctx, store, path); close(done) }()
	defer func() { cancel(); <-done }()

	writePolicy(t, path, "-1") // invalid
	for range 5 {
		syscall.Kill(os.Getpid(), syscall.SIGHUP)
		time.Sleep(10 * time.Millisecond)
	}
	if b := store.Config().Tiers["free"].Rate.Burst; b != 10 {
		t.Fatalf("invalid file replaced the policy: burst %d", b)
	}
	writePolicy(t, path, "30")
	for deadline := time.Now().Add(2 * time.Second); store.Config().Tiers["free"].Rate.Burst != 30; {
		if time.Now().After(deadline) {
			t.Fatal("valid file never loaded")
		}
		syscall.Kill(os.Getpid(), syscall.SIGHUP)
		time.Sleep(10 * time.Millisecond)
	}
}

// Kubernetes Events are queued off the request path and dropped, not waited for, when the queue is full.
func TestOperatorSendNeverBlocks(t *testing.T) {
	o := &operator{events: make(chan func(context.Context), 2)}
	done := make(chan struct{})
	go func() {
		for range 10 {
			o.send(func(context.Context) {})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("send blocked on a full queue")
	}
	if len(o.events) != 2 {
		t.Fatalf("%d queued", len(o.events))
	}
}

func TestSyncRedisStops(t *testing.T) {
	_, red, err := newBackend("redis://127.0.0.1:1", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer red.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { syncRedis(ctx, red, false); close(done) }()
	time.Sleep(20 * time.Millisecond) // one failed sync against nothing
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("syncRedis ignored its context")
	}
}
