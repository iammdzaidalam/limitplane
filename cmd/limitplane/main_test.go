package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/limiter"
)

func TestDefaultConfigParses(t *testing.T) {
	if _, err := loadConfig(""); err != nil {
		t.Fatal(err)
	}
}

func TestProxyForwardedFor(t *testing.T) {
	got := make(chan string, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("X-Forwarded-For")
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)

	for _, tc := range []struct {
		trust bool
		want  string
	}{
		{false, "127.0.0.1"},         // spoofed header dropped
		{true, "6.6.6.6, 127.0.0.1"}, // trusted chain appended to
	} {
		ts := httptest.NewServer(proxy(u, tc.trust))
		req, _ := http.NewRequest("GET", ts.URL+"/x", nil)
		req.Header.Set("X-Forwarded-For", "6.6.6.6")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		ts.Close()
		if xff := <-got; xff != tc.want {
			t.Errorf("trust=%v: XFF %q, want %q", tc.trust, xff, tc.want)
		}
	}
}

// Redis that isn't there at startup (e.g. DNS not ready yet): start degraded instead of exiting.
func TestStartWithoutRedis(t *testing.T) {
	q := limiter.Request{Client: "192.0.2.1", Key: "acme", Rate: limiter.Rate{Limit: 10, Period: time.Second, Burst: 30}, Cost: 1}
	lim, red, err := newBackend("redis://127.0.0.1:1", false, func() int { return 3 })
	if err != nil || red == nil {
		t.Fatalf("must start without Redis: %v", err)
	}
	defer red.Close()
	admitted := 0
	for range 20 {
		res, err := lim.Check(context.Background(), q)
		if err != nil || !res.Degraded {
			t.Fatalf("%+v %v", res, err)
		}
		if res.Allowed {
			admitted++
		}
	}
	if admitted != 10 { // burst 30 split over 3 replicas
		t.Fatalf("admitted %d, want 10", admitted)
	}

	closed, red2, err := newBackend("redis://127.0.0.1:1", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer red2.Close()
	if _, err := closed.Check(context.Background(), q); err == nil {
		t.Fatal("fail-closed must surface the Redis error (the gateway turns it into 503)")
	}
	if _, _, err := newBackend("http://nope", false, nil); err == nil {
		t.Fatal("a bad URL is still a startup error")
	}
}
