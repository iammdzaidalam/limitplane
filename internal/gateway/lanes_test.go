package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/policy"
	"github.com/iammdzaidalam/limitplane/internal/redisx"
)

// lanePolicy: burst 10 at 1/hour, so a run of requests measures the burst alone.
func lanePolicy(key string) *policy.Store {
	return policy.NewStore(policy.Config{
		Tiers: map[string]policy.Tier{"free": {
			Rate:    limiter.Rate{Limit: 1, Period: time.Hour, Burst: 10},
			Monthly: 1000,
			Lanes:   map[string]float64{"human": 2, "retry_bug": 0.25, "crawler": 0.1},
		}},
		Routes:    []policy.Route{{Prefix: "/v1/generate", Cost: 5}},
		Keys:      map[string]policy.Tenant{key: {ID: key, Tier: "free"}},
		Anonymous: "free",
	})
}

// recordingMeter keeps the last request it was asked about.
type recordingMeter struct {
	limiter.Meter
	last limiter.Request
}

func (m *recordingMeter) Check(ctx context.Context, q limiter.Request) (limiter.Result, error) {
	m.last = q
	return m.Meter.Check(ctx, q)
}

// Only the burst moves: rate, period and the monthly cap reach the backend untouched.
func TestLaneScalesBurstOnly(t *testing.T) {
	for _, c := range []struct {
		lane  policy.Lane
		path  string
		burst int64
	}{
		{policy.LaneWarming, "/", 10}, // not listed: the tier's burst
		{policy.LaneBot, "/", 10},
		{policy.LaneHuman, "/", 20},
		{policy.LaneRetryBug, "/", 3},            // round(2.5)
		{policy.LaneCrawler, "/", 1},             // 10 x 0.1
		{policy.LaneCrawler, "/v1/generate", 5},  // never below one request's cost
		{policy.LaneRetryBug, "/v1/generate", 5}, // 3 < cost 5
		{policy.LaneHuman, "/v1/generate/x", 20}, // cost doesn't scale either
	} {
		m := &recordingMeter{Meter: limiter.NewMemory()}
		g := New(Config{Policy: lanePolicy("k1"), Meter: m, Lane: func(string) policy.Lane { return c.lane }})
		r := httptest.NewRequest("GET", c.path, nil)
		r.Header.Set(KeyHeader, "k1")
		d, _ := g.Check(r, r.Method, r.URL.Path)
		want := limiter.Rate{Limit: 1, Period: time.Hour, Burst: c.burst}
		if m.last.Rate != want || m.last.Month != 1000 || d.Lane != c.lane.String() || d.Limit != c.burst {
			t.Errorf("%s %s: sent %+v month %d, decision lane %q limit %d", c.lane, c.path, m.last.Rate, m.last.Month, d.Lane, d.Limit)
		}
	}
}

func TestLanesOffByDefault(t *testing.T) {
	m := &recordingMeter{Meter: limiter.NewMemory()}
	called := false
	g := New(Config{Policy: testPolicy(), Meter: m, Lane: func(string) policy.Lane { called = true; return policy.LaneHuman }})
	r := httptest.NewRequest("GET", "/", nil)
	if d, _ := g.Check(r, "GET", "/"); called || d.Lane != "" || m.last.Rate.Burst != 10 {
		t.Fatalf("tier without lanes: lookup %v, lane %q, burst %d", called, d.Lane, m.last.Rate.Burst)
	}
}

type downBackend struct{ limiter.Backend }

var errDown = errors.New("down")

func (downBackend) Check(context.Context, limiter.Request) (limiter.Result, error) {
	return limiter.Result{}, errDown
}

// The same lane admits the same number of requests in memory, in the local fallback while the
// shared store is down (split across replicas like any burst), and on Redis when one is given.
func TestLaneBackends(t *testing.T) {
	backends := map[string]func(t *testing.T) (limiter.Meter, int){
		"memory": func(*testing.T) (limiter.Meter, int) { return limiter.NewMemory(), 1 },
		"fallback, 2 replicas": func(*testing.T) (limiter.Meter, int) {
			return limiter.NewFallback(downBackend{limiter.NewMemory()}, limiter.NewMemory(), func() int { return 2 }), 2
		},
	}
	if addr := os.Getenv("LIMITPLANE_REDIS"); addr != "" {
		backends["redis"] = func(t *testing.T) (limiter.Meter, int) {
			c, err := redisx.New(addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close() })
			return limiter.NewRedis(c, nil), 1
		}
	}
	for name, mk := range backends {
		t.Run(name, func(t *testing.T) {
			for _, c := range []struct {
				lane policy.Lane
				want int // of 30 back-to-back requests, at 1/hour
			}{{policy.LaneHuman, 20}, {policy.LaneBot, 10}, {policy.LaneRetryBug, 3}} {
				meter, n := mk(t)
				key := "lanes-" + strconv.FormatInt(time.Now().UnixNano(), 36)
				g := New(Config{Policy: lanePolicy(key), Meter: meter, Lane: func(string) policy.Lane { return c.lane }})
				ok := 0
				for range 30 {
					r := httptest.NewRequest("GET", "/", nil)
					r.Header.Set(KeyHeader, key)
					if d, _ := g.Check(r, "GET", "/"); d.Allowed {
						ok++
					}
				}
				if want := max(c.want/n, 1); ok != want {
					t.Errorf("%s: admitted %d of 30, want %d", c.lane, ok, want)
				}
			}
		})
	}
}

// Clients of one tenant in different lanes share its bucket. Whatever the mix, the tenant never gets
// more than rate x time plus the largest lane's burst: GCRA spends interval per unit in every lane.
func TestLanesNeverExceedRate(t *testing.T) {
	s := policy.NewStore(policy.Config{
		Tiers: map[string]policy.Tier{"t": {
			Rate:  limiter.Rate{Limit: 1000, Period: time.Second, Burst: 10},
			Lanes: map[string]float64{"human": 4, "retry_bug": 0.1},
		}},
		Keys:      map[string]policy.Tenant{"k": {ID: "shared", Tier: "t"}},
		Anonymous: "t",
	})
	lanes := []policy.Lane{policy.LaneHuman, policy.LaneRetryBug, policy.LaneBot}
	i := 0
	g := New(Config{Policy: s, Meter: limiter.NewMemory(), Lane: func(string) policy.Lane { i++; return lanes[i%3] }})
	start, ok := time.Now(), 0
	for time.Since(start) < 200*time.Millisecond {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set(KeyHeader, "k")
		if d, _ := g.Check(r, "GET", "/"); d.Allowed {
			ok++
		}
	}
	if bound := int(time.Since(start).Milliseconds()) + 1 + 40; ok > bound || ok < 100 {
		t.Fatalf("admitted %d, want at most %d (1/ms + burst 40)", ok, bound)
	}
}

func BenchmarkMiddlewareLanes(b *testing.B) {
	g := New(Config{Policy: lanePolicy("k1"), Meter: nopMeter{}, OnDecision: func(Decision) {},
		Lane: func(string) policy.Lane { return policy.LaneHuman }})
	h := g.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	r := httptest.NewRequest("GET", "/v1/generate", nil)
	r.Header.Set(KeyHeader, "k1")
	w := httptest.NewRecorder()
	b.ReportAllocs()
	for b.Loop() {
		h.ServeHTTP(w, r)
	}
}
