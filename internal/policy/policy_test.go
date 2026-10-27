package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/limiter"
)

func cfg() Config {
	r := func(l, b int64) limiter.Rate { return limiter.Rate{Limit: l, Period: time.Second, Burst: b} }
	return Config{
		Tiers:     map[string]Tier{"free": {Rate: r(5, 10), Monthly: 100}, "pro": {Rate: r(50, 100)}},
		Routes:    []Route{{"/v1", 2}, {"/v1/generate", 5}, {"/healthz", 1}},
		Keys:      map[string]Tenant{"k1": {ID: "acme", Tier: "pro"}},
		Anonymous: "free",
	}
}

func TestExampleConfigParses(t *testing.T) {
	c, err := Load("../../limitplane.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if c.Tiers["pro"].Rate.Period != time.Second {
		t.Fatalf("period not parsed: %+v", c.Tiers["pro"])
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":  `{"tiers":{"free":{"rate":{"limit":1,"period":"1s","burst":1}}},"anonymous":"free","oops":1}`,
		"no anonymous":   `{"tiers":{"free":{"rate":{"limit":1,"period":"1s","burst":1}}}}`,
		"zero limit":     `{"tiers":{"free":{"rate":{"limit":0,"period":"1s","burst":1}}},"anonymous":"free"}`,
		"zero period":    `{"tiers":{"free":{"rate":{"limit":1,"period":"0s","burst":1}}},"anonymous":"free"}`,
		"burst < cost":   `{"tiers":{"free":{"rate":{"limit":1,"period":"1s","burst":2}}},"routes":[{"prefix":"/a","cost":5}],"anonymous":"free"}`,
		"cost 0":         `{"tiers":{"free":{"rate":{"limit":1,"period":"1s","burst":2}}},"routes":[{"prefix":"/a","cost":0}],"anonymous":"free"}`,
		"unknown tier":   `{"tiers":{"free":{"rate":{"limit":1,"period":"1s","burst":2}}},"keys":{"k":{"id":"x","tier":"gold"}},"anonymous":"free"}`,
		"monthly < cost": `{"tiers":{"free":{"rate":{"limit":1,"period":"1s","burst":9},"monthly":3}},"routes":[{"prefix":"/a","cost":5}],"anonymous":"free"}`,
	}
	for name, js := range cases {
		if _, err := Parse([]byte(js)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestResolve(t *testing.T) {
	s := NewStore(cfg())
	cases := []struct {
		key, path    string
		tenant, tier string
		cost         int64
		anon         bool
	}{
		{"k1", "/v1/generate/x", "acme", "pro", 5, false},
		{"k1", "/v1/embed", "acme", "pro", 2, false},
		{"k1", "/other", "acme", "pro", 1, false},
		{"nope", "/healthz", AnonTenant, "free", 1, true},
		{"", "/v1", AnonTenant, "free", 2, true},
	}
	for _, c := range cases {
		m := s.Resolve(c.key, c.path)
		if m.Tenant != c.tenant || m.Tier != c.tier || m.Cost != c.cost || m.Anon != c.anon {
			t.Errorf("Resolve(%q,%q) = %+v", c.key, c.path, m)
		}
	}
	if m := s.Resolve("nope", "/"); m.Month != 100 || m.Rate.Burst != 10 {
		t.Errorf("anon tier limits not copied: %+v", m)
	}
	if n := testing.AllocsPerRun(100, func() { s.Resolve("k1", "/v1/generate") }); n != 0 {
		t.Errorf("Resolve allocs = %v", n)
	}
}

func TestSwapIsolatedAndValidated(t *testing.T) {
	c := cfg()
	s := NewStore(c)
	c.Keys["k2"] = Tenant{ID: "evil", Tier: "pro"} // caller mutation must not leak in
	if s.Resolve("k2", "/").Anon != true {
		t.Fatal("store shares caller's map")
	}
	bad := cfg()
	bad.Anonymous = "missing"
	if s.Swap(bad) == nil {
		t.Fatal("swap accepted invalid config")
	}
	if s.Config().Anonymous != "free" {
		t.Fatal("invalid swap replaced config")
	}
}

func TestConcurrentSwapResolve(t *testing.T) {
	s := NewStore(cfg())
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 1000 {
				s.Resolve("k1", "/v1/generate")
			}
		})
	}
	for range 100 {
		if err := s.Swap(cfg()); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestWatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.json")
	write := func(s string, mt time.Time) {
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		os.Chtimes(path, mt, mt) // explicit mtime: coarse filesystem clocks would hide the change
	}
	base := `{"tiers":{"free":{"rate":{"limit":1,"period":"1s","burst":5}}},"anonymous":"free","routes":[{"prefix":"/a","cost":COST}]}`
	write(strings.Replace(base, "COST", "1", 1), time.Unix(1000, 0))
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	s := NewStore(c)
	errs := make(chan error, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Watch(ctx, path, 5*time.Millisecond, func(e error) { errs <- e })

	write(strings.Replace(base, "COST", "3", 1), time.Unix(2000, 0))
	waitFor(t, func() bool { return s.Resolve("", "/a").Cost == 3 })

	write(strings.Replace(base, "COST", "9", 1), time.Unix(3000, 0)) // burst 5 < cost 9: invalid
	select {
	case <-errs:
	case <-time.After(2 * time.Second):
		t.Fatal("no error reported for invalid file")
	}
	if got := s.Resolve("", "/a").Cost; got != 3 {
		t.Fatalf("invalid file replaced config, cost=%d", got)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatal("condition not met")
}
