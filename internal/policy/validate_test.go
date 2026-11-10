package policy

import (
	"context"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/limiter"
)

func TestValidateMessages(t *testing.T) {
	rate := limiter.Rate{Limit: 5, Period: time.Second, Burst: 10}
	base := func() Config {
		return Config{Tiers: map[string]Tier{"free": {Rate: rate}}, Anonymous: "free"}
	}
	for _, c := range []struct {
		name string
		edit func(*Config)
		want []string
	}{
		{"valid", func(*Config) {}, nil},
		{"no routes or keys is fine", func(c *Config) { c.Routes, c.Keys = nil, nil }, nil},
		{"prefix without slash", func(c *Config) { c.Routes = []Route{{"v1", 1}} }, []string{`route "v1": prefix must start with /`}},
		{"empty prefix", func(c *Config) { c.Routes = []Route{{"", 1}} }, []string{"prefix must start with /"}},
		{"duplicate prefix", func(c *Config) { c.Routes = []Route{{"/a", 1}, {"/a", 2}} }, []string{`route "/a": duplicate prefix`}},
		{"negative cost", func(c *Config) { c.Routes = []Route{{"/a", -1}} }, []string{"cost must be >= 1"}},
		{"no tiers", func(c *Config) { c.Tiers = nil }, []string{"no tiers", `anonymous tier "free" not defined`}},
		{"limit too high", func(c *Config) {
			c.Tiers["free"] = Tier{Rate: limiter.Rate{Limit: 2e9, Period: time.Second, Burst: 10}}
		}, []string{"limit too high for period"}},
		{"negative burst", func(c *Config) {
			c.Tiers["free"] = Tier{Rate: limiter.Rate{Limit: 5, Period: time.Second, Burst: -1}}
		}, []string{"burst must be >= 0"}},
		{"negative monthly", func(c *Config) { c.Tiers["free"] = Tier{Rate: rate, Monthly: -1} }, []string{"monthly must be 0 (no cap)"}},
		{"monthly == cost is fine", func(c *Config) {
			c.Routes = []Route{{"/a", 3}}
			c.Tiers["free"] = Tier{Rate: rate, Monthly: 3}
		}, nil},
		{"empty key", func(c *Config) { c.Keys = map[string]Tenant{"": {ID: "a", Tier: "free"}} }, []string{"empty api key or tenant id"}},
		{"empty tenant id", func(c *Config) { c.Keys = map[string]Tenant{"k": {Tier: "free"}} }, []string{"empty api key or tenant id"}},
		{"no anonymous", func(c *Config) { c.Anonymous = "" }, []string{"anonymous tier must be set"}},
		{"every problem at once", func(c *Config) {
			c.Routes = []Route{{"x", 0}}
			c.Anonymous = "gold"
			c.Keys = map[string]Tenant{"k": {ID: "a", Tier: "gold"}}
		}, []string{"prefix must start with /", "cost must be >= 1", `anonymous tier "gold"`, `tenant "a": unknown tier "gold"`}},
	} {
		cfg := base()
		c.edit(&cfg)
		err := cfg.Validate()
		if (err == nil) != (c.want == nil) {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: %q lacks %q", c.name, err, w)
			}
		}
	}
}

// limiter.Rate treats burst 0 as "same as limit", so a tier may leave it out.
func TestOmittedBurstMeansLimit(t *testing.T) {
	if _, err := Parse([]byte(`{"tiers":{"free":{"rate":{"limit":5,"period":"1s"}}},"anonymous":"free"}`)); err != nil {
		t.Fatal(err)
	}
}

// Longest prefix wins whatever order the routes are listed in, matching whole segments only.
func TestRouteMatching(t *testing.T) {
	routes := []Route{{"/", 1}, {"/v1", 2}, {"/v1/generate", 5}, {"/v1/generate/batch", 9}, {"/static/", 3}}
	rng := rand.New(rand.NewPCG(3, 4))
	for range 20 {
		rng.Shuffle(len(routes), func(i, j int) { routes[i], routes[j] = routes[j], routes[i] })
		c := cfg()
		c.Routes = routes
		s := NewStore(c)
		for path, want := range map[string]int64{
			"/":                    1,
			"/v1":                  2,
			"/v1/":                 2,
			"/v1x":                 1,
			"/v1/generate":         5,
			"/v1/generate/":        5,
			"/v1/generated":        2,
			"/v1/generate/batch/7": 9,
			"/v1/generate/batchy":  5,
			"/static/app.js":       3,
			"/static":              1, // "/static/" needs the slash
			"":                     1,
			"/V1/generate":         1, // case-sensitive, like the mux
			"/v1//generate":        2,
		} {
			if got := s.Resolve("", path).Cost; got != want {
				t.Fatalf("order %v: %q cost %d, want %d", routes, path, got, want)
			}
		}
	}
	if got := NewStore(Config{Tiers: cfg().Tiers, Anonymous: "free"}).Resolve("", "/x").Cost; got != 1 {
		t.Fatalf("no routes: cost %d, want 1", got)
	}
}

func TestStoreIsolation(t *testing.T) {
	s := NewStore(cfg())
	c := s.Config()
	c.Tiers["free"] = Tier{}
	c.Routes[0].Cost = 99
	c.Keys["evil"] = Tenant{ID: "x", Tier: "pro"}
	if s.Resolve("", "/v1").Cost != 2 || s.Resolve("evil", "/").Tenant == "x" || s.Config().Tiers["free"].Monthly != 100 {
		t.Fatal("Config() shares the live config")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("NewStore must panic on an invalid config")
		}
	}()
	NewStore(Config{})
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	for _, bad := range []string{``, `{`, `{"tiers":{}} trailing`, `{"tiers":{"free":{"rate":{"limit":1,"period":"1s","burst":1},"montly":5}}},"anonymous":"free"}`} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}

// Hot reload: anything wrong with the file (gone, unparseable, invalid) keeps the live config and
// says why; the next good version is picked up.
func TestWatchKeepsLastGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.json")
	mtime := time.Unix(1000, 0)
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		mtime = mtime.Add(time.Second)
		os.Chtimes(path, mtime, mtime)
	}
	good := func(cost int) string {
		return `{"tiers":{"free":{"rate":{"limit":1,"period":"1s","burst":9}}},"anonymous":"free","routes":[{"prefix":"/a","cost":` + string(rune('0'+cost)) + `}]}`
	}
	write(good(1))
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	s := NewStore(c)
	write(good(2)) // edited between Load and Watch: the first tick must catch it

	errs := make(chan error, 100)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Watch(ctx, path, 2*time.Millisecond, func(e error) { errs <- e }); close(done) }()
	defer func() { cancel(); <-done }()
	waitFor(t, func() bool { return s.Resolve("", "/a").Cost == 2 })

	expectErr := func(what string, is func(error) bool) {
		t.Helper()
		deadline := time.After(2 * time.Second)
		for {
			select {
			case err := <-errs:
				if is(err) {
					if got := s.Resolve("", "/a").Cost; got != 2 {
						t.Fatalf("%s replaced the config: cost %d", what, got)
					}
					return
				}
			case <-deadline:
				t.Fatalf("%s: no error reported", what)
			}
		}
	}
	os.Remove(path)
	expectErr("deleted file", func(err error) bool { return errors.Is(err, os.ErrNotExist) })
	write(`{"tiers":`)
	expectErr("truncated JSON", func(err error) bool { return strings.Contains(err.Error(), "policy:") })
	write(strings.Replace(good(5), `"burst":9`, `"burst":4`, 1))
	expectErr("invalid policy", func(err error) bool { return strings.Contains(err.Error(), "burst 4 < max route cost 5") })

	// An invalid file is reported once, not on every tick.
	time.Sleep(20 * time.Millisecond)
	for len(errs) > 0 {
		<-errs
	}
	time.Sleep(20 * time.Millisecond)
	if n := len(errs); n != 0 {
		t.Fatalf("unchanged invalid file reported %d more times", n)
	}
	write(good(7))
	waitFor(t, func() bool { return s.Resolve("", "/a").Cost == 7 })

	// Same mtime (coarse clocks, cp -p) but a different size still reloads.
	os.WriteFile(path, []byte(good(8)+"\n\n"), 0o600)
	os.Chtimes(path, mtime, mtime)
	waitFor(t, func() bool { return s.Resolve("", "/a").Cost == 8 })
}
