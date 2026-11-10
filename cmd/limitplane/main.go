// Command limitplane meters traffic in front of an upstream, or serves a demo app.
package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/ai"
	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/org"
	"github.com/iammdzaidalam/limitplane/internal/policy"
	"github.com/iammdzaidalam/limitplane/internal/redisx"
	"github.com/iammdzaidalam/limitplane/internal/server"
	"github.com/iammdzaidalam/limitplane/web"
)

//go:embed default.json
var defaultConfig []byte

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	port := env("PORT", "8080")
	addr := flag.String("addr", ":"+port, "listen address")
	authzAddr := flag.String("authz-addr", os.Getenv("LIMITPLANE_AUTHZ_ADDR"), "forward-auth listener for Envoy, nginx and Traefik, e.g. :9091 (empty: off); reachable only by the proxies")
	upstream := flag.String("upstream", "", "proxy to this URL (empty: demo app)")
	cfgPath := flag.String("config", "", "policy JSON file (empty: built-in demo policy)")
	redisURL := flag.String("redis", os.Getenv("REDIS_URL"), "shared Redis, e.g. redis://:pass@host:6379, or a Cluster: redis+cluster://:pass@h1:6379,h2:6379")
	adminKey := flag.String("admin-key", os.Getenv("LIMITPLANE_ADMIN_KEY"), "dashboard/API key (empty: random, printed once)")
	metricsKey := flag.String("metrics-key", os.Getenv("LIMITPLANE_METRICS_KEY"), "bearer key for /metrics (empty: public)")
	trust := flag.Bool("trust-proxy", false, "trust X-Forwarded-For (only behind a proxy you control)")
	failClosed := flag.Bool("fail-closed", false, "return 503 when the shared backend is down instead of falling back to local limits")
	kubeMode := flag.Bool("kube", os.Getenv("LIMITPLANE_KUBE") == "1", "in-cluster operator mode: policy and tenants come from CRDs")
	kubePolicy := flag.String("kube-policy", "default", "RateLimitPolicy to apply (--kube)")
	replicas := flag.Int("replicas", envInt("LIMITPLANE_REPLICAS", 1), "replicas sharing Redis; while it is down each falls back to 1/n of the budget (--kube counts them itself)")
	dataDir := flag.String("data-dir", os.Getenv("LIMITPLANE_DATA_DIR"), "without --redis, keep orgs, users and dashboard API keys in <dir>/orgs.json (empty: in memory only)")
	signup := flag.Bool("signup", os.Getenv("LIMITPLANE_SIGNUP") == "1", "let anyone sign up, creating an org they own (default: invite only)")
	aiMode := flag.String("ai", env("LIMITPLANE_AI", "auto"), "explanations and ops chat: auto, anthropic, openai or off; rules answer either way (keys: ANTHROPIC_API_KEY, LIMITPLANE_AI_KEY)")
	aiModel := flag.String("ai-model", os.Getenv("LIMITPLANE_AI_MODEL"), "model id (default claude-haiku-5-5 on Anthropic; required for openai)")
	aiBase := flag.String("ai-base-url", os.Getenv("LIMITPLANE_AI_BASE_URL"), "OpenAI-compatible API, e.g. https://api.groq.com/openai/v1 or http://localhost:11434/v1")
	aiShareIPs := flag.Bool("ai-share-ips", false, "send raw client IPs to the model (default: keyed hashes)")
	aiCalls := flag.Int("ai-calls-per-hour", envInt("LIMITPLANE_AI_CALLS_PER_HOUR", 60), "model calls allowed per hour (fleet-wide with Redis)")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if *adminKey == "" {
		b := make([]byte, 18)
		rand.Read(b)
		*adminKey = fmt.Sprintf("%x", b)
		fmt.Fprintf(os.Stderr, "limitplane: generated admin key (not stored): %s\n", *adminKey)
	}

	var op *operator
	limits, red, err := newBackend(*redisURL, *failClosed, func() int {
		if op != nil {
			return op.ctl.Replicas()
		}
		return *replicas
	})
	if err != nil {
		return err
	}
	backend := "memory"
	if red != nil {
		backend = "redis"
		defer red.Close()
	}

	dir, err := openDirectory(*redisURL, *dataDir)
	if err != nil {
		return err
	}
	store := policy.NewStore(cfg)
	sc := server.Config{
		Policy: store, Limits: limits, Dir: dir, Signup: *signup, AdminKey: *adminKey, MetricsKey: *metricsKey, Backend: backend,
		TrustProxy: *trust, FailClosed: *failClosed, Dashboard: web.FS, Kube: *kubeMode,
	}
	if *kubeMode {
		if op, err = newOperator(store, limits, *kubePolicy); err != nil {
			return err
		}
		sc.Leader, sc.OnBan, sc.OnAlert = op.elector.IsLeader, op.banned, op.alert
	}
	if sc.AI, err = aiConfig(ai.Options{Provider: *aiMode, Model: *aiModel, BaseURL: *aiBase}, *aiShareIPs, *aiCalls, *redisURL); err != nil {
		return err
	}
	srv := server.New(sc)

	var up http.Handler
	if *upstream != "" {
		u, err := url.Parse(*upstream)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("bad --upstream %q", *upstream)
		}
		up = proxy(u, *trust)
		if *metricsKey == "" {
			log.Printf("warning: %s/metrics is public and lists tenant ids; set --metrics-key", server.AdminPrefix)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hubCtx, stopHub := context.WithCancel(context.Background())
	defer stopHub()
	go srv.Run(hubCtx)
	if red != nil {
		go syncRedis(ctx, red, *failClosed)
		go red.Watch(ctx) // bans from other replicas, as they happen
		go dir.Watch(ctx) // orgs, users, revocations and keys from other replicas
	}
	if op != nil {
		// --config, if given, is only the startup policy: the CRDs own it from here.
		op.start(ctx, srv.Pilot)
		defer op.stop()
	} else if *cfgPath != "" {
		go store.Watch(ctx, *cfgPath, 2*time.Second, func(err error) { log.Printf("config reload: %v", err) })
		go reloadOnHUP(ctx, store, *cfgPath)
	}

	hs := &http.Server{
		Addr: *addr, Handler: srv.Handler(up),
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute,
		// No WriteTimeout: SSE streams and proxied responses can be long-lived.
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	errc := make(chan error, 2)
	var as *http.Server
	if *authzAddr != "" {
		aln, err := net.Listen("tcp", *authzAddr)
		if err != nil {
			return err
		}
		as = &http.Server{Handler: srv.Authz(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 2 * time.Minute}
		go func() { errc <- as.Serve(aln) }()
		log.Printf("forward auth on %s", *authzAddr)
		if !*trust {
			log.Print("warning: forward auth without --trust-proxy limits every anonymous client as the proxy's IP")
		}
	}
	go func() { errc <- hs.Serve(ln) }()
	mode := "demo"
	if up != nil {
		mode = "proxy -> " + *upstream + ", admin at " + server.AdminPrefix + "/"
	}
	log.Printf("limitplane on %s (%s, backend %s)", *addr, mode, backend)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Print("shutting down")
	stopHub() // ends SSE streams so Shutdown isn't held open by them
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if as != nil {
		as.Shutdown(sctx)
	}
	if err := hs.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// newBackend is in-process limits, or Redis behind a fallback to them. Only a bad URL is an error:
// a Redis that is down (or whose DNS name doesn't resolve yet) is retried, and until then the
// gateway serves degraded from local limits, or 503s with failClosed.
func newBackend(redisURL string, failClosed bool, replicas func() int) (limiter.Backend, *limiter.Redis, error) {
	mem := limiter.NewMemory()
	if redisURL == "" {
		return mem, nil, nil
	}
	c, err := redisx.New(redisURL)
	if err != nil {
		return nil, nil, fmt.Errorf("redis: %w", err)
	}
	red := limiter.NewRedis(c, mem.BanList)
	if failClosed { // fail-closed has to see Redis errors to return 503, so no fallback
		return red, red, nil
	}
	return limiter.NewFallback(red, mem, replicas), red, nil
}

// openDirectory is where orgs, users and dashboard keys live: Redis when there is one, so every
// replica shares them; else a file under dataDir; else memory. A Redis that is down at startup is
// retried by Watch; until then only the admin key can sign in.
func openDirectory(redisURL, dataDir string) (*org.Directory, error) {
	switch {
	case redisURL != "":
		c, err := redisx.New(redisURL)
		if err != nil {
			return nil, fmt.Errorf("redis: %w", err)
		}
		d := org.NewRedis(c)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := d.Load(ctx); err != nil {
			log.Printf("orgs: redis not reachable yet (%v), retrying; only the admin key can sign in meanwhile", err)
		}
		return d, nil
	case dataDir != "":
		return org.OpenFile(dataDir)
	}
	log.Print("orgs: kept in memory only; set --data-dir or --redis to keep them across restarts")
	return org.NewMemory(), nil
}

// aiConfig picks the model (none: rules only) and, with Redis, keeps incidents there so they
// survive restarts and every replica remembers the same ones.
func aiConfig(o ai.Options, shareIPs bool, perHour int, redisURL string) (ai.Config, error) {
	prov, err := ai.NewProvider(o, os.Getenv)
	if err != nil {
		return ai.Config{}, err
	}
	calls := int64(max(perHour, 1))
	c := ai.Config{Provider: prov, ShareIPs: shareIPs, Calls: limiter.Rate{Limit: calls, Period: time.Hour, Burst: min(calls, 10)}}
	if redisURL != "" {
		rc, err := redisx.New(redisURL)
		if err != nil {
			return ai.Config{}, fmt.Errorf("redis: %w", err)
		}
		c.Store = ai.RedisStore{R: rc}
	}
	if prov != nil {
		log.Printf("ai: %s, at most %d model calls an hour", prov.Name(), calls)
	}
	return c, nil
}

// syncRedis reads the ban list back every 2s (repairing anything pub/sub missed, pushing bans
// made during an outage, keeping a copy for the next one) and logs when Redis comes and goes.
func syncRedis(ctx context.Context, r *limiter.Redis, failClosed bool) {
	mode := "limiting locally, decisions marked degraded"
	if failClosed {
		mode = "returning 503 (--fail-closed)"
	}
	up := true
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := r.Bans(pctx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if (err == nil) != up {
			up = err == nil
			switch {
			case up:
				log.Print("redis: reachable, limits are shared again")
			case errors.Is(err, redisx.ErrNodeDown): // Cluster: only that node's slots are affected
				log.Printf("redis: %v; only tenants on that node are affected (%s); retrying every 2s", err, mode)
			default:
				log.Printf("redis: unreachable (%v), %s; retrying every 2s", err, mode)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func loadConfig(path string) (policy.Config, error) {
	if path == "" {
		return policy.Parse(defaultConfig)
	}
	return policy.Load(path)
}

func reloadOnHUP(ctx context.Context, store *policy.Store, path string) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			c, err := policy.Load(path)
			if err == nil {
				err = store.Swap(c)
			}
			if err != nil {
				log.Printf("SIGHUP reload: %v (keeping old config)", err)
				continue
			}
			log.Print("SIGHUP: config reloaded")
		}
	}
}

// proxy forwards to u. Rewrite drops inbound X-Forwarded-* by default; we keep the
// client's chain only when we trust the proxy in front of us, so it can't be spoofed.
func proxy(u *url.URL, trust bool) http.Handler {
	return &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(u)
		if trust {
			pr.Out.Header["X-Forwarded-For"] = pr.In.Header["X-Forwarded-For"]
		}
		pr.SetXForwarded()
	}}
}

func envInt(k string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return n
	}
	return def
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
