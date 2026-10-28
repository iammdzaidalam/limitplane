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

	"github.com/iammdzaidalam/limitplane/internal/limiter"
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
	upstream := flag.String("upstream", "", "proxy to this URL (empty: demo app)")
	cfgPath := flag.String("config", "", "policy JSON file (empty: built-in demo policy)")
	redisURL := flag.String("redis", os.Getenv("REDIS_URL"), "shared Redis, e.g. redis://:pass@host:6379")
	adminKey := flag.String("admin-key", os.Getenv("LIMITPLANE_ADMIN_KEY"), "dashboard/API key (empty: random, printed once)")
	metricsKey := flag.String("metrics-key", os.Getenv("LIMITPLANE_METRICS_KEY"), "bearer key for /metrics (empty: public)")
	trust := flag.Bool("trust-proxy", false, "trust X-Forwarded-For (only behind a proxy you control)")
	failClosed := flag.Bool("fail-closed", false, "return 503 when the shared backend is down instead of falling back to local limits")
	kubeMode := flag.Bool("kube", os.Getenv("LIMITPLANE_KUBE") == "1", "in-cluster operator mode: policy and tenants come from CRDs")
	kubePolicy := flag.String("kube-policy", "default", "RateLimitPolicy to apply (--kube)")
	replicas := flag.Int("replicas", envInt("LIMITPLANE_REPLICAS", 1), "replicas sharing Redis; while it is down each falls back to 1/n of the budget (--kube counts them itself)")
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

	store := policy.NewStore(cfg)
	sc := server.Config{
		Policy: store, Limits: limits, AdminKey: *adminKey, MetricsKey: *metricsKey, Backend: backend,
		TrustProxy: *trust, FailClosed: *failClosed, Dashboard: web.FS, Kube: *kubeMode,
	}
	if *kubeMode {
		if op, err = newOperator(store, limits, *kubePolicy); err != nil {
			return err
		}
		sc.Leader, sc.OnBan, sc.OnAlert = op.elector.IsLeader, op.banned, op.alert
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
	errc := make(chan error, 1)
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

// syncRedis reads the ban list back every 2s (spreading CIDR bans, keeping a copy for outages)
// and logs when Redis comes and goes, including at startup.
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
			if up {
				log.Print("redis: reachable, limits are shared again")
			} else {
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
