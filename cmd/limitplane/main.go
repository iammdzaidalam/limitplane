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

	var lim limiter.Limiter = limiter.NewLocal()
	var quota limiter.Quota = limiter.NewLocalQuota()
	backend := "memory"
	if *redisURL != "" {
		c, err := redisx.Dial(*redisURL)
		if err != nil {
			return fmt.Errorf("redis: %w", err)
		}
		defer c.Close()
		r := limiter.NewRedis(c)
		lim, quota, backend = limiter.NewFallback(r, lim), limiter.NewFallbackQuota(r, quota), "redis"
	}

	store := policy.NewStore(cfg)
	srv := server.New(server.Config{
		Policy: store, Limiter: lim, Quota: quota, AdminKey: *adminKey, MetricsKey: *metricsKey, Backend: backend,
		TrustProxy: *trust, FailClosed: *failClosed, Dashboard: web.FS,
	})

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
	if *cfgPath != "" {
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

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
