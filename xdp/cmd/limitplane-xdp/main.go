// Command limitplane-xdp drops packets from LimitPlane's banned clients at the NIC with XDP,
// and drops per-source packet floods before they reach the kernel stack or the gateway.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/iammdzaidalam/limitplane/xdp/fastpath"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	iface := flag.String("iface", "", "interface to attach to (required)")
	mode := flag.String("mode", "native", "XDP hook: native (driver) or generic (skb, any NIC, slower)")
	gw := flag.String("gateway", "http://127.0.0.1:8080", "LimitPlane admin root (add /_limitplane in proxy mode)")
	adminKey := flag.String("admin-key", os.Getenv("LIMITPLANE_ADMIN_KEY"), "gateway admin key")
	pps := flag.Uint64("pps", 0, "per-source packets/sec before dropping (IPv6 per /64); 0 disables")
	burst := flag.Uint64("burst", 0, "per-source burst in packets (0: same as --pps)")
	every := flag.Duration("sync", time.Second, "ban sync interval")
	metrics := flag.String("metrics", ":9102", "Prometheus listen address (empty: off)")
	flag.Parse()

	if *iface == "" || *adminKey == "" {
		return errors.New("--iface and --admin-key (or LIMITPLANE_ADMIN_KEY) are required")
	}
	if *mode != "native" && *mode != "generic" {
		return fmt.Errorf("--mode %q: want native or generic", *mode)
	}
	if *burst == 0 {
		*burst = *pps
	}
	rate, err := fastpath.RateOf(*pps, *burst)
	if err != nil {
		return err
	}

	fp, err := fastpath.Attach(*iface, *mode == "generic", rate)
	if err != nil {
		return err
	}
	defer fp.Close()
	log.Printf("attached to %s (%s), pps=%d burst=%d, syncing %s every %s", *iface, *mode, *pps, *burst, *gw, *every)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st := &state{}
	if *metrics != "" {
		srv := &http.Server{Addr: *metrics, Handler: st.handler(fp), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("metrics: %v", err)
			}
		}()
		defer srv.Close()
	}

	g := &gateway{base: strings.TrimSuffix(*gw, "/"), key: *adminKey, hc: &http.Client{Timeout: 2 * time.Second}}
	s := &syncer{m: fp, have: map[netip.Prefix]time.Time{}}
	t := time.NewTicker(*every)
	defer t.Stop()
	for {
		st.sync(ctx, g, s)
		select {
		case <-ctx.Done():
			log.Print("detaching")
			return nil
		case <-t.C:
		}
	}
}

// state is what /metrics reports besides the kernel counters.
type state struct {
	mu       sync.Mutex
	bans     int
	skipped  int
	errs     uint64
	lastSync time.Time
	failing  bool
}

func (st *state) sync(ctx context.Context, g *gateway, s *syncer) {
	bans, err := g.bans(ctx)
	now := time.Now()
	var added, removed int
	if err == nil {
		added, removed, err = s.apply(bans, now)
	} else if ctx.Err() == nil {
		// Keep enforcing what we know rather than failing open the moment the gateway blips.
		removed, _ = s.expire(now)
	}
	if added+removed > 0 {
		log.Printf("bans: +%d -%d, %d installed", added, removed, len(s.have))
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.bans, st.skipped = len(s.have), s.skipped
	if err == nil {
		st.lastSync = now
	} else if ctx.Err() == nil {
		st.errs++
	}
	// Log transitions only, so a gateway outage doesn't print a line a second.
	if fail := err != nil && ctx.Err() == nil; fail != st.failing {
		st.failing = fail
		if fail {
			log.Printf("sync failing, keeping %d bans until they expire: %v", len(s.have), err)
		} else {
			log.Print("sync recovered")
		}
	}
}

type counterSource interface {
	Counters() (fastpath.Counters, error)
}

func (st *state) handler(fp counterSource) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		c, err := fp.Counters()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		st.mu.Lock()
		defer st.mu.Unlock()
		st.write(w, c)
	})
}

// write renders the Prometheus text format. Caller holds mu.
func (st *state) write(w io.Writer, c fastpath.Counters) {
	var last float64
	if !st.lastSync.IsZero() {
		last = float64(st.lastSync.UnixMilli()) / 1e3
	}
	fmt.Fprintf(w, `# HELP limitplane_xdp_packets_total Packets seen by the XDP fast path, by verdict.
# TYPE limitplane_xdp_packets_total counter
limitplane_xdp_packets_total{action="pass"} %d
limitplane_xdp_packets_total{action="drop_ban"} %d
limitplane_xdp_packets_total{action="drop_rate"} %d
# HELP limitplane_xdp_bans Prefixes in the kernel ban map.
# TYPE limitplane_xdp_bans gauge
limitplane_xdp_bans %d
# HELP limitplane_xdp_bans_skipped Bans in the last sync whose client is not an IP or CIDR.
# TYPE limitplane_xdp_bans_skipped gauge
limitplane_xdp_bans_skipped %d
# HELP limitplane_xdp_sync_errors_total Failed ban syncs.
# TYPE limitplane_xdp_sync_errors_total counter
limitplane_xdp_sync_errors_total %d
# HELP limitplane_xdp_last_sync_timestamp_seconds Last successful ban sync.
# TYPE limitplane_xdp_last_sync_timestamp_seconds gauge
limitplane_xdp_last_sync_timestamp_seconds %.3f
`, c.Pass, c.DropBan, c.DropRate, st.bans, st.skipped, st.errs, last)
}
