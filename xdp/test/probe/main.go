// Command probe measures gateway latency at a steady request rate, as a legitimate client
// would see it while a flood is running.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"sync"
	"time"
)

func main() {
	url := flag.String("url", "", "URL to GET")
	rps := flag.Int("rps", 20, "requests per second")
	dur := flag.Duration("d", 10*time.Second, "how long to probe")
	key := flag.String("key", "", "X-Api-Key header (use a tier whose limit is above --rps)")
	flag.Parse()
	if *url == "" || *rps <= 0 {
		log.Fatal("need --url and --rps > 0")
	}

	hc := &http.Client{Timeout: 2 * time.Second}
	var (
		mu   sync.Mutex
		lat  []time.Duration
		errs int
		wg   sync.WaitGroup
	)
	t := time.NewTicker(time.Second / time.Duration(*rps))
	defer t.Stop()
	for end := time.Now().Add(*dur); time.Now().Before(end); <-t.C {
		wg.Go(func() {
			req, _ := http.NewRequest(http.MethodGet, *url, nil)
			if *key != "" {
				req.Header.Set("X-Api-Key", *key)
			}
			start := time.Now()
			res, err := hc.Do(req)
			if err == nil {
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
			}
			d := time.Since(start)
			mu.Lock()
			defer mu.Unlock()
			// A timeout counts as an error, not a latency: it would cap p99 at the client timeout.
			if err != nil || res.StatusCode >= 500 {
				errs++
				return
			}
			lat = append(lat, d)
		})
	}
	wg.Wait()
	slices.Sort(lat)
	pct := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		return float64(lat[min(len(lat)-1, int(p*float64(len(lat))))].Microseconds()) / 1e3
	}
	fmt.Printf("requests=%d errors=%d p50_ms=%.2f p99_ms=%.2f max_ms=%.2f\n", len(lat)+errs, errs, pct(0.50), pct(0.99), pct(1))
}
