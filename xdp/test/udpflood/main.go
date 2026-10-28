// Command udpflood sends UDP as fast as it can (or at --pps) for the XDP tests,
// or with --listen counts what arrives, so a test can compare sent, dropped and received.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	to := flag.String("to", "", "target host:port")
	from := flag.String("from", "", "source IP to bind (pick one of several on the interface)")
	dur := flag.Duration("d", 5*time.Second, "how long to send or listen")
	size := flag.Int("size", 64, "payload bytes")
	pps := flag.Int("pps", 0, "target total packets/sec (0: unthrottled)")
	workers := flag.Int("workers", 1, "parallel senders, each with its own socket and source port")
	listen := flag.String("listen", "", "count received datagrams on this address instead of sending")
	flag.Parse()

	if *listen != "" {
		sink(*listen, *dur)
		return
	}
	if *to == "" {
		log.Fatal("need --to or --listen")
	}
	raddr, err := net.ResolveUDPAddr("udp", *to)
	if err != nil {
		log.Fatal(err)
	}
	var laddr *net.UDPAddr
	if *from != "" {
		laddr = &net.UDPAddr{IP: net.ParseIP(*from)}
	}

	var sent, failed atomic.Uint64
	var wg sync.WaitGroup
	deadline := time.Now().Add(*dur)
	start := time.Now()
	for range max(*workers, 1) {
		c, err := net.DialUDP("udp", laddr, raddr)
		if err != nil {
			log.Fatal(err)
		}
		wg.Go(func() {
			defer c.Close()
			buf := make([]byte, *size)
			var gap time.Duration
			if *pps > 0 {
				gap = time.Second * time.Duration(*workers) / time.Duration(*pps)
			}
			next := time.Now()
			for n := 0; ; n++ {
				// Checking the clock every packet costs more than the send at high rates.
				if n%256 == 0 && time.Now().After(deadline) {
					return
				}
				if gap > 0 {
					next = next.Add(gap)
					time.Sleep(time.Until(next))
				}
				if _, err := c.Write(buf); err != nil {
					failed.Add(1) // ENOBUFS/ECONNREFUSED: keep going
					continue
				}
				sent.Add(1)
			}
		})
	}
	wg.Wait()
	el := time.Since(start).Seconds()
	fmt.Printf("sent=%d failed=%d seconds=%.2f pps=%.0f\n", sent.Load(), failed.Load(), el, float64(sent.Load())/el)
}

func sink(addr string, dur time.Duration) {
	c, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(dur))
	buf := make([]byte, 65535)
	var n uint64
	start := time.Now()
	for {
		if _, _, err := c.ReadFrom(buf); err != nil {
			break
		}
		n++
	}
	el := time.Since(start).Seconds()
	fmt.Printf("received=%d seconds=%.2f pps=%.0f\n", n, el, float64(n)/el)
}
