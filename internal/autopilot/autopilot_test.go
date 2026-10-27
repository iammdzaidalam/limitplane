package autopilot

import (
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/gateway"
)

var _ gateway.Bans = (*Pilot)(nil)

func dec(client, path, reason string, at time.Time) gateway.Decision {
	return gateway.Decision{Time: at, Client: client, Path: path, Reason: reason, Allowed: reason == gateway.ReasonOK, RetryAfter: 2 * time.Second}
}

func TestBanExpiresWithoutGoroutine(t *testing.T) {
	var got []Ban
	p := New(Config{OnBan: func(b Ban) { got = append(got, b) }})
	p.Ban("a", time.Hour, "manual")
	p.Ban("b", time.Millisecond, "manual")
	if _, ok := p.Banned("a"); !ok || len(got) != 2 {
		t.Fatalf("ban a missing, OnBan calls %d", len(got))
	}
	time.Sleep(5 * time.Millisecond)
	if _, ok := p.Banned("b"); ok {
		t.Fatal("expired ban still active")
	}
	if bs := p.Bans(); len(bs) != 1 || bs[0].Client != "a" {
		t.Fatalf("Bans() = %+v", bs)
	}
	if len(p.bans) != 1 {
		t.Fatal("expired ban not swept")
	}
	p.Unban("a")
	if _, ok := p.Banned("a"); ok {
		t.Fatal("unban failed")
	}
}

func TestStorm(t *testing.T) {
	var bans []Ban
	p := New(Config{StormBlocks: 3, StormWindow: time.Second, BanFor: time.Minute, OnBan: func(b Ban) { bans = append(bans, b) }})
	now := time.Now()
	// 3 blocks spread over 3s: never 3 inside one second.
	for i := range 3 {
		p.Observe(dec("slow", "/", gateway.ReasonBurst, now.Add(time.Duration(i)*1500*time.Millisecond)))
	}
	// Allowed traffic and other clients don't count.
	for range 5 {
		p.Observe(dec("fast", "/", gateway.ReasonOK, now))
		p.Observe(dec("other", "/", gateway.ReasonBurst, now))
	}
	if len(bans) != 1 || bans[0].Client != "other" {
		t.Fatalf("bans %+v", bans)
	}
	for i := range 3 {
		p.Observe(dec("fast", "/", gateway.ReasonBurst, now.Add(time.Duration(i)*100*time.Millisecond)))
	}
	if _, ok := p.Banned("fast"); !ok || len(bans) != 2 || bans[1].Reason != "storm" {
		t.Fatalf("storm not banned: %+v", bans)
	}
	if _, ok := p.Banned("slow"); ok {
		t.Fatal("slow client banned")
	}
}

func TestQuotaAlertOncePerMonth(t *testing.T) {
	var alerts []Alert
	p := New(Config{OnAlert: func(a Alert) { alerts = append(alerts, a) }})
	p.Usage("acme", 79, 100)
	p.Usage("acme", 80, 100)
	p.Usage("acme", 95, 100)
	p.Usage("globex", 1, 0) // uncapped
	if len(alerts) != 1 || alerts[0].Tenant != "acme" || alerts[0].Used != 80 {
		t.Fatalf("alerts %+v", alerts)
	}
	p.alerted["acme"] = "1999-01" // last month's alert must not suppress this month's
	p.Usage("acme", 90, 100)
	if len(alerts) != 2 {
		t.Fatalf("new month did not alert: %+v", alerts)
	}
}

func labelOf(p *Pilot, client string) string {
	for _, c := range p.Clients() {
		if c.Client == client {
			return c.Label
		}
	}
	return ""
}

func TestLabels(t *testing.T) {
	p := New(Config{})
	r := rand.New(rand.NewPCG(1, 2))
	now := time.Now().Add(-time.Hour)
	at := map[string]time.Time{}
	next := func(c string, gap time.Duration) time.Time {
		if at[c].IsZero() {
			at[c] = now
		}
		at[c] = at[c].Add(gap)
		return at[c]
	}
	for i := range 60 {
		p.Observe(dec("bot", "/v1/ping", gateway.ReasonOK, next("bot", 100*time.Millisecond)))
		p.Observe(dec("crawler", fmt.Sprintf("/page/%d", i), gateway.ReasonOK, next("crawler", 500*time.Millisecond)))
		human := time.Duration(r.ExpFloat64() * float64(3*time.Second))
		p.Observe(dec("human", []string{"/", "/v1/generate", "/v1/embed"}[i%3], gateway.ReasonOK, next("human", human)))
		// Re-fires 10ms after every 429 despite Retry-After 2s.
		reason := gateway.ReasonOK
		if i%2 == 0 {
			reason = gateway.ReasonBurst
		}
		p.Observe(dec("retry", "/v1/generate", reason, next("retry", 10*time.Millisecond)))
	}
	for range 3 {
		p.Observe(dec("new", "/", gateway.ReasonOK, next("new", time.Second)))
	}
	for c, want := range map[string]string{"bot": "bot", "crawler": "crawler", "human": "human", "retry": "retry_bug", "new": "warming"} {
		if got := labelOf(p, c); got != want {
			t.Errorf("%s labelled %q, want %q", c, got, want)
		}
	}
}

func TestBackoffIsNotRetryBug(t *testing.T) {
	p := New(Config{})
	at := time.Now()
	for i := range 20 {
		reason := gateway.ReasonOK
		if i%2 == 0 {
			reason = gateway.ReasonBurst
		}
		at = at.Add(2 * time.Second) // honours Retry-After 2s
		p.Observe(dec("polite", fmt.Sprint(i%2), reason, at))
	}
	if l := labelOf(p, "polite"); l == "retry_bug" {
		t.Fatal("polite client labelled retry_bug")
	}
}

func TestRPS(t *testing.T) {
	p := New(Config{})
	now := time.Now()
	for range 50 {
		p.Observe(dec("c", "/", gateway.ReasonOK, now))
	}
	if rps := p.Clients()[0].RPS; rps < 1 || rps > 10 {
		t.Fatalf("rps %v for 50 reqs in the current 10s window", rps)
	}
	q := New(Config{})
	q.Observe(dec("idle", "/", gateway.ReasonOK, now.Add(-time.Minute)))
	if rps := q.Clients()[0].RPS; rps != 0 {
		t.Fatalf("idle rps %v", rps)
	}
}

func TestLRUEviction(t *testing.T) {
	p := New(Config{MaxClients: 2})
	now := time.Now()
	for _, c := range []string{"a", "b", "a", "c"} {
		p.Observe(dec(c, "/", gateway.ReasonOK, now))
	}
	if len(p.Clients()) != 2 || labelOf(p, "b") != "" || labelOf(p, "a") == "" {
		t.Fatalf("clients %+v", p.Clients())
	}
}

func TestConcurrent(t *testing.T) {
	p := New(Config{StormBlocks: 5, StormWindow: time.Second, BanFor: time.Second, MaxClients: 50})
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 500 {
				c := fmt.Sprint("c", (g*500+i)%80)
				p.Observe(dec(c, "/", gateway.ReasonBurst, time.Now()))
				p.Banned(c)
				if i%50 == 0 {
					p.Clients()
					p.Bans()
					p.Usage(c, 90, 100)
				}
			}
		})
	}
	wg.Wait()
	if n := len(p.Clients()); n > 50 {
		t.Fatalf("tracked %d clients, cap 50", n)
	}
}

func BenchmarkObserve(b *testing.B) {
	p := New(Config{StormBlocks: 10, StormWindow: time.Second, BanFor: time.Minute})
	d := dec("203.0.113.7", "/v1/generate", gateway.ReasonOK, time.Now())
	b.ReportAllocs()
	for b.Loop() {
		p.Observe(d)
	}
}
