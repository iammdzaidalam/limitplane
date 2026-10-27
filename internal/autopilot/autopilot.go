// Package autopilot watches the decision stream: it bans storming clients,
// alerts on quota use and labels each client's behaviour.
package autopilot

import (
	"cmp"
	"container/list"
	"slices"
	"sync"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/gateway"
)

type Config struct {
	StormBlocks int // burst blocks within StormWindow that trigger a ban; 0 disables
	StormWindow time.Duration
	BanFor      time.Duration
	MaxClients  int // fingerprints kept, least recently seen evicted; default 10000
	// Callbacks run on the Observe caller's goroutine (the request path): keep them non-blocking.
	OnBan   func(Ban)
	OnAlert func(Alert)
}

type Ban struct {
	Client string    `json:"client"`
	Until  time.Time `json:"until"`
	Reason string    `json:"reason"`
}

// Alert fires once per tenant per month when usage crosses 80% of the monthly cap.
type Alert struct {
	Tenant string `json:"tenant"`
	Month  string `json:"month"`
	Used   int64  `json:"used"`
	Limit  int64  `json:"limit"`
}

type Pilot struct {
	c Config

	banMu sync.RWMutex
	bans  map[string]Ban

	mu      sync.Mutex
	lru     *list.List // of *track, front = most recently seen
	clients map[string]*list.Element
	alerted map[string]string // tenant -> month already alerted
}

func New(c Config) *Pilot {
	if c.MaxClients <= 0 {
		c.MaxClients = 10000
	}
	return &Pilot{c: c, bans: map[string]Ban{}, lru: list.New(), clients: map[string]*list.Element{}, alerted: map[string]string{}}
}

// Banned implements gateway.Bans. Expired bans read as absent; Ban/Bans sweep them out.
func (p *Pilot) Banned(client string) (time.Time, bool) {
	p.banMu.RLock()
	b, ok := p.bans[client]
	p.banMu.RUnlock()
	if !ok || !time.Now().Before(b.Until) {
		return time.Time{}, false
	}
	return b.Until, true
}

func (p *Pilot) Ban(client string, d time.Duration, reason string) {
	now := time.Now()
	b := Ban{Client: client, Until: now.Add(d), Reason: reason}
	p.banMu.Lock()
	p.sweep(now)
	p.bans[client] = b
	p.banMu.Unlock()
	if p.c.OnBan != nil {
		p.c.OnBan(b)
	}
}

func (p *Pilot) Unban(client string) {
	p.banMu.Lock()
	delete(p.bans, client)
	p.banMu.Unlock()
}

// Bans lists active bans, soonest to expire first.
func (p *Pilot) Bans() []Ban {
	p.banMu.Lock()
	p.sweep(time.Now())
	out := make([]Ban, 0, len(p.bans))
	for _, b := range p.bans {
		out = append(out, b)
	}
	p.banMu.Unlock()
	slices.SortFunc(out, func(a, b Ban) int { return a.Until.Compare(b.Until) })
	return out
}

// sweep drops expired bans; callers hold banMu. Bans are few, so a full pass is cheap.
func (p *Pilot) sweep(now time.Time) {
	for k, b := range p.bans {
		if !now.Before(b.Until) {
			delete(p.bans, k)
		}
	}
}

// Observe feeds one gateway decision into the storm rule and the client's fingerprint.
func (p *Pilot) Observe(d gateway.Decision) {
	p.mu.Lock()
	t := p.track(d.Client)
	t.observe(d)
	storm := p.c.StormBlocks > 0 && d.Reason == gateway.ReasonBurst && t.storm(d.Time, p.c.StormBlocks, p.c.StormWindow)
	p.mu.Unlock()
	if storm {
		p.Ban(d.Client, p.c.BanFor, "storm")
	}
}

// Usage matches gateway.Config.OnQuota.
func (p *Pilot) Usage(tenant string, used, limit int64) {
	if limit <= 0 || used*5 < limit*4 {
		return
	}
	month := time.Now().UTC().Format("2006-01")
	p.mu.Lock()
	fire := p.alerted[tenant] != month
	p.alerted[tenant] = month
	p.mu.Unlock()
	if fire && p.c.OnAlert != nil {
		p.c.OnAlert(Alert{Tenant: tenant, Month: month, Used: used, Limit: limit})
	}
}

// track returns the client's state, evicting the least recently seen one at capacity. Caller holds mu.
func (p *Pilot) track(client string) *track {
	if e, ok := p.clients[client]; ok {
		p.lru.MoveToFront(e)
		return e.Value.(*track)
	}
	if p.lru.Len() >= p.c.MaxClients {
		old := p.lru.Remove(p.lru.Back()).(*track)
		delete(p.clients, old.client)
	}
	t := &track{client: client}
	p.clients[client] = p.lru.PushFront(t)
	return t
}

type Client struct {
	Client     string    `json:"client"`
	Label      string    `json:"label"`
	RPS        float64   `json:"rps"`
	BlockRatio float64   `json:"blockRatio"`
	LastSeen   time.Time `json:"lastSeen"`
}

// Clients lists fingerprints, busiest first.
func (p *Pilot) Clients() []Client {
	now := time.Now()
	p.mu.Lock()
	out := make([]Client, 0, p.lru.Len())
	for e := p.lru.Front(); e != nil; e = e.Next() {
		out = append(out, e.Value.(*track).snapshot(now))
	}
	p.mu.Unlock()
	slices.SortStableFunc(out, func(a, b Client) int { return cmp.Compare(b.RPS, a.RPS) })
	return out
}
