// Package autopilot watches the decision stream: it bans storming clients,
// alerts on quota use and labels each client's behaviour.
package autopilot

import (
	"cmp"
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/gateway"
	"github.com/iammdzaidalam/limitplane/internal/limiter"
)

type Config struct {
	Rules
	MaxClients int              // fingerprints kept, least recently seen evicted; default 10000
	Store      limiter.BanStore // where bans live, shared with the gateway's Meter; nil: in-process
	// Callbacks run on the caller's goroutine (Observe runs on the request path): keep them non-blocking.
	OnBan   func(Ban)
	OnAlert func(Alert)
}

// Rules is the storm-ban rule. RateLimitPolicy spec.autopilot sets it with the same JSON names.
type Rules struct {
	StormBlocks int // burst blocks within StormWindow that trigger a ban; 0 disables
	StormWindow time.Duration
	BanFor      time.Duration
}

var DefaultRules = Rules{StormBlocks: 20, StormWindow: 10 * time.Second, BanFor: 5 * time.Minute}

// UnmarshalJSON reads {"stormBlocks": 20, "stormWindow": "10s", "banFor": "5m"}; absent fields keep their value.
func (r *Rules) UnmarshalJSON(b []byte) error {
	var j struct {
		StormBlocks *int   `json:"stormBlocks"`
		StormWindow string `json:"stormWindow"`
		BanFor      string `json:"banFor"`
	}
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	if j.StormBlocks != nil {
		r.StormBlocks = *j.StormBlocks
	}
	for _, f := range []struct {
		s string
		d *time.Duration
	}{{j.StormWindow, &r.StormWindow}, {j.BanFor, &r.BanFor}} {
		if f.s == "" {
			continue
		}
		d, err := time.ParseDuration(f.s)
		if err != nil {
			return err
		}
		*f.d = d
	}
	return r.Validate()
}

func (r Rules) Validate() error {
	if r.StormBlocks < 0 || r.StormBlocks > 0 && (r.StormWindow <= 0 || r.BanFor <= 0) {
		return errors.New("autopilot: stormBlocks must be >= 0, and stormWindow and banFor > 0 when it is set")
	}
	return nil
}

type Ban = limiter.Ban

// Alert fires once per tenant per month when usage crosses 80% of the monthly cap.
type Alert struct {
	Tenant string `json:"tenant"`
	Month  string `json:"month"`
	Used   int64  `json:"used"`
	Limit  int64  `json:"limit"`
}

type Pilot struct {
	c Config // Rules is guarded by mu; the rest is fixed

	mu      sync.Mutex
	lru     *list.List // of *track, front = most recently seen
	clients map[string]*list.Element
	alerted map[string]string // tenant -> month already alerted
}

func New(c Config) *Pilot {
	if c.MaxClients <= 0 {
		c.MaxClients = 10000
	}
	if c.Store == nil {
		c.Store = limiter.NewBanList()
	}
	return &Pilot{c: c, lru: list.New(), clients: map[string]*list.Element{}, alerted: map[string]string{}}
}

// SetRules swaps the storm rule at runtime (e.g. from a RateLimitPolicy).
func (p *Pilot) SetRules(r Rules) {
	p.mu.Lock()
	p.c.Rules = r
	p.mu.Unlock()
}

func (p *Pilot) Rules() Rules {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.c.Rules
}

// Ban records a ban in the store, where every replica's gateway sees it.
func (p *Pilot) Ban(ctx context.Context, client string, d time.Duration, reason string) error {
	b := Ban{Client: client, Until: time.Now().Add(d), Reason: reason}
	if err := p.c.Store.Ban(ctx, b); err != nil {
		return err
	}
	if p.c.OnBan != nil {
		p.c.OnBan(b)
	}
	return nil
}

func (p *Pilot) Unban(ctx context.Context, client string) error { return p.c.Store.Unban(ctx, client) }

// Bans lists active bans, soonest to expire first.
func (p *Pilot) Bans(ctx context.Context) ([]Ban, error) { return p.c.Store.Bans(ctx) }

// Observe feeds one gateway decision into the storm rule and the client's fingerprint.
func (p *Pilot) Observe(d gateway.Decision) {
	p.mu.Lock()
	t := p.track(d.Client)
	t.observe(d)
	r := p.c.Rules
	storm := r.StormBlocks > 0 && d.Reason == gateway.ReasonBurst && t.storm(d.Time, r.StormBlocks, r.StormWindow)
	p.mu.Unlock()
	if storm {
		p.Ban(context.Background(), d.Client, r.BanFor, "storm") // best effort: the next storm retries
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
