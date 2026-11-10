package policy

import (
	"cmp"
	"context"
	"crypto/sha256"
	"maps"
	"math"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Store serves the current config lock-free; Swap and SetOrgs replace it atomically.
type Store struct {
	cur    atomic.Pointer[compiled]
	mu     sync.Mutex // serialises writers
	orgs   Orgs
	onMove func(tenant, from, to string)
}

type compiled struct {
	cfg     Config
	keys    map[string]Match   // api key -> match without cost
	hashed  map[[32]byte]Match // sha256 of an api key from the org directory -> match without cost
	anon    Match
	routes  []Route           // longest prefix first
	orgOf   map[string]string // tenant -> org, for tenants in one
	tenants []TenantInfo      // by id
}

// NewStore panics on an invalid config: callers get one from Parse/Load.
func NewStore(c Config) *Store {
	s := &Store{}
	if err := s.Swap(c); err != nil {
		panic(err)
	}
	return s
}

func (s *Store) Swap(c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.install(c.clone(), s.orgs)
	return nil
}

// SetOrgs swaps in what the org directory adds. The Store keeps o: don't change it afterwards.
func (s *Store) SetOrgs(o Orgs) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orgs = o
	s.install(s.cur.Load().cfg, o)
}

// OnMove registers f, called after a swap for every tenant whose org changed (to or from "" too).
// It runs under the writers' lock: hand the work off.
func (s *Store) OnMove(f func(tenant, from, to string)) {
	s.mu.Lock()
	s.onMove = f
	s.mu.Unlock()
}

func (s *Store) install(c Config, o Orgs) {
	p := compile(c, o)
	old := s.cur.Swap(p)
	if old == nil || s.onMove == nil {
		return
	}
	for t, from := range old.orgOf {
		if to := p.orgOf[t]; to != from {
			s.onMove(t, from, to)
		}
	}
	for t, to := range p.orgOf {
		if _, ok := old.orgOf[t]; !ok {
			s.onMove(t, "", to)
		}
	}
}

// compile resolves every key to a Match up front. A tenant's org comes from the policy when a key
// names one, else from the directory; a directory tenant whose tier the policy no longer has keeps
// its listing, but its keys stop resolving until the tier is back.
func compile(c Config, o Orgs) *compiled {
	p := &compiled{cfg: c, keys: make(map[string]Match, len(c.Keys)), orgOf: map[string]string{}}
	lanes := make(map[string]*[numLanes]int64, len(c.Tiers))
	for name, t := range c.Tiers {
		lanes[name] = laneBursts(t)
	}
	pinned := map[string]bool{}
	for _, t := range c.Keys {
		if t.Org != "" {
			p.orgOf[t.ID], pinned[t.ID] = t.Org, true
		}
	}
	for id, t := range o.Tenants {
		if !pinned[id] && t.Org != "" {
			p.orgOf[id] = t.Org
		}
	}
	match := func(id, tier string) Match {
		t, org := c.Tiers[tier], p.orgOf[id]
		return Match{Tenant: id, Tier: tier, Rate: t.Rate, Month: t.Monthly, Lanes: lanes[tier], Org: org, OrgMonth: o.Budgets[org]}
	}
	listed := map[string]bool{}
	for _, k := range slices.Sorted(maps.Keys(c.Keys)) {
		t := c.Keys[k]
		p.keys[k] = match(t.ID, t.Tier)
		if !listed[t.ID] {
			listed[t.ID] = true
			p.tenants = append(p.tenants, TenantInfo{ID: t.ID, Tier: t.Tier, Org: p.orgOf[t.ID], Monthly: c.Tiers[t.Tier].Monthly, Pinned: pinned[t.ID]})
		}
	}
	for id, t := range o.Tenants {
		if t.Tier != "" && !listed[id] {
			listed[id] = true
			p.tenants = append(p.tenants, TenantInfo{ID: id, Tier: t.Tier, Org: p.orgOf[id], Monthly: c.Tiers[t.Tier].Monthly, Managed: true})
		}
	}
	slices.SortFunc(p.tenants, func(a, b TenantInfo) int { return strings.Compare(a.ID, b.ID) })
	if len(o.Keys) > 0 {
		p.hashed = make(map[[32]byte]Match, len(o.Keys))
		for h, id := range o.Keys {
			if t := o.Tenants[id]; t.Tier != "" {
				if _, ok := c.Tiers[t.Tier]; ok {
					p.hashed[h] = match(id, t.Tier)
				}
			}
		}
	}
	at := c.Tiers[c.Anonymous]
	p.anon = Match{Tenant: AnonTenant, Tier: c.Anonymous, Rate: at.Rate, Month: at.Monthly, Anon: true, Lanes: lanes[c.Anonymous]}
	// Linear scan over a few dozen sorted prefixes beats a trie on cache locality; no allocs either way.
	p.routes = slices.Clone(c.Routes)
	slices.SortFunc(p.routes, func(a, b Route) int { return cmp.Compare(len(b.Prefix), len(a.Prefix)) })
	return p
}

// laneBursts precomputes the tier's burst in every lane (unlisted lanes keep it), so the request
// path does an array read instead of float math. nil when the tier has no lanes.
func laneBursts(t Tier) *[numLanes]int64 {
	if len(t.Lanes) == 0 {
		return nil
	}
	var b [numLanes]int64
	for l := range b {
		f, ok := t.Lanes[laneNames[l]]
		if !ok {
			f = 1
		}
		b[l] = max(1, int64(math.Round(float64(burst(t.Rate))*f)))
	}
	return &b
}

// Config returns a copy, so callers can't mutate the live maps.
func (s *Store) Config() Config { return s.cur.Load().cfg.clone() }

// Tenants lists every tenant, from the policy and the org directory, by id.
func (s *Store) Tenants() []TenantInfo { return slices.Clone(s.cur.Load().tenants) }

// OrgOf is the tenant's org, or "".
func (s *Store) OrgOf(tenant string) string { return s.cur.Load().orgOf[tenant] }

// HashKey is how API keys created in the org directory are stored and found. They are long and
// random, so one fast hash is as good as a slow one, and a slow one would cost every request.
func HashKey(key string) [32]byte {
	var b [64]byte // on the stack: no allocation for keys up to 64 bytes
	if len(key) <= len(b) {
		return sha256.Sum256(b[:copy(b[:], key)])
	}
	return sha256.Sum256([]byte(key))
}

func (s *Store) Resolve(apiKey, path string) Match {
	p := s.cur.Load()
	m, ok := p.keys[apiKey]
	if !ok && apiKey != "" && len(p.hashed) > 0 {
		m, ok = p.hashed[HashKey(apiKey)]
	}
	if !ok {
		m = p.anon
	}
	m.Cost = 1
	for _, r := range p.routes {
		if matches(path, r.Prefix) {
			m.Cost = r.Cost
			break
		}
	}
	return m
}

// Watch polls path's mtime and swaps in valid changes until ctx ends.
// An invalid file keeps the old config and reports through onErr.
func (s *Store) Watch(ctx context.Context, path string, every time.Duration, onErr func(error)) {
	// no baseline: the first tick reloads once, so an edit between Load and Watch isn't missed
	var last time.Time
	size := int64(-1)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		fi, err := os.Stat(path)
		if err != nil {
			report(onErr, err)
			continue
		}
		if fi.ModTime().Equal(last) && fi.Size() == size {
			continue
		}
		last, size = fi.ModTime(), fi.Size()
		c, err := Load(path)
		if err == nil {
			err = s.Swap(c)
		}
		report(onErr, err)
	}
}

func report(f func(error), err error) {
	if err != nil && f != nil {
		f(err)
	}
}

// matches treats a prefix as whole path segments: /v1/embed matches /v1/embed/x but not /v1/embeddings.
func matches(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return len(path) == len(prefix) || prefix[len(prefix)-1] == '/' || path[len(prefix)] == '/'
}
