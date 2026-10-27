package policy

import (
	"cmp"
	"context"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// Store serves the current config lock-free; Swap replaces it atomically.
type Store struct {
	cur atomic.Pointer[compiled]
}

type compiled struct {
	cfg    Config
	keys   map[string]Match // api key -> match without cost
	anon   Match
	routes []Route // longest prefix first
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
	c = c.clone()
	p := &compiled{cfg: c, keys: make(map[string]Match, len(c.Keys))}
	for k, t := range c.Keys {
		tier := c.Tiers[t.Tier]
		p.keys[k] = Match{Tenant: t.ID, Tier: t.Tier, Rate: tier.Rate, Month: tier.Monthly}
	}
	at := c.Tiers[c.Anonymous]
	p.anon = Match{Tenant: AnonTenant, Tier: c.Anonymous, Rate: at.Rate, Month: at.Monthly, Anon: true}
	// Linear scan over a few dozen sorted prefixes beats a trie on cache locality; no allocs either way.
	p.routes = slices.Clone(c.Routes)
	slices.SortFunc(p.routes, func(a, b Route) int { return cmp.Compare(len(b.Prefix), len(a.Prefix)) })
	s.cur.Store(p)
	return nil
}

// Config returns a copy, so callers can't mutate the live maps.
func (s *Store) Config() Config { return s.cur.Load().cfg.clone() }

func (s *Store) Resolve(apiKey, path string) Match {
	p := s.cur.Load()
	m, ok := p.keys[apiKey]
	if !ok {
		m = p.anon
	}
	m.Cost = 1
	for _, r := range p.routes {
		if strings.HasPrefix(path, r.Prefix) {
			m.Cost = r.Cost
			break
		}
	}
	return m
}

// Watch polls path's mtime and swaps in valid changes until ctx ends.
// An invalid file keeps the old config and reports through onErr.
func (s *Store) Watch(ctx context.Context, path string, every time.Duration, onErr func(error)) {
	var last time.Time
	var size int64
	if fi, err := os.Stat(path); err == nil {
		last, size = fi.ModTime(), fi.Size()
	}
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
