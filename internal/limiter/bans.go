package limiter

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

type Ban struct {
	Client string    `json:"client"`
	Until  time.Time `json:"until"`
	Reason string    `json:"reason"`
}

// ErrBadBan is a ban on an IPv4-mapped prefix shorter than /96, which would span non-IPv4 space.
var ErrBadBan = errors.New("limiter: an IPv4-mapped prefix must be /96 or longer")

// canonical spells an IP or CIDR one way, so "10.0.0.7/30" and "10.0.0.4/30" are the same ban.
// A single-address prefix becomes a plain IP, which is matched exactly, and an IPv4-mapped prefix
// becomes its IPv4 one (clients are unmapped before matching).
func canonical(client string) (string, error) {
	if a, err := netip.ParseAddr(client); err == nil {
		return a.Unmap().String(), nil
	}
	if p, err := netip.ParsePrefix(client); err == nil {
		if a := p.Addr(); a.Is4In6() {
			if p.Bits() < 96 {
				return "", ErrBadBan
			}
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		if p = p.Masked(); p.IsSingleIP() {
			return p.Addr().String(), nil
		}
		return p.String(), nil
	}
	return client, nil
}

// BanList is an in-process BanStore. Reads load an immutable snapshot with no lock, so the
// request path never contends with the rare writer, which copies the set.
//
// Behind Redis it is the cache every check reads, and Ban/Unban on it only happen while Redis is
// down (the fallback). Those writes are kept as pending and pushed to Redis when it is back.
type BanList struct {
	mu       sync.Mutex // serialises writers
	snap     atomic.Pointer[banSnap]
	seq      uint64          // bumped by every write
	tracking bool            // set by NewRedis
	pending  map[string]*Ban // client -> ban to push, or nil for an unban
}

type banSnap struct {
	byClient map[string]Ban             // every ban, by canonical client
	nets     map[netip.Prefix]time.Time // CIDR bans
	bits     []int                      // distinct prefix lengths in nets
}

func NewBanList() *BanList {
	l := &BanList{}
	l.snap.Store(newSnap(nil, time.Now()))
	return l
}

// newSnap indexes the unexpired bans.
func newSnap(bans map[string]Ban, now time.Time) *banSnap {
	s := &banSnap{byClient: map[string]Ban{}, nets: map[netip.Prefix]time.Time{}}
	for c, b := range bans {
		if !now.Before(b.Until) {
			continue
		}
		s.byClient[c] = b
		if p, err := netip.ParsePrefix(c); err == nil {
			s.nets[p] = b.Until
			if !slices.Contains(s.bits, p.Bits()) {
				s.bits = append(s.bits, p.Bits())
			}
		}
	}
	return s
}

// Banned matches client exactly (O(1)), then against each CIDR length in use: one map lookup per
// distinct length, not per ban.
func (l *BanList) Banned(client string, now time.Time) (time.Time, bool) {
	s := l.snap.Load()
	if b, ok := s.byClient[client]; ok && now.Before(b.Until) {
		return b.Until, true
	}
	return s.inNet(client, now)
}

func (s *banSnap) inNet(client string, now time.Time) (time.Time, bool) {
	if len(s.bits) == 0 {
		return time.Time{}, false
	}
	a, err := netip.ParseAddr(client)
	if err != nil {
		return time.Time{}, false
	}
	a = a.Unmap()
	for _, bits := range s.bits {
		p, err := a.Prefix(bits) // errors when bits is too long for a's family
		if until, ok := s.nets[p]; err == nil && ok && now.Before(until) {
			return until, true
		}
	}
	return time.Time{}, false
}

func (l *BanList) Ban(_ context.Context, b Ban) error {
	var err error
	if b.Client, err = canonical(b.Client); err != nil {
		return err
	}
	l.update(func(m map[string]Ban) {
		m[b.Client] = b
		l.mark(b.Client, &b)
	})
	return nil
}

func (l *BanList) Unban(_ context.Context, client string) error {
	c, err := canonical(client)
	if err != nil {
		return err
	}
	l.update(func(m map[string]Ban) {
		delete(m, c)
		l.mark(c, nil)
	})
	return nil
}

func (l *BanList) mark(client string, b *Ban) {
	if l.tracking {
		l.pending[client] = b
	}
}

// set and drop apply a write that is already in Redis (ours, or one another replica published).
// It is newer than anything pending for that client, so that is dropped.
func (l *BanList) set(b Ban) {
	var err error
	if b.Client, err = canonical(b.Client); err != nil {
		return
	}
	l.update(func(m map[string]Ban) {
		m[b.Client] = b
		delete(l.pending, b.Client)
	})
}

func (l *BanList) drop(client string) {
	c, err := canonical(client)
	if err != nil {
		return
	}
	l.update(func(m map[string]Ban) {
		delete(m, c)
		delete(l.pending, c)
	})
}

func (l *BanList) track() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tracking = true
	if l.pending == nil {
		l.pending = map[string]*Ban{}
	}
}

// writes returns the pending writes and the current version, for a sync to push and then compare.
func (l *BanList) writes() (map[string]*Ban, uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return maps.Clone(l.pending), l.seq
}

// settle forgets a pushed write, unless a newer one for the client replaced it meanwhile.
func (l *BanList) settle(client string, b *Ban) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if p, ok := l.pending[client]; ok && p == b {
		delete(l.pending, client)
	}
}

func (l *BanList) Bans(context.Context) ([]Ban, error) {
	out := make([]Ban, 0)
	now := time.Now()
	for _, b := range l.snap.Load().byClient {
		if now.Before(b.Until) {
			out = append(out, b)
		}
	}
	slices.SortFunc(out, func(a, b Ban) int { return a.Until.Compare(b.Until) })
	return out, nil
}

// replace swaps in the list read back from Redis, unless a write landed after version seq was
// read (the list may predate it; the next sync catches up). Pending writes stay on top.
func (l *BanList) replace(bans []Ban, seq uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seq != seq {
		return false
	}
	m := make(map[string]Ban, len(bans))
	for _, b := range bans {
		if c, err := canonical(b.Client); err == nil {
			b.Client = c
			m[c] = b
		}
	}
	for c, b := range l.pending {
		if b == nil {
			delete(m, c)
		} else {
			m[c] = *b
		}
	}
	l.store(m)
	return true
}

// update copies the set, applies f and publishes the copy. Expired bans are dropped on the way.
func (l *BanList) update(f func(map[string]Ban)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	m := maps.Clone(l.snap.Load().byClient)
	f(m)
	l.store(m)
}

func (l *BanList) store(m map[string]Ban) {
	l.seq++
	l.snap.Store(newSnap(m, time.Now()))
}
