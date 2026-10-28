package limiter

import (
	"context"
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

// canonical spells an IP or CIDR one way, so "10.0.0.7/30" and "10.0.0.4/30" are the same ban.
// A single-address prefix becomes a plain IP, which is matched exactly.
func canonical(client string) string {
	if a, err := netip.ParseAddr(client); err == nil {
		return a.Unmap().String()
	}
	if p, err := netip.ParsePrefix(client); err == nil {
		if p = p.Masked(); p.IsSingleIP() {
			return p.Addr().String()
		}
		return p.String()
	}
	return client
}

// BanList is an in-process BanStore. Reads load an immutable snapshot with no lock, so the
// request path never contends with the rare writer, which copies the set.
type BanList struct {
	mu   sync.Mutex // serialises writers
	snap atomic.Pointer[banSnap]
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
	b.Client = canonical(b.Client)
	l.update(func(m map[string]Ban) { m[b.Client] = b })
	return nil
}

func (l *BanList) Unban(_ context.Context, client string) error {
	l.update(func(m map[string]Ban) { delete(m, canonical(client)) })
	return nil
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

// replace swaps in a full list, e.g. the bans read back from Redis.
func (l *BanList) replace(bans []Ban) {
	l.update(func(m map[string]Ban) {
		clear(m)
		for _, b := range bans {
			b.Client = canonical(b.Client)
			m[b.Client] = b
		}
	})
}

// update copies the set, applies f and publishes the copy. Expired bans are dropped on the way.
func (l *BanList) update(f func(map[string]Ban)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	m := maps.Clone(l.snap.Load().byClient)
	f(m)
	l.snap.Store(newSnap(m, time.Now()))
}
