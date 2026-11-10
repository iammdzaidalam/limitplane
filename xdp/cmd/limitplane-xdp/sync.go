package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/iammdzaidalam/limitplane/xdp/fastpath"
)

// ban is the subset of autopilot.Ban that the fast path needs.
type ban struct {
	Client string    `json:"client"`
	Until  time.Time `json:"until"`
}

// gateway reads bans from the LimitPlane admin API. Not safe for concurrent use.
type gateway struct {
	base  string // admin root: http://host:port, or .../_limitplane in proxy mode
	key   string
	hc    *http.Client
	token string
}

// bans logs in only when there is no token or it was rejected: /api/login is rate-limited to 5/min.
func (g *gateway) bans(ctx context.Context) ([]ban, error) {
	for retried := false; ; retried = true {
		if g.token == "" {
			if err := g.login(ctx); err != nil {
				return nil, err
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.base+"/api/bans", nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+g.token)
		var out []ban
		err = g.do(req, &out)
		var se statusError
		if errors.As(err, &se) && se == http.StatusUnauthorized && !retried {
			g.token = "" // expired, or the gateway restarted with another key
			continue
		}
		return out, err
	}
}

func (g *gateway) login(ctx context.Context) error {
	body, _ := json.Marshal(map[string]string{"key": g.key})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.base+"/api/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	var out struct{ Token string }
	if err := g.do(req, &out); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	g.token = out.Token
	return nil
}

type statusError int

func (e statusError) Error() string {
	return fmt.Sprintf("HTTP %d %s", int(e), http.StatusText(int(e)))
}

func (g *gateway) do(req *http.Request, v any) error {
	res, err := g.hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return statusError(res.StatusCode)
	}
	return json.NewDecoder(res.Body).Decode(v)
}

type banMap interface {
	Ban(p netip.Prefix, deadline uint64) error
	Unban(netip.Prefix) error
}

// installed is one prefix in the kernel map.
type installed struct {
	until    time.Time // the gateway's expiry, for expire()
	deadline uint64    // what the map holds: CLOCK_MONOTONIC ns, 0 = none
}

// syncer mirrors the gateway's ban list into the kernel map.
type syncer struct {
	m       banMap
	mono    func() uint64  // CLOCK_MONOTONIC now, in ns
	exempt  []netip.Prefix // never banned; a ban inside one is skipped
	have    map[netip.Prefix]installed
	skipped int // clients in the last list that aren't IPs or CIDRs, or are exempt
}

// slack is how far a deadline may drift before it is rewritten. The two clocks are read afresh every
// sync, so a wall-clock step (NTP, a VM resuming) is corrected within one tick; the slack absorbs the
// sub-millisecond jitter between reads and a Redis-backed gateway's TTL rounding.
const slack = 100 * time.Millisecond

// apply diffs the unexpired bans against what is installed, so a steady state costs no syscalls.
// Failed writes are not recorded and get retried next time.
func (s *syncer) apply(bans []ban, now time.Time) (added, removed int, err error) {
	mono := s.mono()
	want := make(map[netip.Prefix]time.Time, len(bans))
	s.skipped = 0
	for _, b := range bans {
		p, err := fastpath.ParsePrefix(strings.TrimSpace(b.Client))
		if err != nil || s.isExempt(p) {
			s.skipped++
			continue
		}
		if now.Before(b.Until) && b.Until.After(want[p]) {
			want[p] = b.Until
		}
	}
	var errs []error
	for p := range s.have {
		if _, ok := want[p]; ok {
			continue
		}
		if err := s.m.Unban(p); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(s.have, p)
		removed++
	}
	cover := covering(want)
	for p, until := range want {
		d := deadline(mono, cover[p].Sub(now))
		old, ok := s.have[p]
		if !ok || absDiff(old.deadline, d) > uint64(slack) { // 0 (none) vs a real deadline differs by the uptime
			if err := s.m.Ban(p, d); err != nil {
				errs = append(errs, fmt.Errorf("ban %s: %w", p, err))
				continue
			}
			if !ok {
				added++
			}
			old.deadline = d
		}
		s.have[p] = installed{until, old.deadline}
	}
	return added, removed, errors.Join(errs...)
}

// covering gives each prefix the latest expiry of any ban containing it, itself included. The trie only
// returns the longest match, so a /32 inside a /24 must not lapse before the /24 does.
func covering(want map[netip.Prefix]time.Time) map[netip.Prefix]time.Time {
	var lens []int
	for p := range want {
		if !slices.Contains(lens, p.Bits()) {
			lens = append(lens, p.Bits())
		}
	}
	out := make(map[netip.Prefix]time.Time, len(want))
	for p, until := range want {
		for _, n := range lens {
			if n < p.Bits() {
				if u, ok := want[netip.PrefixFrom(p.Addr(), n).Masked()]; ok && u.After(until) {
					until = u
				}
			}
		}
		out[p] = until
	}
	return out
}

// deadline turns time left into a CLOCK_MONOTONIC deadline; one too far out to represent never lapses.
func deadline(mono uint64, left time.Duration) uint64 {
	const forever = 100 * 365 * 24 * time.Hour
	if left >= forever {
		return 0
	}
	return mono + uint64(max(left, 1))
}

func absDiff(a, b uint64) uint64 { return max(a, b) - min(a, b) }

func (s *syncer) isExempt(p netip.Prefix) bool {
	for _, e := range s.exempt {
		if e.Bits() <= p.Bits() && e.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// expire is the fallback while the gateway is unreachable: keep known bans until they run out.
// The kernel lapses them on time by itself; this deletes them from the map.
func (s *syncer) expire(now time.Time) (removed int, err error) {
	bans := make([]ban, 0, len(s.have))
	for p, in := range s.have {
		bans = append(bans, ban{Client: p.String(), Until: in.until})
	}
	skipped := s.skipped
	_, removed, err = s.apply(bans, now)
	s.skipped = skipped
	return removed, err
}
