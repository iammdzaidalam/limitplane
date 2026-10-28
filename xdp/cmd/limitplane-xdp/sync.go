package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
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
	Ban(netip.Prefix) error
	Unban(netip.Prefix) error
}

// syncer mirrors the gateway's ban list into the kernel map.
type syncer struct {
	m       banMap
	have    map[netip.Prefix]time.Time // installed prefix -> expiry
	skipped int                        // clients in the last list that aren't IPs or CIDRs
}

// apply diffs the unexpired bans against what is installed, so a steady state costs no syscalls.
// Failed writes are not recorded and get retried next time.
func (s *syncer) apply(bans []ban, now time.Time) (added, removed int, err error) {
	want := make(map[netip.Prefix]time.Time, len(bans))
	s.skipped = 0
	for _, b := range bans {
		p, err := fastpath.ParsePrefix(strings.TrimSpace(b.Client))
		if err != nil {
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
	for p, until := range want {
		if _, ok := s.have[p]; !ok {
			if err := s.m.Ban(p); err != nil {
				errs = append(errs, fmt.Errorf("ban %s: %w", p, err))
				continue
			}
			added++
		}
		s.have[p] = until
	}
	return added, removed, errors.Join(errs...)
}

// expire is the fallback while the gateway is unreachable: keep known bans until they run out.
func (s *syncer) expire(now time.Time) (removed int, err error) {
	bans := make([]ban, 0, len(s.have))
	for p, until := range s.have {
		bans = append(bans, ban{Client: p.String(), Until: until})
	}
	skipped := s.skipped
	_, removed, err = s.apply(bans, now)
	s.skipped = skipped
	return removed, err
}
