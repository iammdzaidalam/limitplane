package main

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/xdp/fastpath"
)

// fakeMap records map writes; fail makes the next writes for a prefix error.
type fakeMap struct {
	m      map[netip.Prefix]bool
	writes int
	fail   map[netip.Prefix]bool
}

func (f *fakeMap) Ban(p netip.Prefix) error {
	f.writes++
	if f.fail[p] {
		return errors.New("map full")
	}
	f.m[p] = true
	return nil
}

func (f *fakeMap) Unban(p netip.Prefix) error {
	f.writes++
	if f.fail[p] {
		return errors.New("busy")
	}
	delete(f.m, p)
	return nil
}

func (f *fakeMap) keys() []string {
	var out []string
	for p := range f.m {
		out = append(out, p.String())
	}
	slices.Sort(out)
	return out
}

func newSyncer() (*syncer, *fakeMap) {
	f := &fakeMap{m: map[netip.Prefix]bool{}, fail: map[netip.Prefix]bool{}}
	return &syncer{m: f, have: map[netip.Prefix]time.Time{}}, f
}

func TestApplyDiffs(t *testing.T) {
	s, f := newSyncer()
	now := time.Now()
	later := now.Add(time.Minute)
	bans := []ban{
		{"203.0.113.7", later},
		{"::ffff:203.0.113.7", later.Add(time.Minute)}, // same source, longer ban wins
		{"198.51.100.0/24", later},
		{"2001:db8::1", later},
		{"10.0.0.1", now}, // already expired
		{"acme-tenant", later},
	}
	added, removed, err := s.apply(bans, now)
	if err != nil || added != 3 || removed != 0 {
		t.Fatalf("first sync: +%d -%d %v", added, removed, err)
	}
	if got := f.keys(); !slices.Equal(got, []string{"198.51.100.0/24", "2001:db8::1/128", "203.0.113.7/32"}) {
		t.Fatalf("map = %v", got)
	}
	if s.skipped != 1 || !s.have[netip.MustParsePrefix("203.0.113.7/32")].Equal(later.Add(time.Minute)) {
		t.Fatalf("skipped=%d have=%v", s.skipped, s.have)
	}

	// Same list again: no syscalls.
	w := f.writes
	if added, removed, _ := s.apply(bans, now); added+removed != 0 || f.writes != w {
		t.Fatalf("steady state wrote: +%d -%d writes %d->%d", added, removed, w, f.writes)
	}

	// One ban lifted, one new, and time passes the /24's expiry.
	bans = []ban{{"203.0.113.7", later.Add(time.Minute)}, {"198.51.100.0/24", later}, {"192.0.2.9", later.Add(time.Hour)}}
	added, removed, err = s.apply(bans, later)
	if err != nil || added != 1 || removed != 2 {
		t.Fatalf("second sync: +%d -%d %v", added, removed, err)
	}
	if got := f.keys(); !slices.Equal(got, []string{"192.0.2.9/32", "203.0.113.7/32"}) {
		t.Fatalf("map = %v", got)
	}
}

func TestApplyRetriesFailedWrites(t *testing.T) {
	s, f := newSyncer()
	now := time.Now()
	p := netip.MustParsePrefix("192.0.2.1/32")
	bans := []ban{{"192.0.2.1", now.Add(time.Hour)}}

	f.fail[p] = true
	if _, _, err := s.apply(bans, now); err == nil || len(s.have) != 0 {
		t.Fatalf("failed ban should error and not be recorded: %v %v", err, s.have)
	}
	f.fail[p] = false
	if added, _, err := s.apply(bans, now); err != nil || added != 1 {
		t.Fatalf("retry: +%d %v", added, err)
	}

	f.fail[p] = true
	if _, _, err := s.apply(nil, now); err == nil || len(s.have) != 1 {
		t.Fatalf("failed unban should stay recorded: %v %v", err, s.have)
	}
	f.fail[p] = false
	if _, removed, err := s.apply(nil, now); err != nil || removed != 1 || len(f.m) != 0 {
		t.Fatalf("retry unban: -%d %v %v", removed, err, f.m)
	}
}

func TestExpireKeepsBansWhileGatewayDown(t *testing.T) {
	s, f := newSyncer()
	now := time.Now()
	s.apply([]ban{{"192.0.2.1", now.Add(time.Second)}, {"2001:db8::/48", now.Add(time.Hour)}, {"bad", now.Add(time.Hour)}}, now)
	if removed, err := s.expire(now); removed != 0 || err != nil || len(f.m) != 2 {
		t.Fatalf("nothing expired yet: -%d %v %v", removed, err, f.m)
	}
	if removed, _ := s.expire(now.Add(2 * time.Second)); removed != 1 || f.keys()[0] != "2001:db8::/48" {
		t.Fatalf("want only the IPv6 ban left: -%d %v", removed, f.keys())
	}
	if s.skipped != 1 {
		t.Fatalf("expire must keep the last skipped count, got %d", s.skipped)
	}
}

// fakeGateway mimics /api/login and /api/bans.
func fakeGateway(t *testing.T, bans []ban) (*httptest.Server, *int, *string) {
	logins, valid := 0, ""
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Key string }
		json.NewDecoder(r.Body).Decode(&body)
		if body.Key != "k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		logins++
		valid = "tok" + strings.Repeat("x", logins)
		json.NewEncoder(w).Encode(map[string]string{"token": valid})
	})
	mux.HandleFunc("GET /api/bans", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(bans)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &logins, &valid
}

func TestGatewayLogsInOnceAndOnExpiry(t *testing.T) {
	until := time.Now().Add(time.Minute).UTC().Truncate(time.Second)
	srv, logins, valid := fakeGateway(t, []ban{{"192.0.2.1", until}})
	g := &gateway{base: srv.URL, key: "k", hc: srv.Client()}
	ctx := context.Background()

	for range 3 {
		got, err := g.bans(ctx)
		if err != nil || len(got) != 1 || got[0].Client != "192.0.2.1" || !got[0].Until.Equal(until) {
			t.Fatalf("bans = %v, %v", got, err)
		}
	}
	if *logins != 1 {
		t.Fatalf("logins = %d, want 1 (token reused)", *logins)
	}
	*valid = "rotated" // the gateway restarted: old token now 401s
	if _, err := g.bans(ctx); err != nil || *logins != 2 {
		t.Fatalf("relogin: %v, logins=%d", err, *logins)
	}

	g.key, g.token = "wrong", ""
	_, err := g.bans(ctx)
	var se statusError
	if !errors.As(err, &se) || se != http.StatusUnauthorized {
		t.Fatalf("bad key: %v", err)
	}
}

func TestMetricsText(t *testing.T) {
	st := &state{bans: 2, skipped: 1, errs: 3, lastSync: time.UnixMilli(1700000000500)}
	var b strings.Builder
	st.write(&b, fastpath.Counters{Pass: 10, DropBan: 20, DropRate: 30})
	got := map[string]string{}
	for line := range strings.Lines(b.String()) {
		if !strings.HasPrefix(line, "#") {
			k, v, _ := strings.Cut(strings.TrimSpace(line), " ")
			got[k] = v
		}
	}
	want := map[string]string{
		`limitplane_xdp_packets_total{action="pass"}`:      "10",
		`limitplane_xdp_packets_total{action="drop_ban"}`:  "20",
		`limitplane_xdp_packets_total{action="drop_rate"}`: "30",
		"limitplane_xdp_bans":                              "2",
		"limitplane_xdp_bans_skipped":                      "1",
		"limitplane_xdp_sync_errors_total":                 "3",
		"limitplane_xdp_last_sync_timestamp_seconds":       "1700000000.500",
	}
	if !maps.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
}
