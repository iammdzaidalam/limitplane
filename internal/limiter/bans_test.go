package limiter

import (
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestCanonical(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1":              "192.0.2.1",
		"::ffff:192.0.2.1":       "192.0.2.1",
		"10.0.0.7/30":            "10.0.0.4/30",
		"10.0.0.7/32":            "10.0.0.7",
		"10.0.0.7/0":             "0.0.0.0/0",
		"2001:DB8::1":            "2001:db8::1",
		"2001:db8::1/128":        "2001:db8::1",
		"2001:db8:ffff::/32":     "2001:db8::/32",
		"::ffff:10.1.2.3/104":    "10.0.0.0/8",
		"::ffff:0.0.0.0/96":      "0.0.0.0/0",
		"::ffff:10.1.2.3/128":    "10.1.2.3",
		"fe80::1%eth0":           "fe80::1%eth0",
		"2001:0db8:0000::/48":    "2001:db8::/48",
		"0000:0000::0001":        "::1",
		"10.0.0.0/8":             "10.0.0.0/8",
		"::/0":                   "::/0",
		"::ffff:192.0.2.128/121": "192.0.2.128/25",
	} {
		got, err := canonical(in)
		if err != nil || got != want {
			t.Errorf("canonical(%q) = %q %v, want %q", in, got, err, want)
		}
	}
	// Leading zeros are not an address netip accepts; clients are IPs, so a tenant id never matches.
	for _, bad := range []string{"::ffff:0.0.0.0/95", "::ffff:0:0/64", "::ffff:1.2.3.4/0", "not-an-ip", "192.168.001.001", "anon:192.0.2.1", ""} {
		if _, err := canonical(bad); !errors.Is(err, ErrBadBan) {
			t.Errorf("canonical(%q): %v, want ErrBadBan", bad, err)
		}
	}
}

func TestBanMatching(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		ban  string
		hits []string
		miss []string
	}{
		{"0.0.0.0/0", []string{"1.1.1.1", "::ffff:8.8.8.8", "255.255.255.255"}, []string{"::1", "2001:db8::1"}},
		{"::/0", []string{"::1", "2001:db8::1"}, []string{"1.1.1.1", "::ffff:1.1.1.1"}},
		{"::ffff:0:0/96", []string{"1.1.1.1", "10.0.0.1"}, []string{"2001:db8::1"}},
		{"2001:db8::/127", []string{"2001:db8::", "2001:db8::1"}, []string{"2001:db8::2"}},
		{"192.0.2.0/31", []string{"192.0.2.0", "192.0.2.1"}, []string{"192.0.2.2", "192.0.1.255"}},
		{"fe80::/10", []string{"fe80::1%eth0", "febf::1"}, []string{"fec0::1"}}, // a zoned client still falls in its prefix
	} {
		l := NewBanList()
		if err := l.Ban(ctx, Ban{Client: c.ban, Until: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		for _, ip := range c.hits {
			if _, ok := l.Banned(ip, now); !ok {
				t.Errorf("ban %s: %s not banned", c.ban, ip)
			}
		}
		for _, ip := range c.miss {
			if _, ok := l.Banned(ip, now); ok {
				t.Errorf("ban %s: %s banned", c.ban, ip)
			}
		}
	}
}

// Overlapping bans are independent: lifting one leaves the others, and each expires on its own.
func TestOverlappingBans(t *testing.T) {
	now := time.Now()
	l := NewBanList()
	for _, b := range []Ban{
		{Client: "10.0.0.0/8", Until: now.Add(time.Minute)},
		{Client: "10.1.0.0/16", Until: now.Add(time.Hour)},
		{Client: "10.1.2.3", Until: now.Add(2 * time.Hour)},
	} {
		l.Ban(ctx, b)
	}
	if _, ok := l.Banned("10.1.2.3", now.Add(90*time.Minute)); !ok {
		t.Fatal("exact ban must outlive the prefixes")
	}
	if _, ok := l.Banned("10.1.9.9", now.Add(30*time.Minute)); !ok {
		t.Fatal("/16 must outlive the /8")
	}
	if _, ok := l.Banned("10.2.0.1", now.Add(30*time.Minute)); ok {
		t.Fatal("/8 expired")
	}
	l.Unban(ctx, "10.1.0.0/16")
	if _, ok := l.Banned("10.1.9.9", now); !ok {
		t.Fatal("lifting the /16 lifted the /8 too")
	}
	if _, ok := l.Banned("10.1.2.3", now.Add(30*time.Minute)); !ok {
		t.Fatal("lifting the /16 lifted the exact ban")
	}
	l.Unban(ctx, "10.9.9.9") // nothing there: a no-op
	if bs, _ := l.Bans(ctx); len(bs) != 2 {
		t.Fatalf("bans %+v", bs)
	}
}

// A client caught by several bans is banned until the last of them ends, and Retry-After says so.
func TestOverlappingBansReportLatestExpiry(t *testing.T) {
	now := time.Now()
	l := NewBanList()
	l.Ban(ctx, Ban{Client: "10.1.2.3", Until: now.Add(time.Minute)})
	l.Ban(ctx, Ban{Client: "10.0.0.0/8", Until: now.Add(time.Hour)})
	if until, _ := l.Banned("10.1.2.3", now); !until.Equal(now.Add(time.Hour)) {
		t.Fatalf("banned until %v, want the /8's %v", until.Sub(now), time.Hour)
	}
}

func TestBanExpiry(t *testing.T) {
	now := time.Now()
	l := NewBanList()
	l.Ban(ctx, Ban{Client: "192.0.2.1", Until: now.Add(time.Minute)})
	l.Ban(ctx, Ban{Client: "198.51.100.0/24", Until: now.Add(time.Minute)})
	for _, ip := range []string{"192.0.2.1", "198.51.100.1"} {
		if until, ok := l.Banned(ip, now.Add(time.Minute-1)); !ok || !until.Equal(now.Add(time.Minute)) {
			t.Fatalf("%s: one ns before Until: %v %v", ip, until, ok)
		}
		if _, ok := l.Banned(ip, now.Add(time.Minute)); ok {
			t.Fatalf("%s: still banned at Until", ip)
		}
	}
	// Re-banning replaces the expiry, shorter or longer.
	l.Ban(ctx, Ban{Client: "192.0.2.1", Until: now.Add(time.Second), Reason: "shorter"})
	if until, _ := l.Banned("192.0.2.1", now); !until.Equal(now.Add(time.Second)) {
		t.Fatalf("re-ban kept the old expiry: %v", until)
	}
	// Bans lists live bans only, soonest first.
	l.Ban(ctx, Ban{Client: "203.0.113.9", Until: now.Add(time.Millisecond)})
	l.Ban(ctx, Ban{Client: "203.0.113.10", Until: now.Add(-time.Second)})
	time.Sleep(2 * time.Millisecond)
	bs, _ := l.Bans(ctx)
	if len(bs) != 2 || bs[0].Client != "192.0.2.1" || bs[1].Client != "198.51.100.0/24" {
		t.Fatalf("bans %+v", bs)
	}
	// A write rebuilds the snapshot without the expired entries.
	l.Ban(ctx, Ban{Client: "203.0.113.11", Until: now.Add(time.Hour)})
	if _, ok := l.snap.Load().byClient["203.0.113.9"]; ok {
		t.Fatal("expired ban kept in the snapshot")
	}
}

// Only a list tracking for Redis records writes made while it is the fallback.
func TestPendingWrites(t *testing.T) {
	until := time.Now().Add(time.Hour)
	l := NewBanList()
	l.Ban(ctx, Ban{Client: "192.0.2.1", Until: until})
	if p, _ := l.writes(); len(p) != 0 {
		t.Fatalf("untracked list recorded %v", p)
	}
	l.track()
	l.Ban(ctx, Ban{Client: "::ffff:192.0.2.2", Until: until, Reason: "r"})
	l.Unban(ctx, "192.0.2.1")
	l.Ban(ctx, Ban{Client: "192.0.2.3", Until: until})
	l.Unban(ctx, "192.0.2.3") // the last write per client wins
	p, seq := l.writes()
	if len(p) != 3 || p["192.0.2.2"] == nil || p["192.0.2.2"].Reason != "r" || p["192.0.2.1"] != nil || p["192.0.2.3"] != nil {
		t.Fatalf("pending %v", p)
	}

	// settle forgets a pushed write, but not one that replaced it meanwhile.
	pushed := p["192.0.2.2"]
	l.Ban(ctx, Ban{Client: "192.0.2.2", Until: until.Add(time.Hour), Reason: "newer"})
	l.settle("192.0.2.2", pushed)
	l.settle("192.0.2.1", p["192.0.2.1"])
	p2, seq2 := l.writes()
	if len(p2) != 2 || p2["192.0.2.2"].Reason != "newer" {
		t.Fatalf("settle: %v", p2)
	}

	// replace is refused when a write landed after the version it read.
	if l.replace(nil, seq) {
		t.Fatal("replace accepted a stale version")
	}
	// Otherwise Redis's list wins, with pending writes on top.
	if !l.replace([]Ban{
		{Client: "192.0.2.3", Until: until}, // pending unban: stays lifted
		{Client: "198.51.100.1", Until: until},
		{Client: "::ffff:0.0.0.0/80", Until: until}, // unusable: dropped
	}, seq2) {
		t.Fatal("replace refused a current version")
	}
	for ip, want := range map[string]bool{"192.0.2.2": true, "192.0.2.3": false, "198.51.100.1": true, "192.0.2.1": false} {
		if _, got := l.Banned(ip, time.Now()); got != want {
			t.Errorf("after replace %s banned %v, want %v", ip, got, want)
		}
	}

	// set and drop apply writes Redis already has, so they clear the pending entry.
	l.set(Ban{Client: "192.0.2.2", Until: until})
	l.drop("192.0.2.3")
	if p, _ := l.writes(); len(p) != 0 {
		t.Fatalf("pending after set/drop: %v", p)
	}
	l.set(Ban{Client: "::ffff:0:0/8", Until: until}) // unusable from a peer: ignored
	l.drop("::ffff:0:0/8")
}

// Reads take no lock: hammer them against writers under -race.
func TestBanListConcurrent(t *testing.T) {
	l := NewBanList()
	l.track()
	until := time.Now().Add(time.Hour)
	l.Ban(ctx, Ban{Client: "10.0.0.0/8", Until: until})
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Go(func() {
			for i := range 100 {
				c := "192.0." + strconv.Itoa(w) + "." + strconv.Itoa(i%256)
				l.Ban(ctx, Ban{Client: c, Until: until})
				if i%3 == 0 {
					l.Unban(ctx, c)
				}
			}
		})
	}
	for range 4 {
		wg.Go(func() {
			for range 1000 {
				if _, ok := l.Banned("10.9.9.9", time.Now()); !ok {
					t.Error("the /8 vanished during writes")
					return
				}
			}
		})
	}
	wg.Wait()
	if bs, _ := l.Bans(ctx); len(bs) != 1+4*(100-34) {
		t.Fatalf("%d bans after the writers, want %d", len(bs), 1+4*(100-34))
	}
}

// Clients are IPs, so a ban that is neither an IP nor a CIDR can never match anything. Accepting it
// (POST /api/bans answers 204) leaves an admin believing a range is blocked when it isn't.
func TestMalformedBanIsRefused(t *testing.T) {
	l := NewBanList()
	for _, bad := range []string{"10.0.0.0/33", "300.1.1.1", "10.0.0.0/8 ", "10.0.0.0/8,10.1.0.0/16"} {
		if err := l.Ban(ctx, Ban{Client: bad, Until: time.Now().Add(time.Hour)}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
