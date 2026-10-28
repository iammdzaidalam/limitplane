package fastpath

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"unsafe"
)

func TestKeyOf(t *testing.T) {
	cases := []struct {
		in   string
		bits uint32
		addr string
	}{
		{"203.0.113.7", 128, "::ffff:203.0.113.7"},
		{"203.0.113.77/24", 120, "::ffff:203.0.113.0"},
		{"0.0.0.0/0", 96, "::ffff:0.0.0.0"},
		{"::ffff:198.51.100.1", 128, "::ffff:198.51.100.1"},
		{"::ffff:198.51.100.0/120", 120, "::ffff:198.51.100.0"},
		{"2001:db8::1", 128, "2001:db8::1"},
		{"2001:db8:1:2:3::/64", 64, "2001:db8:1:2::"},
		{"fe80::1%eth0", 128, "fe80::1"},
	}
	for _, c := range cases {
		p, err := ParsePrefix(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		k := KeyOf(p)
		if k.Prefixlen != c.bits || k.Addr != netip.MustParseAddr(c.addr).As16() {
			t.Errorf("%s: got /%d %v, want /%d %s", c.in, k.Prefixlen, netip.AddrFrom16(k.Addr), c.bits, c.addr)
		}
	}
}

func TestParsePrefixRejects(t *testing.T) {
	for _, s := range []string{"", "tenant-acme", "10.0.0.1/33", "1.2.3.4:80", "[::1]"} {
		if _, err := ParsePrefix(s); err == nil {
			t.Errorf("%q: want error", s)
		}
	}
}

// TestKeyLayout pins the Go key to struct ban_key: 4 bytes prefixlen, then 16 address bytes in network order.
func TestKeyLayout(t *testing.T) {
	if unsafe.Sizeof(Key{}) != 20 {
		t.Fatalf("Key is %d bytes, want 20", unsafe.Sizeof(Key{}))
	}
	k := KeyOf(netip.MustParsePrefix("10.1.2.0/24"))
	b, _ := binary.Append(nil, binary.NativeEndian, k)
	if binary.NativeEndian.Uint32(b) != 120 || [4]byte(b[16:]) != [4]byte{10, 1, 2, 0} || b[14] != 0xff || b[15] != 0xff {
		t.Fatalf("bad layout % x", b)
	}
}

func TestRateOf(t *testing.T) {
	if r, _ := RateOf(0, 100); r != (Rate{}) {
		t.Fatalf("pps 0 should disable, got %+v", r)
	}
	r, err := RateOf(1000, 50)
	if err != nil || r.IntervalNS != 1e6 || r.BurstNS != 50e6 {
		t.Fatalf("got %+v %v", r, err)
	}
	if r, _ := RateOf(10, 0); r.BurstNS != r.IntervalNS {
		t.Fatalf("burst 0 should mean 1 packet, got %+v", r)
	}
	if _, err := RateOf(2e9, 1); err == nil {
		t.Fatal("want error above 1e9 pps")
	}
}
