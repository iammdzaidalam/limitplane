package fastpath

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// These load the real program, so they need root (or CAP_BPF); xdp/test.sh runs them in its container.
func loadOrSkip(t *testing.T) *Fastpath {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	f := &Fastpath{}
	if err := loadFastpathObjects(&f.objs, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// frame builds an Ethernet frame from src, with optional VLAN tags, carrying a minimal IP header.
func frame(src string, vlans ...uint16) []byte {
	a := netip.MustParseAddr(src)
	b := make([]byte, 12, 80)
	for _, v := range vlans {
		b = binary.BigEndian.AppendUint16(b, 0x8100)
		b = binary.BigEndian.AppendUint16(b, v)
	}
	if a.Is4() {
		b = binary.BigEndian.AppendUint16(b, 0x0800)
		ip := make([]byte, 20)
		ip[0] = 0x45
		copy(ip[12:], a.AsSlice())
		return append(b, ip...)
	}
	b = binary.BigEndian.AppendUint16(b, 0x86DD)
	ip := make([]byte, 40)
	ip[0] = 0x60
	copy(ip[8:], a.AsSlice())
	return append(b, ip...)
}

const (
	xdpDrop = 1
	xdpPass = 2
)

func run(t *testing.T, f *Fastpath, src string, vlans ...uint16) uint32 {
	t.Helper()
	ret, err := f.objs.Fastpath.Run(&ebpf.RunOptions{Data: frame(src, vlans...)})
	if err != nil {
		t.Fatal(err)
	}
	return ret
}

func TestProgramBans(t *testing.T) {
	f := loadOrSkip(t)
	now := Monotonic()
	for p, d := range map[string]uint64{
		"192.0.2.0/24":      0,                         // no deadline
		"198.51.100.7":      now + uint64(time.Hour),   // live
		"198.51.100.8":      now - 1,                   // lapsed
		"192.0.2.9":         Exempt,                    // hole in the /24
		"2001:db8:1:2::/64": now + uint64(time.Minute), // IPv6 prefix
	} {
		pfx, _ := ParsePrefix(p)
		if err := f.Ban(pfx, d); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		src   string
		vlans []uint16
		want  uint32
	}{
		{"192.0.2.1", nil, xdpDrop},
		{"192.0.2.1", []uint16{10, 20}, xdpDrop}, // behind two VLAN tags
		{"192.0.2.9", nil, xdpPass},
		{"198.51.100.7", nil, xdpDrop},
		{"198.51.100.8", nil, xdpPass},
		{"203.0.113.1", nil, xdpPass},
		{"2001:db8:1:2::99", nil, xdpDrop},
		{"2001:db8:1:3::1", nil, xdpPass},
	} {
		if got := run(t, f, c.src, c.vlans...); got != c.want {
			t.Errorf("%s vlans=%v: verdict %d, want %d", c.src, c.vlans, got, c.want)
		}
	}
	if n, err := f.ActiveBans(); err != nil || n != 3 {
		t.Errorf("ActiveBans = %d, %v; want 3 (lapsed and exempt don't count)", n, err)
	}
	c, err := f.Counters()
	if err != nil || c.DropBan != 4 || c.Pass != 4 {
		t.Errorf("counters %+v, %v", c, err)
	}
}

func TestProgramRateAndExempt(t *testing.T) {
	f := loadOrSkip(t)
	r, _ := RateOf(1, 2) // 1 pps, burst 2: back-to-back packets past the burst drop
	if err := f.SetRate(r); err != nil {
		t.Fatal(err)
	}
	f.Exempt(netip.MustParsePrefix("10.0.0.1/32"))
	var drops, exemptDrops int
	for range 10 {
		if run(t, f, "10.0.0.2") == xdpDrop {
			drops++
		}
		if run(t, f, "10.0.0.1") == xdpDrop {
			exemptDrops++
		}
	}
	if drops != 8 || exemptDrops != 0 {
		t.Fatalf("drops=%d (want 8) exempt drops=%d (want 0)", drops, exemptDrops)
	}
	// IPv6 shares one budget per /64.
	run(t, f, "2001:db8::1")
	run(t, f, "2001:db8::2")
	if run(t, f, "2001:db8::3") != xdpDrop {
		t.Fatal("third packet from one /64 should be over the burst")
	}
}

func TestOpen(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF")
	}
	f, err := Attach("lo", true, Rate{})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Ban(netip.MustParsePrefix("192.0.2.1/32"), 0)
	g, err := Open("lo")
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if n, err := g.ActiveBans(); err != nil || n != 1 {
		t.Fatalf("ActiveBans via Open = %d, %v", n, err)
	}
	if _, err := g.Counters(); err != nil {
		t.Fatal(err)
	}
	g.Close() // closing the reader must leave the program attached
	h, err := Open("lo")
	if err != nil {
		t.Fatalf("program detached by the reader: %v", err)
	}
	h.Close()
}
