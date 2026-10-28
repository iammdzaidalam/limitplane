// Package fastpath loads the XDP program in bpf/fastpath.c and drives its maps.
package fastpath

import (
	"fmt"
	"net/netip"
	"strings"
)

// Regenerate the committed bindings (needs clang with a bpf target and llvm-strip):
//
//	BPF2GO_CC=/opt/homebrew/opt/llvm/bin/clang BPF2GO_STRIP=/opt/homebrew/opt/llvm/bin/llvm-strip go generate ./fastpath
//
//go:generate go tool bpf2go -tags linux -target bpfel fastpath ../bpf/fastpath.c

// Key mirrors struct ban_key. IPv4 is stored IPv4-mapped (::ffff:a.b.c.d) so one trie holds both families.
type Key struct {
	Prefixlen uint32 // host order
	Addr      [16]byte
}

// KeyOf encodes a ban prefix; an IPv4 /n becomes a mapped /96+n.
func KeyOf(p netip.Prefix) Key {
	p = p.Masked()
	bits := p.Bits()
	if p.Addr().Is4() {
		bits += 96
	}
	return Key{Prefixlen: uint32(bits), Addr: p.Addr().As16()}
}

// ParsePrefix reads a ban's client field: an address (the gateway's client IP) or a CIDR.
// Zones are dropped and IPv4-mapped IPv6 is unmapped, so one source has one key.
func ParsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.WithZone("").Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Rate mirrors struct rate_cfg: GCRA in nanoseconds. The zero value disables the guard.
type Rate struct {
	IntervalNS uint64
	BurstNS    uint64
}

// RateOf allows pps packets per second per source with bursts of up to burst packets.
func RateOf(pps, burst uint64) (Rate, error) {
	if pps == 0 {
		return Rate{}, nil
	}
	if pps > 1e9 {
		return Rate{}, fmt.Errorf("pps %d above 1e9", pps)
	}
	interval := 1e9 / pps
	return Rate{IntervalNS: interval, BurstNS: max(burst, 1) * interval}, nil
}

// Counters are the per-CPU stats summed over CPUs.
type Counters struct {
	Pass, DropBan, DropRate uint64
}

// Stat indexes, matching the enum in fastpath.c.
const (
	statPass = iota
	statDropBan
	statDropRate
)
