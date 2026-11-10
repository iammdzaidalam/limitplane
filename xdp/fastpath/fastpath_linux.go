package fastpath

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Fastpath is the loaded program attached to one interface.
type Fastpath struct {
	objs fastpathObjects
	link link.Link
}

// Attach loads the program and attaches it to iface, in the driver (native) or generic (skb) hook.
func Attach(iface string, generic bool, r Rate) (*Fastpath, error) {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	// Kernels before 5.11 charge BPF maps to RLIMIT_MEMLOCK.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}
	f := &Fastpath{}
	if err := loadFastpathObjects(&f.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier: %+v", ve)
		}
		return nil, err
	}
	if err := f.SetRate(r); err != nil {
		f.objs.Close()
		return nil, err
	}
	flags := link.XDPDriverMode
	if generic {
		flags = link.XDPGenericMode
	}
	f.link, err = link.AttachXDP(link.XDPOptions{Program: f.objs.Fastpath, Interface: ifc.Index, Flags: flags})
	if err != nil {
		f.objs.Close()
		return nil, fmt.Errorf("attach to %s: %w", iface, err)
	}
	return f, nil
}

// Open finds the program a running loader attached to iface and opens its maps, for read-only use.
func Open(iface string) (*Fastpath, error) {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	it := new(link.Iterator)
	defer it.Close()
	for it.Next() {
		info, err := it.Link.Info()
		if err != nil || info.XDP() == nil || info.XDP().Ifindex != uint32(ifc.Index) {
			continue
		}
		prog, err := ebpf.NewProgramFromID(info.Program)
		if err != nil {
			return nil, err
		}
		pi, err := prog.Info()
		prog.Close()
		if err != nil {
			return nil, err
		}
		if pi.Name != fastpathProgFastpath {
			continue
		}
		ids, _ := pi.MapIDs()
		f := &Fastpath{}
		for _, id := range ids {
			m, err := ebpf.NewMapFromID(id)
			if err != nil {
				f.Close()
				return nil, err
			}
			mi, err := m.Info()
			switch {
			case err == nil && mi.Name == fastpathMapBans:
				f.objs.Bans = m
			case err == nil && mi.Name == fastpathMapStats:
				f.objs.Stats = m
			default:
				m.Close()
			}
		}
		if f.objs.Bans == nil || f.objs.Stats == nil {
			f.Close()
			return nil, fmt.Errorf("program on %s has no bans or stats map", iface)
		}
		return f, nil
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("no limitplane-xdp program attached to %s", iface)
}

func (f *Fastpath) SetRate(r Rate) error { return f.objs.Config.Put(uint32(0), r) }

// Ban drops p until the CLOCK_MONOTONIC deadline (nanoseconds, 0 = no deadline).
func (f *Fastpath) Ban(p netip.Prefix, deadline uint64) error {
	return f.objs.Bans.Put(KeyOf(p), deadline)
}

// Exempt makes the program always pass p, even inside a banned range, and skip its pps guard.
func (f *Fastpath) Exempt(p netip.Prefix) error { return f.objs.Bans.Put(KeyOf(p), uint64(Exempt)) }

func (f *Fastpath) Unban(p netip.Prefix) error {
	if err := f.objs.Bans.Delete(KeyOf(p)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// ActiveBans counts the entries the program would drop on now: neither exempt nor lapsed.
func (f *Fastpath) ActiveBans() (int, error) {
	var (
		k     Key
		until uint64
		n     int
	)
	now := Monotonic()
	it := f.objs.Bans.Iterate()
	for it.Next(&k, &until) {
		if until == 0 || until > now { // Exempt (1) is always in the past

			n++
		}
	}
	return n, it.Err()
}

func (f *Fastpath) Counters() (Counters, error) {
	var c Counters
	for i, dst := range []*uint64{statPass: &c.Pass, statDropBan: &c.DropBan, statDropRate: &c.DropRate} {
		var perCPU []uint64
		if err := f.objs.Stats.Lookup(uint32(i), &perCPU); err != nil {
			return c, err
		}
		for _, n := range perCPU {
			*dst += n
		}
	}
	return c, nil
}

// Close detaches the program (if this process attached it) and closes its maps.
func (f *Fastpath) Close() error {
	var err error
	if f.link != nil {
		err = f.link.Close()
	}
	return errors.Join(err, f.objs.Close())
}

// Monotonic reads CLOCK_MONOTONIC in nanoseconds, the clock bpf_ktime_get_ns uses.
func Monotonic() uint64 {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts) // cannot fail for this clock
	return uint64(ts.Nano())
}
