package fastpath

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
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

func (f *Fastpath) SetRate(r Rate) error { return f.objs.Config.Put(uint32(0), r) }

func (f *Fastpath) Ban(p netip.Prefix) error { return f.objs.Bans.Put(KeyOf(p), uint8(1)) }

func (f *Fastpath) Unban(p netip.Prefix) error {
	if err := f.objs.Bans.Delete(KeyOf(p)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
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

// Close detaches the program and frees its maps.
func (f *Fastpath) Close() error {
	return errors.Join(f.link.Close(), f.objs.Close())
}
