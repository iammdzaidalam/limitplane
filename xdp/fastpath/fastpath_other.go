//go:build !linux

package fastpath

import (
	"errors"
	"net/netip"
)

var errLinux = errors.New("XDP needs Linux")

// Fastpath is a stub off Linux so the loader and its tests still build.
type Fastpath struct{}

func Attach(string, bool, Rate) (*Fastpath, error) { return nil, errLinux }
func Open(string) (*Fastpath, error)               { return nil, errLinux }
func (*Fastpath) SetRate(Rate) error               { return errLinux }
func (*Fastpath) Ban(netip.Prefix, uint64) error   { return errLinux }
func (*Fastpath) Exempt(netip.Prefix) error        { return errLinux }
func (*Fastpath) Unban(netip.Prefix) error         { return errLinux }
func (*Fastpath) ActiveBans() (int, error)         { return 0, errLinux }
func (*Fastpath) Counters() (Counters, error)      { return Counters{}, errLinux }
func (*Fastpath) Close() error                     { return nil }
func Monotonic() uint64                            { return 0 }
