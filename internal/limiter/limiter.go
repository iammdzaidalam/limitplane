// Package limiter decides whether a key may spend cost units right now.
package limiter

import (
	"context"
	"time"
)

// Rate allows Limit units per Period, with bursts up to Burst.
type Rate struct {
	Limit  int64         `json:"limit"`
	Period time.Duration `json:"period"`
	Burst  int64         `json:"burst"`
}

// Interval is the time it takes to earn back one unit.
func (r Rate) Interval() time.Duration { return r.Period / time.Duration(r.Limit) }

// Reason says which check rejected a request. The values match the codes meterLua returns.
type Reason uint8

const (
	OK Reason = iota
	Banned
	Burst
	Monthly
)

type Result struct {
	Allowed    bool
	Reason     Reason
	Limit      int64
	Remaining  int64
	RetryAfter time.Duration
	ResetAfter time.Duration
	Used       int64 // monthly units used after this request (Check with a monthly cap only)
	Degraded   bool  // answered by the local fallback
}

// Request is one metered request.
type Request struct {
	Client string // ban key: the client IP
	Key    string // limit key: tenant id, or anon:<ip>
	Rate   Rate
	Cost   int64
	Month  int64 // monthly cap; 0 means none
}

// Limiter enforces short-term rate (bursts) only.
type Limiter interface {
	Allow(ctx context.Context, key string, r Rate, cost int64) (Result, error)
}

// Meter decides a whole request: ban, then monthly cap, then burst. Nothing is spent unless every
// check passes, so a burst reject never bills the month and a monthly reject never uses up burst.
type Meter interface {
	Check(ctx context.Context, q Request) (Result, error)
	Used(ctx context.Context, key string) (int64, error) // this month's spend (UTC)
}

// BanStore holds client bans: an IP, or a CIDR prefix such as 10.0.0.0/24.
type BanStore interface {
	Ban(ctx context.Context, b Ban) error
	Unban(ctx context.Context, client string) error
	Bans(ctx context.Context) ([]Ban, error) // active bans, soonest to expire first
}

// Backend is everything the gateway and admin plane need from a store.
type Backend interface {
	Limiter
	Meter
	BanStore
}
