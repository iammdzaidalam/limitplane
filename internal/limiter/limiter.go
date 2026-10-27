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

type Result struct {
	Allowed    bool
	Limit      int64
	Remaining  int64
	RetryAfter time.Duration
	ResetAfter time.Duration
	Degraded   bool // answered by the local fallback
}

// Limiter enforces short-term rate (bursts).
type Limiter interface {
	Allow(ctx context.Context, key string, r Rate, cost int64) (Result, error)
}

// Quota enforces a hard cap per calendar month (UTC).
type Quota interface {
	Spend(ctx context.Context, key string, limit, cost int64) (used int64, ok bool, err error)
}

// MonthKey scopes a quota key to the current UTC month, so it resets without a cron.
func MonthKey(key string, now time.Time) string {
	return key + ":" + now.UTC().Format("2006-01")
}
