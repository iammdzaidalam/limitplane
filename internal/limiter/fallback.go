package limiter

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

// cooldown is how long a failing primary is skipped, so a dead Redis costs one timeout, not one per request.
const cooldown = time.Second

type breaker struct{ openUntil atomic.Int64 }

func (b *breaker) closed() bool { return time.Now().UnixNano() >= b.openUntil.Load() }
func (b *breaker) trip()        { b.openUntil.Store(time.Now().Add(cooldown).UnixNano()) }

// failover reports whether err should send us to the backup (not caller cancels or bad input).
func (b *breaker) failover(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil || errors.Is(err, ErrInvalid) {
		return false
	}
	b.trip()
	return true
}

type fallback struct {
	primary, backup Limiter
	breaker
}

// NewFallback answers from backup, marked Degraded, while primary is failing.
func NewFallback(primary, backup Limiter) Limiter {
	return &fallback{primary: primary, backup: backup}
}

func (f *fallback) Allow(ctx context.Context, key string, r Rate, cost int64) (Result, error) {
	if f.closed() {
		res, err := f.primary.Allow(ctx, key, r, cost)
		if !f.failover(ctx, err) {
			return res, err
		}
	}
	res, err := f.backup.Allow(ctx, key, r, cost)
	res.Degraded = true
	return res, err
}

type fallbackQuota struct {
	primary, backup Quota
	breaker
}

// NewFallbackQuota is NewFallback for Quota. The backup counts from zero, so a long outage can over-admit.
func NewFallbackQuota(primary, backup Quota) Quota {
	return &fallbackQuota{primary: primary, backup: backup}
}

func (f *fallbackQuota) Spend(ctx context.Context, key string, limit, cost int64) (int64, bool, error) {
	if f.closed() {
		used, ok, err := f.primary.Spend(ctx, key, limit, cost)
		if !f.failover(ctx, err) {
			return used, ok, err
		}
	}
	return f.backup.Spend(ctx, key, limit, cost)
}
