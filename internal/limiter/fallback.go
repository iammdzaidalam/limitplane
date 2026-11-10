package limiter

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/redisx"
)

// cooldown is how long a failing primary is skipped, so a dead Redis costs one timeout, not one per request.
const cooldown = time.Second

type breaker struct{ openUntil atomic.Int64 }

func (b *breaker) closed() bool { return time.Now().UnixNano() >= b.openUntil.Load() }
func (b *breaker) trip()        { b.openUntil.Store(time.Now().Add(cooldown).UnixNano()) }

// failover reports whether err should send us to the backup (not caller cancels or bad input).
// One Cluster node failing sends just this request there: redisx already skips that node, and
// tenants on the other nodes stay shared.
func (b *breaker) failover(ctx context.Context, err error) bool {
	if err == nil || redisx.CallerGaveUp(ctx, err) || errors.Is(err, ErrInvalid) || errors.Is(err, ErrBadBan) {
		return false
	}
	if !errors.Is(err, redisx.ErrNodeDown) {
		b.trip()
	}
	return true
}

type fallback struct {
	primary, backup Backend
	replicas        func() int
	breaker
}

// NewFallback answers from backup, marked Degraded, while primary is failing. Every replica then
// limits on its own, so each gets 1/replicas() of the budget (burst, monthly cap and org budget);
// nil replicas means 1. The backup's monthly counts start from zero, so an outage can admit up to
// about one more month's cap across the fleet.
func NewFallback(primary, backup Backend, replicas func() int) Backend {
	if replicas == nil {
		replicas = func() int { return 1 }
	}
	return &fallback{primary: primary, backup: backup, replicas: replicas}
}

// run calls op on the primary unless it is failing, else on the backup (degraded = true).
func run[T any](ctx context.Context, f *fallback, op func(b Backend, degraded bool) (T, error)) (T, bool, error) {
	if f.closed() {
		v, err := op(f.primary, false)
		if !f.failover(ctx, err) {
			return v, false, err
		}
	}
	v, err := op(f.backup, true)
	return v, true, err
}

func (f *fallback) Allow(ctx context.Context, key string, r Rate, cost int64) (Result, error) {
	res, deg, err := run(ctx, f, func(b Backend, deg bool) (Result, error) {
		if deg {
			r = share(r, f.replicas(), cost)
		}
		return b.Allow(ctx, key, r, cost)
	})
	res.Degraded = deg
	return res, err
}

func (f *fallback) Check(ctx context.Context, q Request) (Result, error) {
	res, deg, err := run(ctx, f, func(b Backend, deg bool) (Result, error) {
		if deg {
			n := f.replicas()
			q.Rate = share(q.Rate, n, q.Cost)
			q.Month, q.OrgMonth = part(q.Month, n, q.Cost), part(q.OrgMonth, n, q.Cost)
		}
		return b.Check(ctx, q)
	})
	res.Degraded = deg
	return res, err
}

func (f *fallback) Used(ctx context.Context, key string) (int64, error) {
	return f.UsedIn(ctx, key, "")
}

func (f *fallback) UsedIn(ctx context.Context, key, org string) (int64, error) {
	n, _, err := run(ctx, f, func(b Backend, _ bool) (int64, error) { return b.UsedIn(ctx, key, org) })
	return n, err
}

func (f *fallback) OrgUsed(ctx context.Context, org string) (int64, error) {
	n, _, err := run(ctx, f, func(b Backend, _ bool) (int64, error) { return b.OrgUsed(ctx, org) })
	return n, err
}

func (f *fallback) Move(ctx context.Context, key, from, to string) error {
	_, _, err := run(ctx, f, func(b Backend, _ bool) (struct{}, error) { return struct{}{}, b.Move(ctx, key, from, to) })
	return err
}

func (f *fallback) Ban(ctx context.Context, x Ban) error {
	_, _, err := run(ctx, f, func(b Backend, _ bool) (struct{}, error) { return struct{}{}, b.Ban(ctx, x) })
	return err
}

func (f *fallback) Unban(ctx context.Context, client string) error {
	_, _, err := run(ctx, f, func(b Backend, _ bool) (struct{}, error) { return struct{}{}, b.Unban(ctx, client) })
	return err
}

func (f *fallback) Bans(ctx context.Context) ([]Ban, error) {
	bs, _, err := run(ctx, f, func(b Backend, _ bool) ([]Ban, error) { return b.Bans(ctx) })
	return bs, err
}

// share is one replica's slice of r while n replicas each fall back on their own, so together they
// admit about r. Stretching the period keeps the rate exact (Limit/n would truncate). Burst never
// drops below cost (itself >= 1), or a route would be blocked outright instead of slowed.
func share(r Rate, n int, cost int64) Rate {
	if n <= 1 {
		return r
	}
	return Rate{Limit: r.Limit, Period: r.Period * time.Duration(n), Burst: max(r.burst()/int64(n), cost)}
}

// part is one replica's share of a monthly cap (0: none), never below cost.
func part(cap int64, n int, cost int64) int64 {
	if cap <= 0 || n <= 1 {
		return cap
	}
	return max(cap/int64(n), cost)
}
