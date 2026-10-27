package limiter

import (
	"context"
	"fmt"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/redisx"
)

// Redis shares limits across gateway replicas. Needs Redis >= 5 (effects replication for TIME + write).
type Redis struct{ c *redisx.Client }

func NewRedis(c *redisx.Client) *Redis { return &Redis{c: c} }

// Same math as gcra() but in micros (Lua doubles are exact to 2^53) and on Redis TIME,
// so every replica shares one clock. %d keeps the tat from being written as 1.7e+15.
var gcraLua = redisx.NewScript(`
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000000 + tonumber(t[2])
local interval, burst, cost = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
local dvt = burst * interval
local tat = tonumber(redis.call('GET', KEYS[1]) or 0)
if tat < now then tat = now end
local nxt = tat + cost * interval
local allow_at = nxt - dvt
if allow_at > now then
  return {0, math.floor((dvt - (tat - now)) / interval), allow_at - now, tat - now}
end
local ttl = nxt - now
redis.call('SET', KEYS[1], string.format('%d', nxt), 'PX', math.ceil(ttl / 1000))
return {1, math.floor((dvt - ttl) / interval), 0, ttl}
`)

var quotaLua = redisx.NewScript(`
local used = tonumber(redis.call('GET', KEYS[1]) or 0)
local limit, cost = tonumber(ARGV[1]), tonumber(ARGV[2])
if limit > 0 and used + cost > limit then return {used, 0} end
used = redis.call('INCRBY', KEYS[1], cost)
redis.call('PEXPIREAT', KEYS[1], ARGV[3])
return {used, 1}
`)

// Braces are a Cluster hash tag; each script touches one key, so any slot works.
func rateKey(k string) string  { return "lp:r:{" + k + "}" }
func quotaKey(k string) string { return "lp:q:{" + k + "}" }

func (l *Redis) Allow(ctx context.Context, key string, r Rate, cost int64) (Result, error) {
	if err := check(r, cost); err != nil {
		return Result{}, err
	}
	us := max(r.Interval().Microseconds(), 1)
	v, err := l.c.Eval(ctx, gcraLua, []string{rateKey(key)}, us, r.burst(), cost)
	if err != nil {
		return Result{}, err
	}
	n, err := ints(v, 4)
	if err != nil {
		return Result{}, err
	}
	return Result{
		Allowed:    n[0] == 1,
		Limit:      r.burst(),
		Remaining:  n[1],
		RetryAfter: time.Duration(n[2]) * time.Microsecond,
		ResetAfter: time.Duration(n[3]) * time.Microsecond,
	}, nil
}

func (l *Redis) Spend(ctx context.Context, key string, limit, cost int64) (int64, bool, error) {
	// a day past month end, so replica clock skew at the boundary can't drop a live key
	y, m, _ := time.Now().UTC().Date()
	exp := time.Date(y, m+1, 2, 0, 0, 0, 0, time.UTC).UnixMilli()
	v, err := l.c.Eval(ctx, quotaLua, []string{quotaKey(key)}, limit, cost, exp)
	if err != nil {
		return 0, false, err
	}
	n, err := ints(v, 2)
	if err != nil {
		return 0, false, err
	}
	return n[0], n[1] == 1, nil
}

func ints(v any, want int) ([]int64, error) {
	arr, ok := v.([]any)
	if !ok || len(arr) != want {
		return nil, fmt.Errorf("limiter: unexpected redis reply %v", v)
	}
	out := make([]int64, want)
	for i, a := range arr {
		if out[i], ok = a.(int64); !ok {
			return nil, fmt.Errorf("limiter: unexpected redis reply %v", v)
		}
	}
	return out, nil
}
