package limiter

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/redisx"
)

// Redis shares limits and bans across gateway replicas. Needs Redis >= 5 (effects replication for TIME + write).
//
// Key layout: everything a limit key owns carries its hash tag, so one script can touch it all and
// Cluster puts it in one slot: lp:{acme}:r (burst tat) and lp:{acme}:q:2026-10 (monthly spend).
// Bans are per client, not per key: lp:ban:<ip or cidr>, a string (the reason) with a PX expiry.
type Redis struct {
	c    *redisx.Client
	bans *BanList // last list read back: CIDRs are matched here (the script only does exact keys)
}

// NewRedis uses cache for the ban list it syncs; pass the fallback's BanList so bans keep
// applying while Redis is down. nil makes a private one.
func NewRedis(c *redisx.Client, cache *BanList) *Redis {
	if cache == nil {
		cache = NewBanList()
	}
	return &Redis{c: c, bans: cache}
}

const banPrefix = "lp:ban:"

// month turns unix seconds into "YYYY-MM" (UTC), Hinnant's civil-from-days. Redis's Lua has no os.date.
const monthLua = `
local function month(s)
  local z = math.floor(s / 86400) + 719468
  local era = math.floor(z / 146097)
  local doe = z - era * 146097
  local yoe = math.floor((doe - math.floor(doe / 1460) + math.floor(doe / 36524) - math.floor(doe / 146096)) / 365)
  local doy = doe - (365 * yoe + math.floor(yoe / 4) - math.floor(yoe / 100))
  local mp = math.floor((5 * doy + 2) / 153)
  local m = mp < 10 and mp + 3 or mp - 9
  local y = yoe + era * 400
  if m <= 2 then y = y + 1 end
  return string.format('%04d-%02d', y, m)
end
`

// One round trip per request: ban, monthly cap, GCRA, then both writes, atomically.
// KEYS: ban, burst tat, quota key minus its month (appended here, from Redis's clock).
// ARGV: interval (us), burst, cost, monthly cap (0 = none).
// Returns {reason, remaining, retry us, reset us, used}; reason codes match Reason.
// GCRA is gcra() in micros (Lua doubles are exact to 2^53); %d keeps the tat from being written as 1.7e+15.
var meterLua = redisx.NewScript(monthLua + `
local ban = redis.call('PTTL', KEYS[1])
if ban > 0 then return {1, 0, ban * 1000, 0, 0} end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000000 + tonumber(t[2])
local interval, burst, cost, cap = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3]), tonumber(ARGV[4])
local qk, used = nil, 0
if cap > 0 then
  qk = KEYS[3] .. month(tonumber(t[1]))
  used = tonumber(redis.call('GET', qk) or 0)
  if used + cost > cap then return {3, 0, 0, 0, used} end
end
local dvt = burst * interval
local tat = tonumber(redis.call('GET', KEYS[2]) or 0)
if tat < now then tat = now end
local nxt = tat + cost * interval
local allow_at = nxt - dvt
if allow_at > now then
  return {2, math.floor((dvt - (tat - now)) / interval), allow_at - now, tat - now, used}
end
local ttl = nxt - now
redis.call('SET', KEYS[2], string.format('%d', nxt), 'PX', math.ceil(ttl / 1000))
if qk then
  used = redis.call('INCRBY', qk, cost)
  if used == cost then redis.call('PEXPIRE', qk, 3024000000) end -- 35 days: outlives its month
end
return {0, math.floor((dvt - ttl) / interval), 0, ttl, used}
`)

var usedLua = redisx.NewScript(monthLua + `
return tonumber(redis.call('GET', KEYS[1] .. month(tonumber(redis.call('TIME')[1]))) or 0)
`)

var bansLua = redisx.NewScript(`
local out = {}
for _, k in ipairs(KEYS) do
  out[#out + 1] = redis.call('GET', k) or ''
  out[#out + 1] = redis.call('PTTL', k)
end
return out
`)

func tag(key string) string { return "lp:{" + key + "}:" }

func (l *Redis) Allow(ctx context.Context, key string, r Rate, cost int64) (Result, error) {
	return l.Check(ctx, Request{Key: key, Rate: r, Cost: cost}) // client "" is never banned
}

func (l *Redis) Check(ctx context.Context, q Request) (Result, error) {
	if err := check(q.Rate, q.Cost); err != nil {
		return Result{}, err
	}
	now := time.Now()
	if until, ok := l.bans.snap.Load().inNet(q.Client, now); ok {
		return Result{Reason: Banned, RetryAfter: until.Sub(now)}, nil
	}
	us, b, k := max(q.Rate.Interval().Microseconds(), 1), q.Rate.burst(), tag(q.Key)
	v, err := l.c.Eval(ctx, meterLua, []string{banPrefix + q.Client, k + "r", k + "q:"}, us, b, q.Cost, max(q.Month, 0))
	if err != nil {
		return Result{}, err
	}
	n, err := ints(v, 5)
	if err != nil {
		return Result{}, err
	}
	res := Result{
		Allowed:    n[0] == 0,
		Reason:     Reason(n[0]),
		Remaining:  n[1],
		RetryAfter: time.Duration(n[2]) * time.Microsecond,
		ResetAfter: time.Duration(n[3]) * time.Microsecond,
		Used:       n[4],
	}
	if res.Reason == OK || res.Reason == Burst {
		res.Limit = b
	}
	return res, nil
}

func (l *Redis) Used(ctx context.Context, key string) (int64, error) {
	v, err := l.c.Eval(ctx, usedLua, []string{tag(key) + "q:"})
	if err != nil {
		return 0, err
	}
	n, ok := v.(int64)
	if !ok {
		return 0, fmt.Errorf("limiter: unexpected redis reply %v", v)
	}
	return n, nil
}

func (l *Redis) Ban(ctx context.Context, b Ban) error {
	b.Client = canonical(b.Client)
	ms := time.Until(b.Until).Milliseconds()
	if ms <= 0 {
		return nil
	}
	if _, err := l.c.Do(ctx, "SET", banPrefix+b.Client, b.Reason, "PX", ms); err != nil {
		return err
	}
	return l.bans.Ban(ctx, b) // CIDRs apply here at once; other replicas pick them up on their next sync
}

func (l *Redis) Unban(ctx context.Context, client string) error {
	client = canonical(client)
	if _, err := l.c.Do(ctx, "DEL", banPrefix+client); err != nil {
		return err
	}
	return l.bans.Unban(ctx, client)
}

// Bans SCANs the ban prefix (bans are few) and refreshes the local copy, so calling it on a
// timer is the sync that spreads CIDR bans and keeps a list for when Redis is down.
func (l *Redis) Bans(ctx context.Context) ([]Ban, error) {
	out := make([]Ban, 0)
	now := time.Now()
	for cursor := "0"; ; {
		v, err := l.c.Do(ctx, "SCAN", cursor, "MATCH", banPrefix+"*", "COUNT", 500)
		page, ok := v.([]any)
		if err != nil || !ok || len(page) != 2 {
			return nil, replyErr(err, v)
		}
		cursor, _ = page[0].(string)
		var keys []string
		for _, k := range page[1].([]any) {
			if s, ok := k.(string); ok {
				keys = append(keys, s)
			}
		}
		if len(keys) > 0 {
			v, err := l.c.Eval(ctx, bansLua, keys)
			vals, ok := v.([]any)
			if err != nil || !ok || len(vals) != 2*len(keys) {
				return nil, replyErr(err, v)
			}
			for i, k := range keys {
				reason, _ := vals[2*i].(string)
				if ttl, _ := vals[2*i+1].(int64); ttl > 0 { // gone or no expiry: skip
					out = append(out, Ban{Client: strings.TrimPrefix(k, banPrefix), Until: now.Add(time.Duration(ttl) * time.Millisecond), Reason: reason})
				}
			}
		}
		if cursor == "0" {
			break
		}
	}
	slices.SortFunc(out, func(a, b Ban) int { return a.Until.Compare(b.Until) })
	l.bans.replace(out)
	return out, nil
}

func (l *Redis) Close() error { return l.c.Close() }

func replyErr(err error, v any) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("limiter: unexpected redis reply %v", v)
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
