package limiter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/redisx"
)

// Redis shares limits and bans across gateway replicas, on one Redis or a Cluster. Needs Redis >= 5
// (effects replication for TIME + write).
//
// Key layout: everything a limit key owns carries its hash tag, so the per-request script touches
// one slot: lp:{acme}:r (burst tat) and lp:{acme}:q:2026-10 (monthly spend).
// Bans are one hash, lp:bans (client -> "<expiry ms> <reason>"), announced on channel lp:bans.
// Requests check bans in process against a synced copy, so the script never needs a ban key.
type Redis struct {
	c     *redisx.Client
	bans  *BanList // every ban, kept current by Watch (pub/sub) and Bans (sync)
	ready func()   // test hook: Watch (re)subscribed and resynced
}

// NewRedis uses cache as its ban list; pass the fallback's BanList so bans keep applying while
// Redis is down, and bans made meanwhile are pushed when it is back. nil makes a private one.
func NewRedis(c *redisx.Client, cache *BanList) *Redis {
	if cache == nil {
		cache = NewBanList()
	}
	cache.track()
	return &Redis{c: c, bans: cache}
}

const (
	bansKey     = "lp:bans"
	bansChannel = "lp:bans" // channels and keys are separate namespaces
	watchPing   = 10 * time.Second
)

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

// One round trip per request: monthly cap, GCRA, then both writes, atomically.
// KEYS: burst tat, quota key minus its month (appended here, from Redis's clock). Same hash tag.
// ARGV: interval (us), burst, cost, monthly cap (0 = none).
// Returns {reason, remaining, retry us, reset us, used}; reason codes match Reason.
// GCRA is gcra() in micros (Lua doubles are exact to 2^53); %d keeps the tat from being written as 1.7e+15.
var meterLua = redisx.NewScript(monthLua + `
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000000 + tonumber(t[2])
local interval, burst, cost, cap = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3]), tonumber(ARGV[4])
local qk, used = nil, 0
if cap > 0 then
  qk = KEYS[2] .. month(tonumber(t[1]))
  used = tonumber(redis.call('GET', qk) or 0)
  if used + cost > cap then return {3, 0, 0, 0, used} end
end
local dvt = burst * interval
local tat = tonumber(redis.call('GET', KEYS[1]) or 0)
if tat < now then tat = now end
local nxt = tat + cost * interval
local allow_at = nxt - dvt
if allow_at > now then
  return {2, math.floor((dvt - (tat - now)) / interval), allow_at - now, tat - now, used}
end
local ttl = nxt - now
redis.call('SET', KEYS[1], string.format('%d', nxt), 'PX', math.ceil(ttl / 1000))
if qk then
  used = redis.call('INCRBY', qk, cost)
  if used == cost then redis.call('PEXPIRE', qk, 3024000000) end -- 35 days: outlives its month
end
return {0, math.floor((dvt - ttl) / interval), 0, ttl, used}
`)

var usedLua = redisx.NewScript(monthLua + `
return tonumber(redis.call('GET', KEYS[1] .. month(tonumber(redis.call('TIME')[1]))) or 0)
`)

// nowMs is Redis's clock in milliseconds, so ban expiry doesn't depend on replica clocks.
const nowMs = `local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
`

// Ban and unban write the hash and announce it on the channel of the same name, in one step.
// ARGV: client, [ttl ms, reason].
var banLua = redisx.NewScript(nowMs + `
redis.call('HSET', KEYS[1], ARGV[1], string.format('%d', now + tonumber(ARGV[2])) .. ' ' .. ARGV[3])
redis.call('PUBLISH', KEYS[1], 'ban ' .. ARGV[1] .. ' ' .. ARGV[2] .. ' ' .. ARGV[3])
return 1
`)

var unbanLua = redisx.NewScript(`
redis.call('HDEL', KEYS[1], ARGV[1])
redis.call('PUBLISH', KEYS[1], 'unban ' .. ARGV[1])
return 1
`)

// Live bans as {client, ms left, reason, ...}; expired ones are deleted on the way.
var bansLua = redisx.NewScript(nowMs + `
local all, out = redis.call('HGETALL', KEYS[1]), {}
for i = 1, #all, 2 do
  local exp, reason = string.match(all[i + 1], '^(%d+) (.*)$')
  local left = (tonumber(exp) or 0) - now
  if left > 0 then
    out[#out + 1] = all[i]
    out[#out + 1] = left
    out[#out + 1] = reason
  else
    redis.call('HDEL', KEYS[1], all[i])
  end
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
	if until, ok := l.bans.Banned(q.Client, now); ok { // a banned flood never reaches Redis
		return Result{Reason: Banned, RetryAfter: until.Sub(now)}, nil
	}
	us, b, k := max(q.Rate.Interval().Microseconds(), 1), q.Rate.burst(), tag(q.Key)
	v, err := l.c.Eval(ctx, meterLua, []string{k + "r", k + "q:"}, us, b, q.Cost, max(q.Month, 0))
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

// Ban applies here at once; every other replica gets it from the PUBLISH.
func (l *Redis) Ban(ctx context.Context, b Ban) error {
	var err error
	if b.Client, err = canonical(b.Client); err != nil {
		return err
	}
	if err := l.push(ctx, b.Client, &b); err != nil {
		return err
	}
	l.bans.set(b)
	return nil
}

func (l *Redis) Unban(ctx context.Context, client string) error {
	client, err := canonical(client)
	if err != nil {
		return err
	}
	if err := l.push(ctx, client, nil); err != nil {
		return err
	}
	l.bans.drop(client)
	return nil
}

// push writes one ban (nil: an unban) with its remaining TTL. An expired ban is a no-op.
func (l *Redis) push(ctx context.Context, client string, b *Ban) error {
	if b == nil {
		_, err := l.c.Eval(ctx, unbanLua, []string{bansKey}, client)
		return err
	}
	ms := time.Until(b.Until).Milliseconds()
	if ms <= 0 {
		return nil
	}
	_, err := l.c.Eval(ctx, banLua, []string{bansKey}, client, ms, b.Reason)
	return err
}

// Bans first pushes bans and unbans made here while Redis was down (keeping their remaining TTL),
// then reads the list back into the local copy. On a timer it is the safety net under Watch:
// it repairs anything pub/sub missed.
func (l *Redis) Bans(ctx context.Context) ([]Ban, error) {
	pending, seq := l.bans.writes()
	for c, b := range pending {
		if err := l.push(ctx, c, b); err != nil {
			return nil, err
		}
		l.bans.settle(c, b)
	}
	v, err := l.c.Eval(ctx, bansLua, []string{bansKey})
	vals, ok := v.([]any)
	if err != nil || !ok || len(vals)%3 != 0 {
		return nil, replyErr(err, v)
	}
	now := time.Now()
	out := make([]Ban, 0, len(vals)/3)
	for i := 0; i < len(vals); i += 3 {
		c, _ := vals[i].(string)
		ms, _ := vals[i+1].(int64)
		reason, _ := vals[i+2].(string)
		out = append(out, Ban{Client: c, Until: now.Add(time.Duration(ms) * time.Millisecond), Reason: reason})
	}
	slices.SortFunc(out, func(a, b Ban) int { return a.Until.Compare(b.Until) })
	l.bans.replace(out, seq)
	return out, nil
}

// Watch applies other replicas' bans and unbans as they are published, until ctx ends. After
// every (re)subscribe it resyncs, so nothing published while it was disconnected is lost.
func (l *Redis) Watch(ctx context.Context) {
	for ctx.Err() == nil {
		if err := l.watch(ctx); err != nil && ctx.Err() == nil {
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
		}
	}
}

func (l *Redis) watch(ctx context.Context) error {
	sub, err := l.c.Subscribe(ctx, bansChannel)
	if err != nil {
		return err
	}
	defer sub.Close()
	defer context.AfterFunc(ctx, func() { sub.Close() })()
	sctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	l.Bans(sctx) // best effort: if the bans node is down, the periodic sync retries
	cancel()
	if l.ready != nil {
		l.ready()
	}
	idle := false
	for {
		m, err := sub.Receive(watchPing)
		if errors.Is(err, os.ErrDeadlineExceeded) && !idle { // quiet: check the conn is alive
			idle = true
			if err := sub.Ping(); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		idle = false
		if m.Kind == "message" {
			l.apply(m.Data)
		}
	}
}

// apply reads "ban <client> <ttl ms> <reason>" or "unban <client>".
func (l *Redis) apply(msg string) {
	op, rest, _ := strings.Cut(msg, " ")
	client, rest, _ := strings.Cut(rest, " ")
	switch op {
	case "ban":
		ttl, reason, _ := strings.Cut(rest, " ")
		if ms, err := strconv.ParseInt(ttl, 10, 64); err == nil {
			l.bans.set(Ban{Client: client, Until: time.Now().Add(time.Duration(ms) * time.Millisecond), Reason: reason})
		}
	case "unban":
		l.bans.drop(client)
	}
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
