package org

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/redisx"
)

// In Redis the directory is four hashes (record id -> JSON) and a version counter, all under one
// hash tag so every script runs on one Cluster slot. A commit is announced on a channel; replicas
// reload on the message, and check the version every syncEvery in case they missed one.
var dirKeys = []string{"lp:{dir}:v", "lp:{dir}:" + kOrgs, "lp:{dir}:" + kUsers, "lp:{dir}:" + kTenants, "lp:{dir}:" + kKeys}

const (
	dirChannel = "lp:dir"
	syncEvery  = 2 * time.Second
)

// {version, {id, json, ...} per kind}, in one consistent read.
var loadLua = redisx.NewScript(`
local out = {redis.call('GET', KEYS[1]) or '0'}
for i = 2, #KEYS do out[i] = redis.call('HGETALL', KEYS[i]) end
return out
`)

// ARGV: expected version, then (kind index into KEYS, id, json or "" to delete) per change.
// Returns the new version, or -1 when the stored one moved on.
var commitLua = redisx.NewScript(`
if (redis.call('GET', KEYS[1]) or '0') ~= ARGV[1] then return -1 end
for i = 2, #ARGV, 3 do
  local k = KEYS[tonumber(ARGV[i])]
  if ARGV[i + 2] == '' then redis.call('HDEL', k, ARGV[i + 1]) else redis.call('HSET', k, ARGV[i + 1], ARGV[i + 2]) end
end
local v = redis.call('INCR', KEYS[1])
redis.call('PUBLISH', '` + dirChannel + `', v)
return v
`)

type redisBackend struct{ c *redisx.Client }

// NewRedis keeps the directory in Redis, shared by every replica. Call Watch to follow other
// replicas' changes; until the first load succeeds the directory is empty.
func NewRedis(c *redisx.Client) *Directory { return newDirectory(&redisBackend{c}) }

func (r *redisBackend) load(ctx context.Context) (*State, error) {
	v, err := r.c.Eval(ctx, loadLua, dirKeys)
	a, ok := v.([]any)
	if err != nil || !ok || len(a) != len(dirKeys) {
		return nil, replyErr(err, v)
	}
	s := newState()
	vs, _ := a[0].(string)
	if s.Version, err = strconv.ParseInt(vs, 10, 64); err != nil {
		return nil, replyErr(nil, v)
	}
	for i, kind := range kinds {
		kv, ok := a[i+1].([]any)
		if !ok || len(kv)%2 != 0 {
			return nil, replyErr(nil, v)
		}
		for j := 0; j < len(kv); j += 2 {
			id, _ := kv[j].(string)
			raw, _ := kv[j+1].(string)
			if err := s.set(kind, id, []byte(raw)); err != nil {
				return nil, err
			}
		}
	}
	return s.index(), nil
}

func (r *redisBackend) commit(ctx context.Context, v int64, cs []change) (int64, error) {
	args := []any{v}
	for _, c := range cs {
		i := 0
		for j, k := range kinds {
			if k == c.kind {
				i = j + 2 // KEYS is 1-based and starts with the version
			}
		}
		args = append(args, i, c.id, c.raw)
	}
	res, err := r.c.Eval(ctx, commitLua, dirKeys, args...)
	n, ok := res.(int64)
	switch {
	case err != nil || !ok:
		return 0, replyErr(err, res)
	case n < 0:
		return 0, errStale
	}
	return n, nil
}

// Watch follows other replicas' commits until ctx ends: a reload on every message, a version
// check every syncEvery as the safety net, and a resync after every (re)subscribe. It returns at
// once for a directory that isn't in Redis.
func (d *Directory) Watch(ctx context.Context) {
	r, ok := d.be.(*redisBackend)
	if !ok {
		return
	}
	for ctx.Err() == nil {
		if err := r.listen(ctx, d); err != nil && ctx.Err() == nil {
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
		}
	}
}

func (r *redisBackend) listen(ctx context.Context, d *Directory) error {
	sub, err := r.c.Subscribe(ctx, dirChannel)
	if err != nil {
		return err
	}
	defer sub.Close()
	defer context.AfterFunc(ctx, func() { sub.Close() })()
	sync := func() {
		sctx, cancel := context.WithTimeout(ctx, syncEvery)
		defer cancel()
		if v, err := r.c.Do(sctx, "GET", dirKeys[0]); err == nil && version(v) != d.Snapshot().Version {
			d.Load(sctx)
		}
	}
	sync()
	pinged := false
	for {
		m, err := sub.Receive(syncEvery)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			if pinged { // no pong since the last quiet spell: the connection is gone
				return err
			}
			sync()
			if err := sub.Ping(); err != nil {
				return err
			}
			pinged = true
			continue
		}
		if err != nil {
			return err
		}
		pinged = false
		if n, err := strconv.ParseInt(m.Data, 10, 64); m.Kind == "message" && err == nil && n > d.Snapshot().Version {
			sync()
		}
	}
}

func version(v any) int64 {
	s, _ := v.(string)
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func replyErr(err error, v any) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("org: unexpected redis reply %v", v)
}
