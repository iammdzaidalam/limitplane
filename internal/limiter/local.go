package limiter

import (
	"context"
	"runtime"
	"sync"
	"time"
)

// sweepEvery bounds how long an idle key's entry outlives its tat.
const sweepEvery = int64(time.Minute)

// Local is an in-process GCRA limiter: one int64 (theoretical arrival time) per key.
type Local struct {
	shards []shard
	mask   uint32
	now    func() time.Time
}

type shard struct {
	mu    sync.Mutex
	tat   map[string]int64
	swept int64
	_     [32]byte // keep hot shards off each other's cache line
}

func NewLocal() *Local {
	n := 1
	for n < 8*runtime.GOMAXPROCS(0) {
		n <<= 1
	}
	l := &Local{shards: make([]shard, n), mask: uint32(n - 1), now: time.Now}
	for i := range l.shards {
		l.shards[i].tat = map[string]int64{}
	}
	return l
}

func (l *Local) Allow(_ context.Context, key string, r Rate, cost int64) (Result, error) {
	if err := check(r, cost); err != nil {
		return Result{}, err
	}
	h := uint32(2166136261) // FNV-1a
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	s := &l.shards[h&l.mask]
	now := l.now().UnixNano()
	s.mu.Lock()
	res, tat := gcra(now, s.tat[key], r, cost)
	if res.Allowed {
		s.tat[key] = tat
	}
	if now-s.swept > sweepEvery {
		s.swept = now
		for k, t := range s.tat {
			if t <= now { // fully refilled: same as absent
				delete(s.tat, k)
			}
		}
	}
	s.mu.Unlock()
	return res, nil
}

func (l *Local) size() (n int) {
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.Lock()
		n += len(s.tat)
		s.mu.Unlock()
	}
	return n
}
