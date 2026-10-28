package limiter

import (
	"context"
	"runtime"
	"sync"
	"time"
)

// sweepEvery bounds how long an idle key's entry outlives its tat.
const sweepEvery = int64(time.Minute)

// Local is an in-process GCRA limiter: one int64 (theoretical arrival time) per key, plus the
// key's monthly spend in the same shard, so one lock decides both (the in-memory hash tag).
type Local struct {
	shards []shard
	mask   uint32
	now    func() time.Time
}

type shard struct {
	mu    sync.Mutex
	tat   map[string]int64
	used  map[string]int64 // monthly spend of capped keys
	month int              // year*12+month that used counts
	swept int64
	_     [24]byte // keep hot shards off each other's cache line
}

func NewLocal() *Local {
	n := 1
	for n < 8*runtime.GOMAXPROCS(0) {
		n <<= 1
	}
	l := &Local{shards: make([]shard, n), mask: uint32(n - 1), now: time.Now}
	for i := range l.shards {
		l.shards[i].tat = map[string]int64{}
		l.shards[i].used = map[string]int64{}
	}
	return l
}

func (l *Local) Allow(_ context.Context, key string, r Rate, cost int64) (Result, error) {
	return l.decide(key, r, cost, 0)
}

// Used returns key's spend this month.
func (l *Local) Used(_ context.Context, key string) (int64, error) {
	s := l.shard(key)
	m := monthOf(l.now())
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.month != m {
		return 0, nil
	}
	return s.used[key], nil
}

func (l *Local) shard(key string) *shard {
	h := uint32(2166136261) // FNV-1a
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return &l.shards[h&l.mask]
}

func monthOf(t time.Time) int {
	y, m, _ := t.UTC().Date()
	return y*12 + int(m)
}

// decide checks the monthly cap (limit > 0), then GCRA, and writes only if both pass.
func (l *Local) decide(key string, r Rate, cost, limit int64) (Result, error) {
	if err := check(r, cost); err != nil {
		return Result{}, err
	}
	s := l.shard(key)
	t := l.now()
	now := t.UnixNano()
	month := 0
	if limit > 0 {
		month = monthOf(t)
	}
	s.mu.Lock()
	var used int64
	if limit > 0 {
		if s.month != month { // a new month: every count starts again
			clear(s.used)
			s.month = month
		}
		if used = s.used[key]; used+cost > limit {
			s.mu.Unlock()
			return Result{Reason: Monthly, Used: used}, nil
		}
	}
	res, tat := gcra(now, s.tat[key], r, cost)
	if res.Allowed {
		s.tat[key] = tat
		if limit > 0 {
			used += cost
			s.used[key] = used
		}
	} else {
		res.Reason = Burst
	}
	res.Used = used
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

// Memory is the single-process Backend.
type Memory struct {
	*Local
	*BanList
}

func NewMemory() *Memory { return &Memory{NewLocal(), NewBanList()} }

func (m *Memory) Check(_ context.Context, q Request) (Result, error) {
	now := m.now()
	if until, ok := m.Banned(q.Client, now); ok {
		return Result{Reason: Banned, RetryAfter: until.Sub(now)}, nil
	}
	return m.decide(q.Key, q.Rate, q.Cost, q.Month)
}
