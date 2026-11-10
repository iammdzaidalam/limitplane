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
// A key in an org lives in the org's shard, next to the org's spend.
type Local struct {
	shards []shard
	mask   uint32
	now    func() time.Time
}

type shard struct {
	mu    sync.Mutex
	tat   map[string]int64
	used  map[string]int64 // monthly spend of capped keys
	org   map[string]int64 // monthly spend of orgs
	month int              // year*12+month that used and org count
	swept int64
	_     [16]byte // keep hot shards off each other's cache line
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
		l.shards[i].org = map[string]int64{}
	}
	return l
}

func (l *Local) Allow(_ context.Context, key string, r Rate, cost int64) (Result, error) {
	return l.decide(Request{Key: key, Rate: r, Cost: cost})
}

// Used returns key's spend this month.
func (l *Local) Used(ctx context.Context, key string) (int64, error) { return l.UsedIn(ctx, key, "") }

// UsedIn returns the spend this month of key in org.
func (l *Local) UsedIn(_ context.Context, key, org string) (int64, error) {
	return l.spent(l.shard(key, org), key, false), nil
}

// OrgUsed returns org's spend this month.
func (l *Local) OrgUsed(_ context.Context, org string) (int64, error) {
	return l.spent(l.shard("", org), org, true), nil
}

func (l *Local) spent(s *shard, k string, org bool) int64 {
	m := monthOf(l.now())
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.month != m:
		return 0
	case org:
		return s.org[k]
	}
	return s.used[k]
}

// Move takes key's spend out of its old shard and adds it in the new one. Its tat is dropped: at
// worst one extra burst.
func (l *Local) Move(_ context.Context, key, from, to string) error {
	if from == to {
		return nil
	}
	m := monthOf(l.now())
	s := l.shard(key, from)
	s.mu.Lock()
	n := s.used[key]
	if s.month != m {
		n = 0
	}
	delete(s.used, key)
	delete(s.tat, key)
	s.mu.Unlock()
	if n == 0 {
		return nil
	}
	s = l.shard(key, to)
	s.mu.Lock()
	if s.month != m {
		s.roll(m)
	}
	s.used[key] += n
	s.mu.Unlock()
	return nil
}

// shard picks by org when there is one, so a tenant and its org share a lock.
func (l *Local) shard(key, org string) *shard {
	if org != "" {
		key = org
	}
	h := uint32(2166136261) // FNV-1a
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return &l.shards[h&l.mask]
}

// roll starts a new month: every count starts again. Callers hold s.mu.
func (s *shard) roll(month int) {
	clear(s.used)
	clear(s.org)
	s.month = month
}

func monthOf(t time.Time) int {
	y, m, _ := t.UTC().Date()
	return y*12 + int(m)
}

// decide checks the monthly cap (q.Month > 0), the org's budget (q.OrgMonth > 0), then GCRA, and
// writes only if all pass. An org's spend is counted even without a budget, so one set mid-month
// covers the whole month.
func (l *Local) decide(q Request) (Result, error) {
	if err := check(q.Rate, q.Cost); err != nil {
		return Result{}, err
	}
	key, org, cost := q.Key, q.Org, q.Cost
	s := l.shard(key, org)
	t := l.now()
	now := t.UnixNano()
	month := 0
	if q.Month > 0 || org != "" {
		month = monthOf(t)
	}
	s.mu.Lock()
	if month != 0 && s.month != month {
		s.roll(month)
	}
	var used, orgUsed int64
	if q.Month > 0 {
		if used = s.used[key]; used+cost > q.Month {
			s.mu.Unlock()
			return Result{Reason: Monthly, Used: used}, nil
		}
	}
	if org != "" {
		if orgUsed = s.org[org]; q.OrgMonth > 0 && orgUsed+cost > q.OrgMonth {
			s.mu.Unlock()
			return Result{Reason: OrgMonthly, Used: used, OrgUsed: orgUsed}, nil
		}
	}
	res, tat := gcra(now, s.tat[key], q.Rate, cost)
	if res.Allowed {
		s.tat[key] = tat
		if q.Month > 0 {
			used += cost
			s.used[key] = used
		}
		if org != "" {
			orgUsed += cost
			s.org[org] = orgUsed
		}
	} else {
		res.Reason = Burst
	}
	res.Used, res.OrgUsed = used, orgUsed
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
	return m.decide(q)
}
