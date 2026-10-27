package limiter

import (
	"context"
	"strings"
	"sync"
	"time"
)

// LocalQuota is an in-process monthly counter. Keys come from MonthKey.
type LocalQuota struct {
	mu    sync.Mutex
	used  map[string]int64
	month int
	now   func() time.Time
}

func NewLocalQuota() *LocalQuota {
	return &LocalQuota{used: map[string]int64{}, now: time.Now}
}

// Spend adds cost unless it would pass limit (limit <= 0 means no cap).
func (q *LocalQuota) Spend(_ context.Context, key string, limit, cost int64) (int64, bool, error) {
	now := q.now().UTC()
	q.mu.Lock()
	defer q.mu.Unlock()
	if y, m, _ := now.Date(); y*12+int(m) != q.month {
		q.month = y*12 + int(m)
		suffix := MonthKey("", now)
		for k := range q.used {
			if !strings.HasSuffix(k, suffix) {
				delete(q.used, k)
			}
		}
	}
	used := q.used[key]
	if limit > 0 && used+cost > limit {
		return used, false, nil
	}
	used += cost
	q.used[key] = used
	return used, true, nil
}
