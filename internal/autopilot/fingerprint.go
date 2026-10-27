package autopilot

import (
	"hash/maphash"
	"math"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/gateway"
)

const (
	minSamples = 10  // below this a client is "warming"
	alpha      = 0.1 // EWMA weight: roughly the last 10-20 requests dominate
	pathRing   = 32  // recent paths kept for diversity
	bucketSec  = 10  // RPS sliding-window bucket
)

var seed = maphash.MakeSeed()

// track is one client's bounded state: O(pathRing + StormBlocks) memory regardless of traffic.
type track struct {
	client string
	n      int64
	last   time.Time

	gapMean, gapVar float64 // EWMA of inter-arrival seconds
	blockEWMA       float64

	paths [pathRing]uint64
	pi    int

	lastBlock time.Time // pending 429 whose follow-up we judge
	lastRetry time.Duration
	followups int64 // requests right after a 429
	respected int64 // of those, ones that waited at least half of Retry-After

	bucket    int64 // unix second / bucketSec
	cur, prev int64

	blocks []time.Time // storm ring of burst-block times
	bi, bn int
}

func (t *track) observe(d gateway.Decision) {
	now := d.Time
	blocked := 0.0
	if !d.Allowed {
		blocked = 1
	}
	if t.n == 0 {
		t.blockEWMA = blocked
	} else {
		gap := max(0, now.Sub(t.last).Seconds()) // concurrent requests can arrive slightly out of order
		if t.n == 1 {
			t.gapMean = gap
		} else {
			diff := gap - t.gapMean
			t.gapMean += alpha * diff
			t.gapVar = (1 - alpha) * (t.gapVar + alpha*diff*diff)
		}
		t.blockEWMA += alpha * (blocked - t.blockEWMA)
	}
	if !t.lastBlock.IsZero() {
		t.followups++
		if now.Sub(t.lastBlock) >= t.lastRetry/2 {
			t.respected++
		}
		t.lastBlock = time.Time{}
	}
	// Bans aren't a fresh 429 the client could have honoured; only burst/monthly count.
	if d.Reason == gateway.ReasonBurst || d.Reason == gateway.ReasonMonthly {
		t.lastBlock, t.lastRetry = now, d.RetryAfter
	}
	t.paths[t.pi%pathRing] = maphash.String(seed, d.Path)
	t.pi++
	t.n++
	t.last = now

	b := now.Unix() / bucketSec
	switch {
	case b == t.bucket:
	case b == t.bucket+1:
		t.bucket, t.prev, t.cur = b, t.cur, 0
	default:
		t.bucket, t.prev, t.cur = b, 0, 0
	}
	t.cur++
}

// storm records a burst block and reports whether the last n blocks all fell within win.
func (t *track) storm(now time.Time, n int, win time.Duration) bool {
	if len(t.blocks) != n {
		t.blocks, t.bi, t.bn = make([]time.Time, n), 0, 0
	}
	t.blocks[t.bi] = now
	t.bi = (t.bi + 1) % n
	t.bn = min(t.bn+1, n)
	if t.bn == n && now.Sub(t.blocks[t.bi]) <= win {
		t.bn = 0 // start fresh after the ban
		return true
	}
	return false
}

func (t *track) rps(now time.Time) float64 {
	b := now.Unix() / bucketSec
	cur, prev := t.cur, t.prev
	switch b {
	case t.bucket:
	case t.bucket + 1:
		cur, prev = 0, cur
	default:
		return 0
	}
	// Sliding-window counter: weight the previous bucket by how much of it still overlaps.
	frac := float64(now.Unix()%bucketSec) / bucketSec
	return (float64(prev)*(1-frac) + float64(cur)) / bucketSec
}

func (t *track) diversity() float64 {
	k := min(t.pi, pathRing)
	distinct := 0
outer:
	for i, h := range t.paths[:k] {
		for _, g := range t.paths[:i] {
			if g == h {
				continue outer
			}
		}
		distinct++
	}
	return float64(distinct) / float64(k)
}

// label is a heuristic, not a verdict:
//   - retry_bug: keeps firing right after 429s instead of honouring Retry-After
//   - crawler: mostly distinct paths at a steady-ish pace
//   - bot: metronomic timing (low inter-arrival variation) or mostly blocked
//   - human: bursty think-time timing on a few paths
func (t *track) label() string {
	if t.n < minSamples {
		return "warming"
	}
	if t.followups >= 3 && t.respected*5 < t.followups {
		return "retry_bug"
	}
	cv := 0.0
	if t.gapMean > 0 {
		cv = math.Sqrt(t.gapVar) / t.gapMean
	}
	switch {
	case t.diversity() >= 0.6 && cv < 1:
		return "crawler"
	case cv < 0.3 || t.blockEWMA > 0.5:
		return "bot"
	}
	return "human"
}

func (t *track) snapshot(now time.Time) Client {
	return Client{Client: t.client, Label: t.label(), RPS: t.rps(now), BlockRatio: t.blockEWMA, LastSeen: t.last}
}
