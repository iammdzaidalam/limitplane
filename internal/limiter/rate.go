package limiter

import (
	"encoding/json"
	"errors"
	"math"
	"math/bits"
	"time"
)

var ErrInvalid = errors.New("limiter: rate needs limit > 0, period >= limit ns, cost > 0")

type rateJSON struct {
	Limit  int64  `json:"limit"`
	Period string `json:"period"`
	Burst  int64  `json:"burst"`
}

func (r Rate) MarshalJSON() ([]byte, error) {
	return json.Marshal(rateJSON{r.Limit, r.Period.String(), r.Burst})
}

func (r *Rate) UnmarshalJSON(b []byte) error {
	var j rateJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	p, err := time.ParseDuration(j.Period)
	if err != nil {
		return err
	}
	*r = Rate{Limit: j.Limit, Period: p, Burst: j.Burst}
	return nil
}

// burst is the bucket size; 0 means Limit.
func (r Rate) burst() int64 {
	if r.Burst > 0 {
		return r.Burst
	}
	return r.Limit
}

func check(r Rate, cost int64) error {
	if r.Limit <= 0 || r.Period <= 0 || r.Interval() <= 0 || cost <= 0 {
		return ErrInvalid
	}
	return nil
}

// gcra decides one request. now and tat are unix nanos; it returns the tat to store.
// Mirrored in Lua (redis.go) in micros: change both together.
// Products saturate: a slow rate with a big burst (1/day, burst 1e6) spans more than int64 nanos.
func gcra(now, tat int64, r Rate, cost int64) (Result, int64) {
	t := int64(r.Interval())
	b := r.burst()
	dvt := mulSat(b, t) // how far tat may run ahead of now
	if tat < now {
		tat = now
	}
	next := tat + min(mulSat(cost, t), math.MaxInt64-tat)
	res := Result{Limit: b}
	if next-now > dvt {
		res.RetryAfter = time.Duration(next - dvt - now)
		res.ResetAfter = time.Duration(tat - now)
		res.Remaining = max(b-ceilDiv(tat-now, t), 0) // tat can be past dvt: clock stepped back, tier lowered
		return res, tat
	}
	res.Allowed = true
	res.ResetAfter = time.Duration(next - now)
	res.Remaining = b - ceilDiv(next-now, t)
	return res, next
}

// mulSat is a*b for a, b > 0, capped at MaxInt64.
func mulSat(a, b int64) int64 {
	if hi, lo := bits.Mul64(uint64(a), uint64(b)); hi != 0 || lo > math.MaxInt64 {
		return math.MaxInt64
	}
	return a * b
}

// ceilDiv is ceil(a/b) for a >= 0, b > 0, without overflowing a+b-1.
func ceilDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 {
		q++
	}
	return q
}
