package limiter

import (
	"encoding/json"
	"errors"
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
func gcra(now, tat int64, r Rate, cost int64) (Result, int64) {
	t := int64(r.Interval())
	b := r.burst()
	dvt := b * t // how far tat may run ahead of now
	if tat < now {
		tat = now
	}
	next := tat + cost*t
	res := Result{Limit: b}
	if allowAt := next - dvt; allowAt > now {
		res.RetryAfter = time.Duration(allowAt - now)
		res.ResetAfter = time.Duration(tat - now)
		res.Remaining = (dvt - (tat - now)) / t
		return res, tat
	}
	res.Allowed = true
	res.ResetAfter = time.Duration(next - now)
	res.Remaining = (dvt - (next - now)) / t
	return res, next
}
