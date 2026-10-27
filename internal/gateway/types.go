// Package gateway is the HTTP middleware that meters every request.
package gateway

import "time"

// Reasons a decision can carry.
const (
	ReasonOK      = "ok"
	ReasonBurst   = "burst"
	ReasonMonthly = "monthly"
	ReasonBanned  = "banned"
	ReasonError   = "error" // backend failed and fail-closed is on
)

type Decision struct {
	Time       time.Time     `json:"time"`
	Tenant     string        `json:"tenant"`
	Tier       string        `json:"tier"`
	Client     string        `json:"client"`
	Method     string        `json:"method"`
	Path       string        `json:"path"`
	Cost       int64         `json:"cost"`
	Allowed    bool          `json:"allowed"`
	Reason     string        `json:"reason"`
	Limit      int64         `json:"limit"`
	Remaining  int64         `json:"remaining"`
	RetryAfter time.Duration `json:"retryAfter"`
	Degraded   bool          `json:"degraded,omitempty"` // shared backend down, local fallback used
}

// Bans is how the gateway asks whether a client is cooling down.
type Bans interface {
	Banned(client string) (until time.Time, ok bool)
}
