// Package policy maps an API key and a path to a tenant, a tier and a cost.
package policy

import "github.com/iammdzaidalam/limitplane/internal/limiter"

type Tier struct {
	Rate    limiter.Rate `json:"rate"`
	Monthly int64        `json:"monthly,omitempty"` // 0 means no monthly cap
}

type Route struct {
	Prefix string `json:"prefix"`
	Cost   int64  `json:"cost"`
}

type Tenant struct {
	ID   string `json:"id"`
	Tier string `json:"tier"`
}

type Config struct {
	Tiers     map[string]Tier   `json:"tiers"`
	Routes    []Route           `json:"routes"`    // longest prefix wins, default cost 1
	Keys      map[string]Tenant `json:"keys"`      // api key -> tenant
	Anonymous string            `json:"anonymous"` // tier for unknown keys, limited per client IP
}

// Match is what the gateway needs to meter one request.
type Match struct {
	Tenant string
	Tier   string
	Rate   limiter.Rate
	Month  int64
	Cost   int64
	Anon   bool
}
