// Package policy maps an API key and a path to a tenant, a tier and a cost.
package policy

import "github.com/iammdzaidalam/limitplane/internal/limiter"

type Tier struct {
	Rate    limiter.Rate `json:"rate"`
	Monthly int64        `json:"monthly,omitempty"` // 0 means no monthly cap
	// Lanes scales the burst by the client's autopilot label, e.g. {"human": 2, "retry_bug": 0.25}.
	// Only the burst: GCRA still spends one interval per unit in every lane, so over any window a
	// tenant gets at most rate x time plus its largest lane burst, and the monthly cap is untouched.
	// Scaling the refill instead would let anyone who times requests like a human beat the paid
	// rate (the label is a heuristic), and a slower refill for one client would bill its tenant's
	// shared bucket extra per unit.
	Lanes map[string]float64 `json:"lanes,omitempty"`
}

// Lane is the autopilot's label for a client. A tier with lanes picks its burst by it.
type Lane uint8

const (
	LaneWarming Lane = iota // too few requests to judge yet
	LaneHuman
	LaneBot
	LaneCrawler
	LaneRetryBug
	numLanes
)

// Bounds on a lane's burst factor, so a typo can't turn a burst into a flood or a wall.
const (
	MinLaneFactor = 0.1
	MaxLaneFactor = 4
)

var laneNames = [numLanes]string{"warming", "human", "bot", "crawler", "retry_bug"}

func (l Lane) String() string {
	if l >= numLanes {
		return "unknown"
	}
	return laneNames[l]
}

// LaneOf parses a lane name.
func LaneOf(name string) (Lane, bool) {
	for i, n := range laneNames {
		if n == name {
			return Lane(i), true
		}
	}
	return 0, false
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
	Lanes  *[numLanes]int64 // the tier's burst per Lane; nil when it has no lanes
}
