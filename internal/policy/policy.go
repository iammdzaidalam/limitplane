package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/limiter"
)

// AnonTenant is the tenant name reported for requests without a known key.
const AnonTenant = "anonymous"

// Parse decodes and validates a JSON config. Unknown fields are rejected so typos fail loudly.
func Parse(b []byte) (Config, error) {
	var c Config
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("policy: %w", err)
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return Parse(b)
}

// Validate rejects configs that would make some request impossible to ever serve.
func (c Config) Validate() error {
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf("policy: "+f, a...)) }

	maxCost := int64(1)
	seen := map[string]bool{}
	for _, r := range c.Routes {
		if !strings.HasPrefix(r.Prefix, "/") {
			bad("route %q: prefix must start with /", r.Prefix)
		}
		if seen[r.Prefix] {
			bad("route %q: duplicate prefix", r.Prefix)
		}
		seen[r.Prefix] = true
		if r.Cost < 1 {
			bad("route %q: cost must be >= 1", r.Prefix)
		}
		maxCost = max(maxCost, r.Cost)
	}
	if len(c.Tiers) == 0 {
		bad("no tiers")
	}
	for _, name := range slices.Sorted(maps.Keys(c.Tiers)) {
		t := c.Tiers[name]
		switch {
		case t.Rate.Limit <= 0:
			bad("tier %q: limit must be > 0", name)
		case t.Rate.Period <= 0:
			bad("tier %q: period must be > 0", name)
		case t.Rate.Interval() <= 0:
			bad("tier %q: limit too high for period", name)
		case t.Rate.Burst < 0:
			bad("tier %q: burst must be >= 0", name)
		}
		// A burst below a route's cost means that route can never pass.
		b := burst(t.Rate)
		if b < maxCost {
			bad("tier %q: burst %d < max route cost %d", name, b, maxCost)
		}
		// GCRA keeps burst x interval in an int64 of nanoseconds, and a lane may raise the burst.
		f := 1.0
		for _, x := range t.Lanes {
			f = max(f, x)
		}
		if t.Rate.Limit > 0 && float64(b)*f*float64(t.Rate.Interval()) > float64(maxSpan) {
			bad("tier %q: burst x interval over 100 years", name)
		}
		if t.Monthly < 0 || (t.Monthly > 0 && t.Monthly < maxCost) {
			bad("tier %q: monthly must be 0 (no cap) or >= max route cost %d", name, maxCost)
		}
		for _, l := range slices.Sorted(maps.Keys(t.Lanes)) {
			if _, ok := LaneOf(l); !ok {
				bad("tier %q: unknown lane %q (want one of %s)", name, l, strings.Join(laneNames[:], ", "))
			} else if f := t.Lanes[l]; !(f >= MinLaneFactor && f <= MaxLaneFactor) {
				bad("tier %q: lane %q factor %g outside %g..%g", name, l, f, MinLaneFactor, MaxLaneFactor)
			}
		}
	}
	if c.Anonymous == "" {
		bad("anonymous tier must be set")
	} else if _, ok := c.Tiers[c.Anonymous]; !ok {
		bad("anonymous tier %q not defined", c.Anonymous)
	}
	orgOf := map[string]string{}
	for _, k := range slices.Sorted(maps.Keys(c.Keys)) {
		t := c.Keys[k]
		if k == "" || t.ID == "" {
			bad("keys: empty api key or tenant id")
		}
		if _, ok := c.Tiers[t.Tier]; !ok {
			bad("tenant %q: unknown tier %q", t.ID, t.Tier)
		}
		if o, seen := orgOf[t.ID]; seen && o != t.Org {
			bad("tenant %q: keys name different orgs (%q, %q)", t.ID, o, t.Org)
		}
		orgOf[t.ID] = t.Org
		if t.Org != "" && !ValidOrg(t.Org) {
			bad("tenant %q: org %q must be lowercase letters, digits and dashes (1-40)", t.ID, t.Org)
		}
		if t.Org != "" && strings.ContainsAny(t.ID, "{}") {
			bad("tenant %q: an id in an org can't contain { or }", t.ID) // they would break its Redis hash tag
		}
	}
	return errors.Join(errs...)
}

var orgID = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)

// ValidOrg reports whether id can name an org: it goes into Redis keys and URLs as it is.
func ValidOrg(id string) bool { return orgID.MatchString(id) }

// maxSpan bounds how far ahead a burst may book; int64 nanoseconds end at about 292 years.
const maxSpan = 100 * 365 * 24 * time.Hour

// burst is the effective bucket size: limiter.Rate treats 0 as Limit.
func burst(r limiter.Rate) int64 {
	if r.Burst > 0 {
		return r.Burst
	}
	return r.Limit
}

func (c Config) clone() Config {
	c.Tiers = maps.Clone(c.Tiers)
	for k, t := range c.Tiers {
		if t.Lanes != nil {
			t.Lanes = maps.Clone(t.Lanes)
			c.Tiers[k] = t
		}
	}
	c.Routes = slices.Clone(c.Routes)
	c.Keys = maps.Clone(c.Keys)
	return c
}
