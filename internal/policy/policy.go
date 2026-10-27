package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
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
		}
		// A burst below a route's cost means that route can never pass.
		if t.Rate.Burst < maxCost {
			bad("tier %q: burst %d < max route cost %d", name, t.Rate.Burst, maxCost)
		}
		if t.Monthly < 0 || (t.Monthly > 0 && t.Monthly < maxCost) {
			bad("tier %q: monthly must be 0 (no cap) or >= max route cost %d", name, maxCost)
		}
	}
	if c.Anonymous == "" {
		bad("anonymous tier must be set")
	} else if _, ok := c.Tiers[c.Anonymous]; !ok {
		bad("anonymous tier %q not defined", c.Anonymous)
	}
	for _, k := range slices.Sorted(maps.Keys(c.Keys)) {
		t := c.Keys[k]
		if k == "" || t.ID == "" {
			bad("keys: empty api key or tenant id")
		}
		if _, ok := c.Tiers[t.Tier]; !ok {
			bad("tenant %q: unknown tier %q", t.ID, t.Tier)
		}
	}
	return errors.Join(errs...)
}

func (c Config) clone() Config {
	c.Tiers = maps.Clone(c.Tiers)
	c.Routes = slices.Clone(c.Routes)
	c.Keys = maps.Clone(c.Keys)
	return c
}
