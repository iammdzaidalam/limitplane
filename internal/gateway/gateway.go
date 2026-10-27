package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

// KeyHeader carries the tenant API key.
const KeyHeader = "X-Api-Key" // canonical form, so Header.Get skips an alloc

type Config struct {
	Policy  *policy.Store
	Limiter limiter.Limiter
	Quota   limiter.Quota // nil disables monthly caps
	Bans    Bans          // nil disables bans
	// OnDecision runs synchronously on the request path: it must not block (hand off to a channel or counter).
	OnDecision func(Decision)
	// OnQuota reports a named tenant's monthly usage after each spend; same rule as OnDecision.
	OnQuota    func(tenant string, used, limit int64)
	TrustProxy bool
	FailClosed bool // backend error -> 503 instead of allowing
}

type Gateway struct{ c Config }

func New(c Config) *Gateway { return &Gateway{c: c} }

type ctxKey struct{}

// DecisionFrom returns the decision the gateway made for this request.
func DecisionFrom(ctx context.Context) (Decision, bool) {
	d, ok := ctx.Value(ctxKey{}).(Decision)
	return d, ok
}

// Middleware meters each request: ban -> burst -> monthly.
// Burst runs before monthly so a request the burst limiter rejects never bills the plan;
// the reverse order would need a refund. A monthly reject does burn burst tokens, but those
// refill on their own and the tenant is blocked until the month rolls over anyway.
func (g *Gateway) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		ip := ClientIP(r, g.c.TrustProxy)
		d := Decision{Time: now, Client: ip, Method: r.Method, Path: r.URL.Path}

		if g.c.Bans != nil {
			if until, ok := g.c.Bans.Banned(ip); ok {
				d.Reason, d.RetryAfter = ReasonBanned, until.Sub(now)
				g.finish(w, r, next, d, d.RetryAfter)
				return
			}
		}

		m := g.c.Policy.Resolve(r.Header.Get(KeyHeader), d.Path)
		d.Tenant, d.Tier, d.Cost = m.Tenant, m.Tier, m.Cost
		key := m.Tenant
		if m.Anon {
			key = "anon:" + ip
		}

		res, err := g.c.Limiter.Allow(r.Context(), key, m.Rate, m.Cost)
		if err != nil {
			if g.c.FailClosed {
				d.Reason = ReasonError
				g.finish(w, r, next, d, 0)
				return
			}
			res = limiter.Result{Allowed: true, Limit: m.Rate.Burst, Remaining: m.Rate.Burst, Degraded: true}
		}
		d.Limit, d.Remaining, d.RetryAfter, d.Degraded = res.Limit, res.Remaining, res.RetryAfter, res.Degraded
		reset := res.ResetAfter
		if !res.Allowed {
			d.Reason = ReasonBurst
			g.finish(w, r, next, d, reset)
			return
		}

		if m.Month > 0 && g.c.Quota != nil {
			used, ok, err := g.c.Quota.Spend(r.Context(), limiter.MonthKey(key, now), m.Month, m.Cost)
			switch {
			case err != nil && g.c.FailClosed:
				d.Reason = ReasonError
				g.finish(w, r, next, d, 0)
				return
			case err != nil:
				d.Degraded = true
			case g.c.OnQuota != nil && !m.Anon:
				g.c.OnQuota(m.Tenant, used, m.Month)
			}
			if err == nil && !ok {
				d.Reason, d.Limit, d.Remaining = ReasonMonthly, m.Month, max(0, m.Month-used)
				d.RetryAfter = nextMonth(now).Sub(now)
				g.finish(w, r, next, d, d.RetryAfter)
				return
			}
		}

		d.Allowed, d.Reason = true, ReasonOK
		g.finish(w, r, next, d, reset)
	})
}

func (g *Gateway) finish(w http.ResponseWriter, r *http.Request, next http.Handler, d Decision, reset time.Duration) {
	h := w.Header()
	if d.Reason != ReasonError {
		// Canonical keys and one shared backing array: Header.Set would allocate per call.
		v := [3]string{strconv.FormatInt(d.Limit, 10), strconv.FormatInt(d.Remaining, 10), strconv.FormatInt(ceilSec(reset), 10)}
		vs := v[:]
		h["Ratelimit-Limit"], h["X-Ratelimit-Limit"] = vs[0:1:1], vs[0:1:1]
		h["Ratelimit-Remaining"], h["X-Ratelimit-Remaining"] = vs[1:2:2], vs[1:2:2]
		h["Ratelimit-Reset"], h["X-Ratelimit-Reset"] = vs[2:3:3], vs[2:3:3]
	}
	if g.c.OnDecision != nil {
		g.c.OnDecision(d)
	}
	if d.Allowed {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, d)))
		return
	}

	code, retry := http.StatusTooManyRequests, max(1, ceilSec(d.RetryAfter))
	if d.Reason == ReasonError {
		code = http.StatusServiceUnavailable
	} else {
		h.Set("Retry-After", strconv.FormatInt(retry, 10))
	}
	body, _ := json.Marshal(struct {
		Error      string `json:"error"`
		Reason     string `json:"reason"`
		RetryAfter int64  `json:"retryAfter,omitempty"`
		Message    string `json:"message"`
	}{errName(d.Reason), d.Reason, retry, message(d, retry)})
	h.Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(body)
}

func errName(reason string) string {
	if reason == ReasonError {
		return "unavailable"
	}
	return "rate_limited"
}

func message(d Decision, retry int64) string {
	switch d.Reason {
	case ReasonBurst:
		return fmt.Sprintf("Too many requests for the %s tier (this route costs %d units). Retry in %ds.", d.Tier, d.Cost, retry)
	case ReasonMonthly:
		return fmt.Sprintf("The %s plan's monthly quota of %d units is used up. It resets on the 1st (UTC).", d.Tier, d.Limit)
	case ReasonBanned:
		return fmt.Sprintf("This client is temporarily blocked for abusive traffic. Retry in %ds.", retry)
	}
	return "Rate limiting is unavailable, so the request was rejected. Try again shortly."
}

func ceilSec(d time.Duration) int64 { return int64((d + time.Second - 1) / time.Second) }

func nextMonth(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, time.UTC)
}

// ClientIP is RemoteAddr's host unless trustProxy is set; then it is the right-most
// X-Forwarded-For hop that is not one of our proxies. Left-most is whatever the client
// wrote, so trusting it would let anyone pick their own rate-limit key.
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		xs := r.Header.Values("X-Forwarded-For")
		last := ""
		for i := len(xs) - 1; i >= 0; i-- {
			for h := xs[i]; h != ""; {
				j := strings.LastIndexByte(h, ',')
				hop := strings.TrimSpace(h[j+1:])
				h = h[:max(j, 0)]
				a, err := netip.ParseAddr(hop)
				if err != nil {
					// Our proxies never write garbage: everything from here left is client-supplied.
					return fallback(last, r)
				}
				if !isProxy(a) {
					return hop
				}
				last = hop
			}
		}
		return fallback(last, r)
	}
	return fallback("", r)
}

// shortcut: treats any private/loopback hop as our proxy; add a configurable CIDR list for public-IP proxies (e.g. a CDN).
func isProxy(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
}

func fallback(ip string, r *http.Request) string {
	if ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
