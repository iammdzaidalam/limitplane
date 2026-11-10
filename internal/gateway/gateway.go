package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

// KeyHeader carries the tenant API key.
const KeyHeader = "X-Api-Key" // canonical form, so Header.Get skips an alloc

type Config struct {
	Policy *policy.Store
	Meter  limiter.Meter
	// OnDecision runs synchronously on the request path: it must not block (hand off to a channel or counter).
	OnDecision func(Decision)
	// OnQuota reports a named tenant's monthly usage after each check; same rule as OnDecision.
	OnQuota func(tenant string, used, limit int64)
	// Lane returns a client's autopilot label for tiers with lanes; nil turns lanes off.
	// It runs on the request path: one lock-free read.
	Lane       func(client string) policy.Lane
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

// Middleware meters each request with Check and lets it through only when allowed.
func (g *Gateway) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, reset := g.Check(r, r.Method, r.URL.Path)
		writeHeaders(w.Header(), d, reset)
		if !d.Allowed {
			deny(w, d, status(d))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, d)))
	})
}

// Check decides one request for method and path, with one Meter.Check: ban -> monthly -> burst,
// and nothing is spent unless all three pass. So a burst reject never bills the plan and a monthly
// reject never uses up burst. Monthly is checked before burst because it is the stickier answer: a
// tenant out of quota is told to wait for the 1st, not to retry in two seconds.
// It reports the decision to OnDecision and returns it with the time until the burst refills.
func (g *Gateway) Check(r *http.Request, method, path string) (Decision, time.Duration) {
	now := time.Now()
	ip := ClientIP(r, g.c.TrustProxy)
	d := Decision{Time: now, Client: ip, Method: method, Path: clean(path)}

	m := g.c.Policy.Resolve(r.Header.Get(KeyHeader), d.Path)
	d.Tenant, d.Tier, d.Cost = m.Tenant, m.Tier, m.Cost
	key := m.Tenant
	if m.Anon {
		key = "anon:" + ip
	}
	// Lanes reshape the burst only, never below one request: sustained rate and quota stay the plan's.
	if m.Lanes != nil && g.c.Lane != nil {
		l := g.c.Lane(ip)
		m.Rate.Burst, d.Lane = max(m.Lanes[l], m.Cost), l.String()
	}

	res, err := g.c.Meter.Check(r.Context(), limiter.Request{Client: ip, Key: key, Rate: m.Rate, Cost: m.Cost, Month: m.Month})
	failed := err != nil
	if failed && !g.c.FailClosed {
		res = limiter.Result{Allowed: true, Limit: m.Rate.Burst, Remaining: m.Rate.Burst, Degraded: true}
	}
	if !failed && m.Month > 0 && !m.Anon && res.Reason != limiter.Banned && g.c.OnQuota != nil {
		g.c.OnQuota(m.Tenant, res.Used, m.Month)
	}
	d.Limit, d.Remaining, d.RetryAfter, d.Degraded = res.Limit, res.Remaining, res.RetryAfter, res.Degraded
	reset := res.ResetAfter
	switch {
	case failed && g.c.FailClosed:
		d.Reason = ReasonError
	case res.Reason == limiter.Banned:
		d.Reason, reset = ReasonBanned, d.RetryAfter
	case res.Reason == limiter.Monthly:
		d.Reason, d.Limit, d.Remaining = ReasonMonthly, m.Month, max(0, m.Month-res.Used)
		d.RetryAfter = nextMonth(now).Sub(now)
		reset = d.RetryAfter
	case res.Reason == limiter.Burst:
		d.Reason = ReasonBurst
	default:
		d.Allowed, d.Reason = true, ReasonOK
	}
	if g.c.OnDecision != nil {
		g.c.OnDecision(d)
	}
	return d, reset
}

// writeHeaders sets the RateLimit headers (none when there is no answer to give).
func writeHeaders(h http.Header, d Decision, reset time.Duration) {
	if d.Reason == ReasonError {
		return
	}
	// Canonical keys and one shared backing array: Header.Set would allocate per call.
	v := [3]string{strconv.FormatInt(d.Limit, 10), strconv.FormatInt(d.Remaining, 10), strconv.FormatInt(ceilSec(reset), 10)}
	vs := v[:]
	h["Ratelimit-Limit"], h["X-Ratelimit-Limit"] = vs[0:1:1], vs[0:1:1]
	h["Ratelimit-Remaining"], h["X-Ratelimit-Remaining"] = vs[1:2:2], vs[1:2:2]
	h["Ratelimit-Reset"], h["X-Ratelimit-Reset"] = vs[2:3:3], vs[2:3:3]
}

// status is the code for a denied decision: 503 when there was no answer, else 429.
func status(d Decision) int {
	if d.Reason == ReasonError {
		return http.StatusServiceUnavailable
	}
	return http.StatusTooManyRequests
}

// deny writes Retry-After (unless the backend failed) and the JSON body that says why.
func deny(w http.ResponseWriter, d Decision, code int) {
	h := w.Header()
	retry := max(1, ceilSec(d.RetryAfter))
	if d.Reason != ReasonError {
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

// clean resolves dot segments and repeated slashes, so /v1/ping/../generate is priced as
// /v1/generate, the way the app behind will most likely route it. Already-clean paths cost nothing.
func clean(p string) string {
	if !strings.Contains(p, "/.") && !strings.Contains(p, "//") {
		return p
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c
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
