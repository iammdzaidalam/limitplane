// Package server is the admin plane: API, SSE, metrics, dashboard and demo routes.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
	"math"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/autopilot"
	"github.com/iammdzaidalam/limitplane/internal/gateway"
	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

// AdminPrefix is where the admin plane lives in proxy mode.
const AdminPrefix = "/_limitplane"

const tokenTTL = 12 * time.Hour

var loginRate = limiter.Rate{Limit: 5, Period: time.Minute, Burst: 5}

type Config struct {
	Policy     *policy.Store
	Limiter    limiter.Limiter
	Quota      limiter.Quota
	AdminKey   string
	Backend    string // "memory" or "redis"
	TrustProxy bool
	FailClosed bool
	Dashboard  fs.FS // nil disables GET /
}

type Server struct {
	Hub     *Hub
	Pilot   *autopilot.Pilot
	Gateway *gateway.Gateway
	cfg     Config
	secret  []byte
}

func New(c Config) *Server {
	s := &Server{cfg: c}
	// Derived from the admin key so replicas sharing a key accept each other's tokens.
	s.secret = mac([]byte(c.AdminKey), "limitplane-jwt")
	s.Hub = NewHub(func(d gateway.Decision) { s.Pilot.Observe(d) }, func() map[string]string {
		m := map[string]string{}
		for _, t := range c.Policy.Config().Keys {
			m[t.ID] = t.Tier
		}
		return m
	})
	s.Pilot = autopilot.New(autopilot.Config{
		StormBlocks: 20, StormWindow: 10 * time.Second, BanFor: 5 * time.Minute,
		OnBan:   func(b autopilot.Ban) { s.Hub.Publish("ban", b) },
		OnAlert: func(a autopilot.Alert) { s.Hub.Publish("alert", a) },
	})
	s.Gateway = gateway.New(gateway.Config{
		Policy: c.Policy, Limiter: c.Limiter, Quota: c.Quota, Bans: s.Pilot,
		OnDecision: s.Hub.OnDecision, OnQuota: s.Pilot.Usage, TrustProxy: c.TrustProxy, FailClosed: c.FailClosed,
	})
	return s
}

// Run drives the decision hub until ctx ends.
func (s *Server) Run(ctx context.Context) { s.Hub.Run(ctx) }

// Handler serves the admin plane plus traffic. upstream nil means demo mode:
// admin at /, demo API under /v1. Otherwise admin moves under AdminPrefix and
// every other request is metered and forwarded to upstream.
func (s *Server) Handler(upstream http.Handler) http.Handler {
	admin := s.admin()
	mux := http.NewServeMux()
	if upstream == nil {
		mux.Handle("/", admin)
		mux.Handle("/v1/", s.Gateway.Middleware(demo()))
		return mux
	}
	mux.Handle(AdminPrefix+"/", http.StripPrefix(AdminPrefix, admin))
	mux.Handle(AdminPrefix, http.RedirectHandler(AdminPrefix+"/", http.StatusMovedPermanently))
	mux.Handle("/", s.Gateway.Middleware(upstream))
	return mux
}

func (s *Server) admin() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") })
	m.HandleFunc("GET /metrics", s.metrics)
	m.HandleFunc("POST /api/login", s.login)
	api := func(pattern string, h http.HandlerFunc) { m.Handle(pattern, s.auth(h, false)) }
	api("GET /api/stats", s.stats)
	m.Handle("GET /api/events", s.auth(http.HandlerFunc(s.events), true))
	api("GET /api/audit", s.audit)
	api("GET /api/clients", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.Pilot.Clients()) })
	api("GET /api/bans", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.Pilot.Bans()) })
	api("POST /api/bans", s.ban)
	api("DELETE /api/bans/{client}", func(w http.ResponseWriter, r *http.Request) {
		s.Pilot.Unban(r.PathValue("client"))
		w.WriteHeader(http.StatusNoContent)
	})
	api("GET /api/policy", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.cfg.Policy.Config()) })
	api("PUT /api/policy", s.putPolicy)
	if s.cfg.Dashboard != nil {
		m.Handle("GET /", http.FileServerFS(s.cfg.Dashboard))
	}
	return secure(m, csp(s.cfg.Dashboard))
}

var inlineScript = regexp.MustCompile(`(?s)<script>(.*?)</script>`)

// csp allows the dashboard's own inline scripts by hash, so 'unsafe-inline' stays off for scripts.
func csp(dash fs.FS) string {
	scripts := "'self'"
	if dash != nil {
		b, _ := fs.ReadFile(dash, "index.html")
		for _, m := range inlineScript.FindAllSubmatch(b, -1) {
			sum := sha256.Sum256(m[1])
			scripts += " 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		}
	}
	return "default-src 'self'; script-src " + scripts + "; img-src 'self' data:; " +
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; " +
		"frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
}

func secure(h http.Handler, policy string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", policy)
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

// auth requires a valid bearer token; query tokens only where headers can't be set (EventSource).
func (s *Server) auth(h http.Handler, allowQuery bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok && allowQuery {
			tok = r.URL.Query().Get("token")
		}
		if _, err := verifyJWT(s.secret, tok, time.Now()); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := gateway.ClientIP(r, s.cfg.TrustProxy)
	res, err := s.cfg.Limiter.Allow(r.Context(), "login:"+ip, loginRate, 1)
	if err == nil && !res.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(res.RetryAfter.Seconds()))))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
		return
	}
	var body struct{ Key string }
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	// Hash first so the comparison is constant-time regardless of length.
	a, b := sha256.Sum256([]byte(body.Key)), sha256.Sum256([]byte(s.cfg.AdminKey))
	if s.cfg.AdminKey == "" || subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid key"})
		return
	}
	writeJSON(w, 200, map[string]string{"token": signJWT(s.secret, "admin", time.Now(), tokenTTL)})
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	st, per := s.Hub.snapshot(now)
	st.Backend = s.cfg.Backend
	cfg := s.cfg.Policy.Config()
	seen := map[string]bool{}
	add := func(id, tier string, label string, monthly bool) {
		c := per[label]
		t := tenantStats{Tenant: id, Tier: tier, Allowed: c.Allowed, Blocked: c.Blocked}
		if lim := cfg.Tiers[tier].Monthly; monthly && lim > 0 {
			t.MonthlyLimit = lim
			// Spending 0 reads the current usage from whichever backend is shared.
			if used, _, err := s.cfg.Quota.Spend(r.Context(), limiter.MonthKey(id, now), lim, 0); err == nil {
				t.MonthlyUsed = used
			}
		}
		st.Tenants = append(st.Tenants, t)
	}
	for _, t := range cfg.Keys {
		if !seen[t.ID] {
			seen[t.ID] = true
			add(t.ID, t.Tier, t.ID, true)
		}
	}
	slices.SortFunc(st.Tenants, func(a, b tenantStats) int { return strings.Compare(a.Tenant, b.Tenant) })
	// Anonymous quota is per client IP, so no single monthly figure.
	add(policy.AnonTenant, cfg.Anonymous, anonLabel, false)
	writeJSON(w, 200, st)
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		n = 100
	}
	writeJSON(w, 200, s.Hub.Audit(min(n, auditSize)))
}

func (s *Server) ban(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Client  string `json:"client"`
		Minutes int    `json:"minutes"`
		Reason  string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&b); err != nil || b.Client == "" || b.Minutes < 1 || b.Minutes > 7*24*60 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "need client and minutes in 1..10080"})
		return
	}
	if b.Reason == "" {
		b.Reason = "manual"
	}
	s.Pilot.Ban(b.Client, time.Duration(b.Minutes)*time.Minute, b.Reason)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) putPolicy(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	var c policy.Config
	if err == nil {
		c, err = policy.Parse(body)
	}
	if err == nil {
		err = s.cfg.Policy.Swap(c)
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, s.cfg.Policy.Config())
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	// Subscribe before flushing headers so a client that sees 200 can't miss the next event.
	ch := s.Hub.Subscribe()
	defer s.Hub.Unsubscribe(ch)
	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	if rc.Flush() != nil {
		return
	}
	beat := time.NewTicker(15 * time.Second)
	defer beat.Stop()
	for {
		var err error
		select {
		case <-r.Context().Done():
			return
		case <-s.Hub.Done():
			return
		case msg := <-ch:
			_, err = w.Write(msg)
		case <-beat.C:
			_, err = io.WriteString(w, ": ping\n\n")
		}
		if err != nil || rc.Flush() != nil {
			return
		}
	}
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	s.Hub.writeMetrics(w, len(s.Pilot.Bans()))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
