// Package server is the admin plane: API, SSE, metrics, dashboard and demo routes.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/ai"
	"github.com/iammdzaidalam/limitplane/internal/autopilot"
	"github.com/iammdzaidalam/limitplane/internal/gateway"
	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/org"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

// AdminPrefix is where the admin plane lives in proxy mode.
const AdminPrefix = "/_limitplane"

type Config struct {
	Policy     *policy.Store
	Limits     limiter.Backend // burst, monthly, org budgets and bans: memory, or Redis behind a fallback
	Dir        *org.Directory  // orgs, users, their tenants and keys; nil: an empty one in memory
	Signup     bool            // anyone may create an org and become its owner (default: invite only)
	AdminKey   string
	MetricsKey string // empty: /metrics is public
	Backend    string // "memory" or "redis"
	TrustProxy bool
	FailClosed bool
	Dashboard  fs.FS       // nil disables GET /
	Kube       bool        // policy comes from CRDs (--kube)
	Leader     func() bool // nil: not running leader election
	// Hooks for autopilot bans and 80% quota alerts. Called on the request or hub goroutine: don't block.
	OnBan   func(autopilot.Ban)
	OnAlert func(autopilot.Alert)
	AI      ai.Config // model and options for explanations and ops chat; no Provider: rules only
}

type Server struct {
	Hub     *Hub
	Pilot   *autopilot.Pilot
	Gateway *gateway.Gateway
	ai      *aiPlane
	cfg     Config
	secret  []byte
}

func New(c Config) *Server {
	if c.Dir == nil {
		c.Dir = org.NewMemory()
	}
	s := &Server{cfg: c}
	// Derived from the admin key so replicas sharing a key accept each other's tokens.
	s.secret = mac([]byte(c.AdminKey), "limitplane-jwt")
	// A tenant's counters live under its org's hash tag, so when its org changes they follow. Every
	// replica moves them when it learns of the change; a repeat finds nothing left to move.
	c.Policy.OnMove(func(tenant, from, to string) {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := c.Limits.Move(ctx, tenant, from, to); err != nil {
				log.Printf("orgs: moving %s's counters from org %q to %q: %v", tenant, from, to, err)
			}
		}()
	})
	s.Hub = NewHub(func(d gateway.Decision) { s.Pilot.Observe(d); s.ai.observe(d) }, func() map[string]string {
		m := map[string]string{}
		for _, t := range c.Policy.Tenants() {
			m[t.ID] = t.Tier
		}
		return m
	})
	// Tenants made in the dashboard get their own stats label from their first request.
	c.Dir.Notify(func(st *org.State) {
		c.Policy.SetOrgs(st.Policy())
		s.Hub.Refresh()
	})
	s.Pilot = autopilot.New(autopilot.Config{
		Rules: autopilot.DefaultRules, Store: c.Limits,
		OnBan: func(b autopilot.Ban) {
			s.Hub.Publish("ban", b)
			s.Hub.Publish("incident", s.ai.ban(b))
			if c.OnBan != nil {
				c.OnBan(b)
			}
		},
		OnAlert: func(a autopilot.Alert) {
			s.Hub.Publish("alert", a)
			s.Hub.Publish("incident", s.ai.alert(a))
			if c.OnAlert != nil {
				c.OnAlert(a)
			}
		},
	})
	s.Gateway = gateway.New(gateway.Config{
		Policy: c.Policy, Meter: c.Limits, OnDecision: s.Hub.OnDecision,
		OnQuota: func(tenant string, used, limit int64) {
			s.Hub.Quota(tenant, used, limit)
			s.Pilot.Usage(tenant, used, limit)
		},
		Lane: s.Pilot.Lane, TrustProxy: c.TrustProxy, FailClosed: c.FailClosed,
	})
	s.ai = newAI(s, c.AI)
	return s
}

// Run drives the decision hub and the AI layer until ctx ends.
func (s *Server) Run(ctx context.Context) {
	go s.ai.run(ctx)
	s.Hub.Run(ctx)
}

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

// Authz serves the forward-auth endpoints for Envoy, nginx and Traefik, plus /healthz. It belongs on
// its own listener that only the proxies can reach (--authz-addr). It believes the path and, with
// TrustProxy, the client address the caller names, so a client calling it directly could price
// its requests as it likes, or drain another IP's budget until autopilot bans that IP. The public
// mux is open to clients; the admin mux wants a login no proxy can do.
func (s *Server) Authz() http.Handler {
	authz := s.Gateway.Authz()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			io.WriteString(w, "ok")
			return
		}
		authz.ServeHTTP(w, r)
	})
}

func (s *Server) admin() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") })
	m.HandleFunc("GET /metrics", s.metricsAuth)
	m.HandleFunc("POST /api/login", s.login)
	m.HandleFunc("GET /api/login", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]bool{"signup": s.cfg.Signup})
	})
	m.HandleFunc("POST /api/signup", s.signup)
	// Every route below needs a token. Reads are scoped to the caller's org (visible); writes
	// check the role in the org they touch (need), or are the platform admin's (sup).
	api := func(pattern string, h http.HandlerFunc) { m.Handle(pattern, s.auth(h, false)) }
	sup := func(pattern string, h http.HandlerFunc) { api(pattern, s.superOnly(h)) }
	api("GET /api/me", s.getMe)
	api("PUT /api/me/password", s.setPassword)
	api("POST /api/me/revoke", s.revokeMe)
	api("GET /api/stats", s.stats)
	m.Handle("GET /api/events", s.auth(http.HandlerFunc(s.events), true))
	api("GET /api/audit", s.audit)
	api("GET /api/clients", s.clients)
	api("GET /api/bans", s.bans)
	// Bans are per client and hold for every tenant, so only the platform admin makes them.
	sup("POST /api/bans", s.ban)
	// {client...}: a CIDR ban has a slash in it.
	sup("DELETE /api/bans/{client...}", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Pilot.Unban(r.Context(), r.PathValue("client")); err != nil {
			banError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	api("GET /api/policy", s.getPolicy)
	sup("PUT /api/policy", s.putPolicy)

	api("GET /api/orgs", s.listOrgs)
	sup("POST /api/orgs", s.createOrg)
	api("GET /api/orgs/{org}", s.getOrg)
	api("PATCH /api/orgs/{org}", s.updateOrg)
	sup("DELETE /api/orgs/{org}", s.deleteOrg)
	api("GET /api/orgs/{org}/members", s.listMembers)
	api("POST /api/orgs/{org}/members", s.addMember)
	api("PATCH /api/orgs/{org}/members/{user}", s.setRole)
	api("DELETE /api/orgs/{org}/members/{user}", s.removeMember)
	api("POST /api/orgs/{org}/members/{user}/revoke", s.revokeMember)
	sup("GET /api/users", s.listUsers)
	sup("POST /api/users", func(w http.ResponseWriter, r *http.Request) { s.addUser(w, r, "", org.Superadmin) })
	sup("DELETE /api/users/{user}", func(w http.ResponseWriter, r *http.Request) { s.removeUser(w, r, r.PathValue("user")) })

	api("GET /api/tenants", s.listTenants)
	api("POST /api/tenants", s.createTenant)
	api("DELETE /api/tenants/{tenant}", s.deleteTenant)
	sup("PUT /api/tenants/{tenant}/org", s.placeTenant)
	api("POST /api/tenants/{tenant}/keys", s.createKey)
	api("DELETE /api/tenants/{tenant}/keys/{key}", s.deleteKey)
	s.ai.routes(api)
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

// metricsAuth takes a static bearer key, since scrapers can't log in for a JWT.
func (s *Server) metricsAuth(w http.ResponseWriter, r *http.Request) {
	if k := s.cfg.MetricsKey; k != "" {
		tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !equal(tok, k) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
	}
	s.metrics(w, r)
}

// equal compares hashes so the time taken doesn't leak the key's length.
func equal(a, b string) bool {
	x, y := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(x[:], y[:]) == 1
}

// stats is the dashboard's numbers for the tenants in view: everything for the superadmin, or one
// org's totals, series, tenants and budget.
func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	o, all := scope(r)
	st, per := s.Hub.snapshot(now, o)
	st.Backend, st.Kube = s.cfg.Backend, s.cfg.Kube
	if s.cfg.Leader != nil {
		st.Leader = s.cfg.Leader()
	}
	keep := s.visible(r)
	st.Tenants = []tenantStats{}
	for _, t := range s.cfg.Policy.Tenants() {
		if !keep(t.ID) {
			continue
		}
		c := per[t.ID]
		ts := tenantStats{Tenant: t.ID, Tier: t.Tier, Org: t.Org, Allowed: c.Allowed, Blocked: c.Blocked}
		if t.Monthly > 0 {
			ts.MonthlyLimit = t.Monthly
			if used, err := s.cfg.Limits.UsedIn(r.Context(), t.ID, t.Org); err == nil {
				ts.MonthlyUsed = used
			}
		}
		st.Tenants = append(st.Tenants, ts)
	}
	if all { // anonymous quota is per client IP, so no single monthly figure; it belongs to no org
		c := per[anonLabel]
		st.Tenants = append(st.Tenants, tenantStats{Tenant: policy.AnonTenant, Tier: s.cfg.Policy.Config().Anonymous, Allowed: c.Allowed, Blocked: c.Blocked})
	}
	if g, ok := s.cfg.Dir.Snapshot().Orgs[o]; ok {
		st.Org = s.orgView(r, g)
	}
	writeJSON(w, 200, st)
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		n = 100
	}
	var keep func(gateway.Decision) bool
	if _, all := scope(r); !all {
		vis := s.visible(r)
		keep = func(d gateway.Decision) bool { return vis(d.Tenant) }
	}
	writeJSON(w, 200, s.Hub.AuditOf(min(n, auditSize), keep))
}

// clients are the fingerprints of clients that sent the tenants in view traffic lately.
func (s *Server) clients(w http.ResponseWriter, r *http.Request) {
	cs := s.Pilot.Clients()
	if _, all := scope(r); !all {
		seen := s.Hub.ClientsOf(s.visible(r))
		cs = slices.DeleteFunc(cs, func(c autopilot.Client) bool { return !seen[c.Client] })
	}
	writeJSON(w, 200, cs)
}

func (s *Server) bans(w http.ResponseWriter, r *http.Request) {
	bans, err := s.Pilot.Bans(r.Context())
	if err != nil {
		unavailable(w, err)
		return
	}
	if _, all := scope(r); !all {
		bans = affecting(bans, s.Hub.ClientsOf(s.visible(r)))
	}
	writeJSON(w, 200, bans)
}

// getPolicy is the whole policy for the platform admin. Org members get tiers and routes, which
// price their own traffic, but no API keys.
func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	c := s.cfg.Policy.Config()
	if p, _ := caller(r); !p.super() {
		c.Keys = map[string]policy.Tenant{}
	}
	writeJSON(w, 200, c)
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
	if err := s.Pilot.Ban(r.Context(), b.Client, time.Duration(b.Minutes)*time.Minute, b.Reason); err != nil {
		banError(w, err)
		return
	}
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
	ch := s.Hub.Subscribe(s.eventFilter(r))
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
			if p, _ := caller(r); !s.live(p) { // revoked: end the stream; the reconnect gets a 401
				return
			}
			_, err = io.WriteString(w, ": ping\n\n")
		}
		if err != nil || rc.Flush() != nil {
			return
		}
	}
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	bans, err := s.Pilot.Bans(r.Context())
	n := len(bans)
	if err != nil {
		n = -1 // unknown: leave the gauge out rather than report 0
	}
	s.Hub.writeMetrics(w, n, time.Now())
	s.ai.writeMetrics(w)
}

// banError is 400 for a ban the store refuses, else 503.
func banError(w http.ResponseWriter, err error) {
	if errors.Is(err, limiter.ErrBadBan) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	unavailable(w, err)
}

func unavailable(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
