package server

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/gateway"
	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/org"
)

const (
	tokenTTL = 12 * time.Hour
	adminSub = "admin" // the admin key's subject; user ids start with u_
)

var (
	loginRate = limiter.Rate{Limit: 5, Period: time.Minute, Burst: 5} // per client IP
	// Per account, across replicas: slows a guesser spread over many IPs. It can also lock the real
	// user out for a few minutes, so it is looser than the IP limit; the admin key isn't subject to it.
	accountRate = limiter.Rate{Limit: 10, Period: 10 * time.Minute, Burst: 10}
)

// principal is who a request acts as.
type principal struct {
	ID    string // user id, or adminSub
	Email string
	Org   string // "" for the superadmin
	Role  org.Role
	ver   int64 // the session version the token was issued at
}

func (p principal) super() bool { return p.Role == org.Superadmin }

type principalKey struct{}

func caller(r *http.Request) (principal, bool) {
	p, ok := r.Context().Value(principalKey{}).(principal)
	return p, ok
}

// auth requires a valid bearer token whose user still exists with the same org, role and session
// version; query tokens only where headers can't be set (EventSource).
func (s *Server) auth(h http.Handler, allowQuery bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok && allowQuery {
			tok = r.URL.Query().Get("token")
		}
		c, err := verifyJWT(s.secret, tok, time.Now())
		p, live := s.principal(c)
		if err != nil || !live {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}

// principal maps verified claims to the caller, or false when the session was revoked: the user
// is gone, or their version, org or role moved on. Admin key tokens end when the key changes.
func (s *Server) principal(c claims) (principal, bool) {
	if c.Sub == adminSub {
		return principal{ID: adminSub, Role: org.Superadmin}, true
	}
	u, ok := s.cfg.Dir.Snapshot().Users[c.Sub]
	if !ok || u.Tokens != c.Ver || u.Org != c.Org || string(u.Role) != c.Role {
		return principal{}, false
	}
	return principal{ID: u.ID, Email: u.Email, Org: u.Org, Role: u.Role, ver: u.Tokens}, true
}

// live reports whether p's session still holds, for long-lived requests (SSE).
func (s *Server) live(p principal) bool {
	_, ok := s.principal(claims{Sub: p.ID, Org: p.Org, Role: string(p.Role), Ver: p.ver})
	return ok
}

// superOnly is for platform-wide actions: policy, bans, orgs themselves.
func (s *Server) superOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p, _ := caller(r); !p.super() {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden", "message": "only a platform admin can do this"})
			return
		}
		h(w, r)
	}
}

// need checks the caller holds role in orgID. Someone from another org gets 404, the same as for
// something that doesn't exist, so ids don't leak across orgs; a member whose role is too low, 403.
func need(w http.ResponseWriter, r *http.Request, orgID string, role org.Role) bool {
	p, _ := caller(r)
	switch {
	case p.super():
		return true
	case orgID == "" || p.Org != orgID:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return false
	case !p.Role.AtLeast(role):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden", "message": "this needs the " + string(role) + " role"})
		return false
	}
	return true
}

// throttle spends one login attempt for key; false (and a 429) when there are none left.
func (s *Server) throttle(w http.ResponseWriter, r *http.Request, key string, rate limiter.Rate) bool {
	res, err := s.cfg.Limits.Allow(r.Context(), key, rate, 1)
	if err == nil && !res.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(res.RetryAfter.Seconds()))))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
		return false
	}
	return true
}

type meView struct {
	User    string   `json:"user"`
	Email   string   `json:"email,omitempty"`
	Org     string   `json:"org,omitempty"`
	OrgName string   `json:"orgName,omitempty"`
	Role    org.Role `json:"role"`
}

type sessionView struct {
	Token string `json:"token"`
	meView
}

func (s *Server) me(p principal) meView {
	return meView{User: p.ID, Email: p.Email, Org: p.Org, OrgName: s.cfg.Dir.Snapshot().Orgs[p.Org].Name, Role: p.Role}
}

func (s *Server) session(p principal) sessionView {
	c := claims{Sub: p.ID, Org: p.Org, Role: string(p.Role), Ver: p.ver}
	return sessionView{signJWT(s.secret, c, time.Now(), tokenTTL), s.me(p)}
}

func userPrincipal(u org.User) principal {
	return principal{ID: u.ID, Email: u.Email, Org: u.Org, Role: u.Role, ver: u.Tokens}
}

// login takes the admin key ({"key"}) or an email and password. Both are limited per client IP,
// and passwords per account too, through the same limiter as traffic, so the limits hold across replicas.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.throttle(w, r, "login:"+gateway.ClientIP(r, s.cfg.TrustProxy), loginRate) {
		return
	}
	var body struct{ Key, Email, Password string }
	if !readJSON(w, r, &body) {
		return
	}
	if body.Email == "" {
		if s.cfg.AdminKey == "" || !equal(body.Key, s.cfg.AdminKey) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid key"})
			return
		}
		writeJSON(w, 200, s.session(principal{ID: adminSub, Role: org.Superadmin}))
		return
	}
	if !s.throttle(w, r, "login-account:"+org.NormEmail(body.Email), accountRate) {
		return
	}
	u, ok := s.cfg.Dir.Authenticate(body.Email, body.Password)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid email or password"})
		return
	}
	writeJSON(w, 200, s.session(userPrincipal(u)))
}

// signup creates an org and makes the caller its owner, when --signup allows it.
func (s *Server) signup(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Signup {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "signup is off", "message": "Sign-up is invite-only here: ask an org owner for an account."})
		return
	}
	if !s.throttle(w, r, "login:"+gateway.ClientIP(r, s.cfg.TrustProxy), loginRate) {
		return
	}
	var body struct{ Org, Email, Password string }
	if !readJSON(w, r, &body) {
		return
	}
	_, u, err := s.cfg.Dir.Signup(r.Context(), strings.TrimSpace(body.Org), body.Email, body.Password)
	if err != nil {
		dirError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, s.session(userPrincipal(u)))
}

func (s *Server) getMe(w http.ResponseWriter, r *http.Request) {
	p, _ := caller(r)
	writeJSON(w, 200, s.me(p))
}

// setPassword changes the caller's password and ends their other sessions; the reply carries a new token.
func (s *Server) setPassword(w http.ResponseWriter, r *http.Request) {
	p, _ := caller(r)
	var body struct{ Current, Password string }
	if !userOnly(w, p) || !readJSON(w, r, &body) {
		return
	}
	u, err := s.cfg.Dir.SetPassword(r.Context(), p.ID, body.Current, body.Password)
	if err != nil {
		dirError(w, err)
		return
	}
	writeJSON(w, 200, s.session(userPrincipal(u)))
}

// revokeMe ends every session of the caller, this one included.
func (s *Server) revokeMe(w http.ResponseWriter, r *http.Request) {
	p, _ := caller(r)
	if !userOnly(w, p) {
		return
	}
	if _, err := s.cfg.Dir.Revoke(r.Context(), p.ID); err != nil {
		dirError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func userOnly(w http.ResponseWriter, p principal) bool {
	if p.ID == adminSub {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the admin key has no password or sessions to revoke; rotate the key instead"})
		return false
	}
	return true
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request", "message": "the body must be JSON"})
		return false
	}
	return true
}

// dirError maps directory errors to responses; anything unexpected is the store being down.
func dirError(w http.ResponseWriter, err error) {
	code := http.StatusServiceUnavailable
	switch {
	case errors.Is(err, org.ErrNotFound):
		code = http.StatusNotFound
	case errors.Is(err, org.ErrInvalid):
		code = http.StatusBadRequest
	case errors.Is(err, org.ErrExists), errors.Is(err, org.ErrConflict), errors.Is(err, org.ErrLastOwner):
		code = http.StatusConflict
	}
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
