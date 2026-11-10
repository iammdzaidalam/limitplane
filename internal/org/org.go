// Package org is the directory of organisations, their members and the tenants they own.
//
// The platform admin (the admin key, or a user with the superadmin role) sees everything. An org
// has members, each an owner, admin or viewer, and tenants, each in at most one org. A tenant is
// either created here (with a tier and API keys stored as hashes) or defined by the policy and
// only placed in an org here.
//
// Every replica serves reads from an immutable in-memory snapshot. Writes check their invariants
// against the snapshot and commit only if nobody else committed since (a version check), so two
// replicas can't both take the last owner away or claim one email twice. With Redis the records
// are hashes and a commit is announced on a channel; without it they are one JSON file.
package org

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"maps"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/policy"
)

type Role string

const (
	Viewer     Role = "viewer"
	Admin      Role = "admin"
	Owner      Role = "owner"
	Superadmin Role = "superadmin" // platform staff: no org, sees every org
)

// rank orders the org roles; 0 is not an org role.
func (r Role) rank() int {
	switch r {
	case Viewer:
		return 1
	case Admin:
		return 2
	case Owner:
		return 3
	}
	return 0
}

// AtLeast reports whether r includes everything need may do.
func (r Role) AtLeast(need Role) bool {
	return r == Superadmin || r.rank() >= need.rank() && need.rank() > 0
}

type Org struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Budget  int64     `json:"budget,omitempty"` // shared monthly units across its tenants; 0 = none
	Created time.Time `json:"created"`
}

type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Org      string `json:"org,omitempty"` // empty for a superadmin
	Role     Role   `json:"role"`
	Password string `json:"password"` // the PBKDF2 encoding (password.go); API views leave it out
	// Tokens is the user's session version: tokens carry it, and bumping it revokes every one issued before.
	Tokens  int64     `json:"tokens"`
	Created time.Time `json:"created"`
}

// Tenant is a tenant created here (Tier set) or a policy tenant placed in an org (Tier empty).
type Tenant struct {
	ID      string    `json:"id"`
	Org     string    `json:"org,omitempty"`
	Tier    string    `json:"tier,omitempty"`
	Created time.Time `json:"created"`
}

// Key is an API key for a tenant created here. Only its SHA-256 is kept; the key is shown once.
type Key struct {
	ID      string    `json:"id"`
	Tenant  string    `json:"tenant"`
	Hash    string    `json:"hash"`   // hex
	Prefix  string    `json:"prefix"` // the first characters, to tell keys apart
	Created time.Time `json:"created"`
}

// State is one immutable version of the directory.
type State struct {
	Version int64
	Orgs    map[string]Org
	Users   map[string]User
	Tenants map[string]Tenant
	Keys    map[string]Key

	email map[string]string // email -> user id
}

func newState() *State {
	return (&State{Orgs: map[string]Org{}, Users: map[string]User{}, Tenants: map[string]Tenant{}, Keys: map[string]Key{}}).index()
}

func (s *State) index() *State {
	s.email = make(map[string]string, len(s.Users))
	for id, u := range s.Users {
		s.email[u.Email] = id
	}
	return s
}

func (s *State) clone() *State {
	return &State{Version: s.Version, Orgs: maps.Clone(s.Orgs), Users: maps.Clone(s.Users), Tenants: maps.Clone(s.Tenants), Keys: maps.Clone(s.Keys)}
}

// UserByEmail finds a user by (normalised) email.
func (s *State) UserByEmail(email string) (User, bool) {
	u, ok := s.Users[s.email[NormEmail(email)]]
	return u, ok
}

// Members are the org's users.
func (s *State) Members(org string) []User {
	var out []User
	for _, u := range s.Users {
		if u.Org == org {
			out = append(out, u)
		}
	}
	return out
}

func (s *State) owners(org string) (n int) {
	for _, u := range s.Users {
		if u.Org == org && u.Role == Owner {
			n++
		}
	}
	return n
}

// KeysOf are the keys of one tenant.
func (s *State) KeysOf(tenant string) []Key {
	var out []Key
	for _, k := range s.Keys {
		if k.Tenant == tenant {
			out = append(out, k)
		}
	}
	return out
}

// Policy is what the directory adds to the policy: org budgets, tenants and key hashes.
func (s *State) Policy() policy.Orgs {
	o := policy.Orgs{
		Budgets: make(map[string]int64, len(s.Orgs)),
		Tenants: make(map[string]policy.OrgTenant, len(s.Tenants)),
		Keys:    make(map[[32]byte]string, len(s.Keys)),
	}
	for id, g := range s.Orgs {
		o.Budgets[id] = g.Budget
	}
	for id, t := range s.Tenants {
		o.Tenants[id] = policy.OrgTenant{Org: t.Org, Tier: t.Tier}
	}
	for _, k := range s.Keys {
		var h [32]byte
		if b, err := hex.DecodeString(k.Hash); err == nil && len(b) == len(h) {
			copy(h[:], b)
			o.Keys[h] = k.Tenant
		}
	}
	return o
}

var (
	ErrNotFound  = errors.New("not found")
	ErrExists    = errors.New("already exists")
	ErrInvalid   = errors.New("invalid")
	ErrLastOwner = errors.New("an org keeps at least one owner")
	ErrConflict  = errors.New("conflict")
)

var tenantID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidTenant is the id rule for tenants created here: safe in URLs, Redis keys and metric labels.
func ValidTenant(id string) bool { return tenantID.MatchString(id) }

// NormEmail is how emails are compared and stored.
func NormEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

func validEmail(e string) bool {
	a, err := mail.ParseAddress(e)
	return err == nil && a.Address == e && len(e) <= 254
}

// Slug turns an org name into an id: lowercase letters and digits, other runs folded to one dash.
func Slug(name string) string {
	var b strings.Builder
	dash := false
	for _, c := range strings.ToLower(name) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			b.WriteRune(c)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.TrimRight(b.String(), "-")
	if len(s) > 40 {
		s = strings.TrimRight(s[:40], "-")
	}
	return s
}

func newID(prefix string) string {
	b := make([]byte, 8)
	rand.Read(b)
	return prefix + hex.EncodeToString(b)
}
