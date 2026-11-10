package org

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/policy"
)

// Record kinds: one Redis hash, or one object in the file, each.
const (
	kOrgs    = "orgs"
	kUsers   = "users"
	kTenants = "tenants"
	kKeys    = "keys"
)

var kinds = [...]string{kOrgs, kUsers, kTenants, kKeys}

// change sets one record (raw JSON) or, with raw nil, deletes it.
type change struct {
	kind, id string
	raw      []byte
}

func put(kind, id string, v any) change {
	b, _ := json.Marshal(v)
	return change{kind, id, b}
}

func del(kind, id string) change { return change{kind: kind, id: id} }

// errStale is a commit refused because another writer committed since the snapshot was read.
var errStale = errors.New("org: directory changed")

type backend interface {
	load(ctx context.Context) (*State, error)
	// commit applies cs only if the stored version is still v, and returns the new version.
	commit(ctx context.Context, v int64, cs []change) (int64, error)
}

type Directory struct {
	be    backend
	iter  int
	dummy func() string

	mu   sync.Mutex // orders this replica's loads and commits, so a slow load never undoes a commit
	cur  atomic.Pointer[State]
	subs []func(*State) // guarded by mu
}

func newDirectory(be backend) *Directory {
	d := &Directory{be: be}
	d.UseIterations(Iterations)
	d.cur.Store(newState())
	return d
}

// UseIterations sets the PBKDF2 work factor for new passwords (tests lower it).
func (d *Directory) UseIterations(n int) {
	d.iter = n
	d.dummy = sync.OnceValue(func() string { return hashPassword("not a password", n) })
}

// Snapshot is the current state. Treat it as read-only.
func (d *Directory) Snapshot() *State { return d.cur.Load() }

// Notify calls f with the current state now and with every new one after, in order.
func (d *Directory) Notify(f func(*State)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.subs = append(d.subs, f)
	f(d.cur.Load())
}

// Load reads the whole directory from the backend.
func (d *Directory) Load(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, err := d.be.load(ctx)
	if err != nil {
		return err
	}
	d.install(s)
	return nil
}

// install publishes s unless it is the version already served. Callers hold mu.
func (d *Directory) install(s *State) {
	if s.Version == d.cur.Load().Version {
		return
	}
	d.cur.Store(s)
	for _, f := range d.subs {
		f(s)
	}
}

// update commits the changes f derives from the current state, retrying on a stale snapshot.
func (d *Directory) update(ctx context.Context, f func(*State) ([]change, error)) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for range 5 {
		s := d.cur.Load()
		cs, err := f(s)
		if err != nil || len(cs) == 0 {
			return err
		}
		v, err := d.be.commit(ctx, s.Version, cs)
		if errors.Is(err, errStale) {
			n, err := d.be.load(ctx)
			if err != nil {
				return err
			}
			d.install(n)
			continue
		}
		if err != nil {
			return err
		}
		n, err := s.with(cs, v)
		if err != nil {
			return err
		}
		d.install(n)
		return nil
	}
	return fmt.Errorf("%w: the directory kept changing, try again", ErrConflict)
}

// with is s plus cs, at version v.
func (s *State) with(cs []change, v int64) (*State, error) {
	n := s.clone()
	for _, c := range cs {
		if err := n.set(c.kind, c.id, c.raw); err != nil {
			return nil, err
		}
	}
	n.Version = v
	return n.index(), nil
}

func (s *State) set(kind, id string, raw []byte) error {
	switch kind {
	case kOrgs:
		return setRecord(s.Orgs, id, raw)
	case kUsers:
		return setRecord(s.Users, id, raw)
	case kTenants:
		return setRecord(s.Tenants, id, raw)
	case kKeys:
		return setRecord(s.Keys, id, raw)
	}
	return fmt.Errorf("org: unknown record kind %q", kind)
}

func setRecord[T any](m map[string]T, id string, raw []byte) error {
	if raw == nil {
		delete(m, id)
		return nil
	}
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("org: record %s: %w", id, err)
	}
	m[id] = v
	return nil
}

func now() time.Time { return time.Now().UTC().Truncate(time.Second) }

func invalid(msg string) error { return fmt.Errorf("%w: %s", ErrInvalid, msg) }

// Authenticate checks an email and password, in about the same time whether or not the email has an account.
func (d *Directory) Authenticate(email, pw string) (User, bool) {
	u, ok := d.Snapshot().UserByEmail(email)
	if !ok {
		checkPassword(d.dummy(), pw)
		return User{}, false
	}
	return u, checkPassword(u.Password, pw)
}

// CreateOrg adds an org; its id is o.ID, or a slug of its name.
func (d *Directory) CreateOrg(ctx context.Context, o Org) (Org, error) {
	if o.ID == "" {
		o.ID = Slug(o.Name)
	}
	if err := checkOrg(o); err != nil {
		return Org{}, err
	}
	o.Created = now()
	return o, d.update(ctx, func(s *State) ([]change, error) {
		if _, ok := s.Orgs[o.ID]; ok {
			return nil, fmt.Errorf("%w: org %s", ErrExists, o.ID)
		}
		return []change{put(kOrgs, o.ID, o)}, nil
	})
}

func checkOrg(o Org) error {
	switch {
	case !policy.ValidOrg(o.ID):
		return invalid("an org id is 1-40 lowercase letters, digits and dashes")
	case o.Name == "" || len(o.Name) > 100:
		return invalid("an org needs a name of up to 100 characters")
	case o.Budget < 0:
		return invalid("a budget is 0 (none) or more units")
	}
	return nil
}

// UpdateOrg changes an org's name and budget; nil leaves one as it is.
func (d *Directory) UpdateOrg(ctx context.Context, id string, name *string, budget *int64) (Org, error) {
	var out Org
	err := d.update(ctx, func(s *State) ([]change, error) {
		o, ok := s.Orgs[id]
		if !ok {
			return nil, ErrNotFound
		}
		if name != nil {
			o.Name = *name
		}
		if budget != nil {
			o.Budget = *budget
		}
		if err := checkOrg(o); err != nil {
			return nil, err
		}
		out = o
		return []change{put(kOrgs, id, o)}, nil
	})
	return out, err
}

// DeleteOrg removes an org and its members. It refuses while the org has tenants.
func (d *Directory) DeleteOrg(ctx context.Context, id string) error {
	return d.update(ctx, func(s *State) ([]change, error) {
		if _, ok := s.Orgs[id]; !ok {
			return nil, ErrNotFound
		}
		for _, t := range s.Tenants {
			if t.Org == id {
				return nil, fmt.Errorf("%w: org %s still has tenants; delete or move them first", ErrConflict, id)
			}
		}
		cs := []change{del(kOrgs, id)}
		for _, u := range s.Members(id) {
			cs = append(cs, del(kUsers, u.ID))
		}
		return cs, nil
	})
}

// Signup creates an org and its first owner in one commit.
func (d *Directory) Signup(ctx context.Context, orgName, email, pw string) (Org, User, error) {
	o := Org{ID: Slug(orgName), Name: orgName, Created: now()}
	if err := checkOrg(o); err != nil {
		return Org{}, User{}, err
	}
	u, err := d.newUser(o.ID, email, Owner, pw)
	if err != nil {
		return Org{}, User{}, err
	}
	return o, u, d.update(ctx, func(s *State) ([]change, error) {
		if _, ok := s.Orgs[o.ID]; ok {
			return nil, fmt.Errorf("%w: org %s", ErrExists, o.ID)
		}
		if _, ok := s.UserByEmail(u.Email); ok {
			return nil, fmt.Errorf("%w: %s", ErrExists, u.Email)
		}
		return []change{put(kOrgs, o.ID, o), put(kUsers, u.ID, u)}, nil
	})
}

func (d *Directory) newUser(org, email string, role Role, pw string) (User, error) {
	email = NormEmail(email)
	switch {
	case !validEmail(email):
		return User{}, invalid("not an email address")
	case org == "" && role != Superadmin, org != "" && role.rank() == 0:
		return User{}, invalid("a role is owner, admin or viewer in an org, or superadmin without one")
	}
	if err := validPassword(pw); err != nil {
		return User{}, invalid(err.Error())
	}
	// Hashed before update's retry loop: it is the slow part.
	return User{ID: newID("u_"), Email: email, Org: org, Role: role, Password: hashPassword(pw, d.iter), Tokens: 1, Created: now()}, nil
}

// AddUser creates a member of org (org "" with role Superadmin: platform staff).
func (d *Directory) AddUser(ctx context.Context, org, email string, role Role, pw string) (User, error) {
	u, err := d.newUser(org, email, role, pw)
	if err != nil {
		return User{}, err
	}
	return u, d.update(ctx, func(s *State) ([]change, error) {
		if _, ok := s.Orgs[org]; org != "" && !ok {
			return nil, ErrNotFound
		}
		if _, ok := s.UserByEmail(u.Email); ok {
			return nil, fmt.Errorf("%w: %s", ErrExists, u.Email)
		}
		return []change{put(kUsers, u.ID, u)}, nil
	})
}

// edit changes one user, and revokes their sessions when revoke is set.
func (d *Directory) edit(ctx context.Context, id string, revoke bool, f func(s *State, u *User) error) (User, error) {
	var out User
	err := d.update(ctx, func(s *State) ([]change, error) {
		u, ok := s.Users[id]
		if !ok {
			return nil, ErrNotFound
		}
		if err := f(s, &u); err != nil {
			return nil, err
		}
		if revoke {
			u.Tokens++
		}
		out = u
		return []change{put(kUsers, id, u)}, nil
	})
	return out, err
}

// SetRole changes an org member's role and revokes their sessions, which carry the old one.
func (d *Directory) SetRole(ctx context.Context, id string, role Role) (User, error) {
	return d.edit(ctx, id, true, func(s *State, u *User) error {
		switch {
		case u.Org == "" || role.rank() == 0:
			return invalid("only org members change roles, to owner, admin or viewer")
		case u.Role == Owner && role != Owner && s.owners(u.Org) == 1:
			return ErrLastOwner
		}
		u.Role = role
		return nil
	})
}

// Revoke ends every session the user has: tokens carry the version they were issued at.
func (d *Directory) Revoke(ctx context.Context, id string) (User, error) {
	return d.edit(ctx, id, true, func(*State, *User) error { return nil })
}

// SetPassword changes a password after checking the current one, and ends the other sessions.
func (d *Directory) SetPassword(ctx context.Context, id, current, next string) (User, error) {
	if err := validPassword(next); err != nil {
		return User{}, invalid(err.Error())
	}
	u, ok := d.Snapshot().Users[id]
	if !ok || !checkPassword(u.Password, current) {
		return User{}, invalid("the current password is wrong")
	}
	h := hashPassword(next, d.iter)
	return d.edit(ctx, id, true, func(_ *State, u *User) error {
		u.Password = h
		return nil
	})
}

// RemoveUser deletes a user, unless they are their org's last owner.
func (d *Directory) RemoveUser(ctx context.Context, id string) error {
	return d.update(ctx, func(s *State) ([]change, error) {
		u, ok := s.Users[id]
		if !ok {
			return nil, ErrNotFound
		}
		if u.Role == Owner && s.owners(u.Org) == 1 {
			return nil, ErrLastOwner
		}
		return []change{del(kUsers, id)}, nil
	})
}

// CreateTenant adds a tenant with its own tier to an org ("" for none). The caller checks the tier
// exists and that the policy has no tenant of that id.
func (d *Directory) CreateTenant(ctx context.Context, t Tenant) (Tenant, error) {
	if !ValidTenant(t.ID) {
		return Tenant{}, invalid("a tenant id is 1-64 letters, digits, dots, dashes and underscores")
	}
	if t.Tier == "" {
		return Tenant{}, invalid("a tenant needs a tier")
	}
	t.Created = now()
	return t, d.update(ctx, func(s *State) ([]change, error) {
		if _, ok := s.Orgs[t.Org]; t.Org != "" && !ok {
			return nil, ErrNotFound
		}
		if _, ok := s.Tenants[t.ID]; ok {
			return nil, fmt.Errorf("%w: tenant %s", ErrExists, t.ID)
		}
		return []change{put(kTenants, t.ID, t)}, nil
	})
}

// DeleteTenant removes a tenant created here, with its keys.
func (d *Directory) DeleteTenant(ctx context.Context, id string) error {
	return d.update(ctx, func(s *State) ([]change, error) {
		if t, ok := s.Tenants[id]; !ok || t.Tier == "" {
			return nil, ErrNotFound
		}
		cs := []change{del(kTenants, id)}
		for _, k := range s.KeysOf(id) {
			cs = append(cs, del(kKeys, k.ID))
		}
		return cs, nil
	})
}

// PlaceTenant puts a tenant in an org, or in none with org "". A tenant the policy defines is
// recorded by id alone; one created here keeps its tier and keys.
func (d *Directory) PlaceTenant(ctx context.Context, id, org string) (Tenant, error) {
	var out Tenant
	err := d.update(ctx, func(s *State) ([]change, error) {
		if _, ok := s.Orgs[org]; org != "" && !ok {
			return nil, ErrNotFound
		}
		t, ok := s.Tenants[id]
		if !ok {
			if !ValidTenant(id) {
				return nil, invalid("not a tenant id")
			}
			t = Tenant{ID: id, Created: now()}
		}
		t.Org, out = org, t
		if t.Tier == "" && org == "" {
			return []change{del(kTenants, id)}, nil
		}
		return []change{put(kTenants, id, t)}, nil
	})
	return out, err
}

// CreateKey makes an API key for a tenant created here and returns it; only its hash is kept.
func (d *Directory) CreateKey(ctx context.Context, tenant string) (Key, string, error) {
	b := make([]byte, 24)
	rand.Read(b)
	plain := "lp_" + base64.RawURLEncoding.EncodeToString(b)
	sum := policy.HashKey(plain)
	k := Key{ID: newID("k_"), Tenant: tenant, Hash: hex.EncodeToString(sum[:]), Prefix: plain[:9], Created: now()}
	return k, plain, d.update(ctx, func(s *State) ([]change, error) {
		if t, ok := s.Tenants[tenant]; !ok || t.Tier == "" {
			return nil, ErrNotFound
		}
		return []change{put(kKeys, k.ID, k)}, nil
	})
}

// DeleteKey revokes a key of tenant.
func (d *Directory) DeleteKey(ctx context.Context, tenant, id string) error {
	return d.update(ctx, func(s *State) ([]change, error) {
		if k, ok := s.Keys[id]; !ok || k.Tenant != tenant {
			return nil, ErrNotFound
		}
		return []change{del(kKeys, id)}, nil
	})
}
