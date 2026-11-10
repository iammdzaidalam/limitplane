package org

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/policy"
	"github.com/iammdzaidalam/limitplane/internal/redisx"
)

var ctx = context.Background()

const pw = "correct horse battery"

// directories runs f against every backend: memory, a file, and Redis when LIMITPLANE_REDIS is set.
func directories(t *testing.T, f func(t *testing.T, open func() *Directory)) {
	t.Run("memory", func(t *testing.T) {
		d := fast(NewMemory())
		f(t, func() *Directory { return d })
	})
	t.Run("file", func(t *testing.T) {
		dir := t.TempDir()
		f(t, func() *Directory {
			d, err := OpenFile(dir)
			if err != nil {
				t.Fatal(err)
			}
			return fast(d)
		})
	})
	t.Run("redis", func(t *testing.T) {
		addr := os.Getenv("LIMITPLANE_REDIS")
		if addr == "" {
			t.Skip("LIMITPLANE_REDIS not set")
		}
		c := redisClient(t, addr)
		f(t, func() *Directory {
			d := fast(NewRedis(c))
			if err := d.Load(ctx); err != nil {
				t.Fatal(err)
			}
			return d
		})
	})
}

func redisClient(t *testing.T, addr string) *redisx.Client {
	c, err := redisx.New(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.Do(ctx, "DEL", dirKeys[0], dirKeys[1], dirKeys[2], dirKeys[3], dirKeys[4])
	return c
}

func fast(d *Directory) *Directory { d.UseIterations(1000); return d }

func TestPasswords(t *testing.T) {
	h := hashPassword(pw, 1000)
	if !strings.HasPrefix(h, "pbkdf2-sha256$1000$") || !checkPassword(h, pw) || checkPassword(h, pw+"x") {
		t.Fatalf("hash %s", h)
	}
	if hashPassword(pw, 1000) == h {
		t.Fatal("salt must differ per hash")
	}
	for _, bad := range []string{"", "sha256$1$a$b", "pbkdf2-sha256$x$AAAA$AAAA", "pbkdf2-sha256$99999999$AAAA$AAAA", "pbkdf2-sha256$1000$!!$AAAA"} {
		if checkPassword(bad, pw) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDirectory(t *testing.T) {
	directories(t, func(t *testing.T, open func() *Directory) {
		d := open()
		o, owner, err := d.Signup(ctx, "Acme Corp", " Alice@Example.com ", pw)
		if err != nil || o.ID != "acme-corp" || owner.Email != "alice@example.com" || owner.Role != Owner {
			t.Fatalf("signup %+v %+v %v", o, owner, err)
		}
		if _, ok := d.Authenticate("ALICE@example.com", pw); !ok {
			t.Fatal("login with the right password")
		}
		for _, c := range [][2]string{{"alice@example.com", "wrong password"}, {"nobody@example.com", pw}} {
			if _, ok := d.Authenticate(c[0], c[1]); ok {
				t.Fatalf("%v accepted", c)
			}
		}
		if _, _, err := d.Signup(ctx, "acme corp!", "bob@example.com", pw); !errors.Is(err, ErrExists) {
			t.Fatalf("same slug: %v", err)
		}
		for _, c := range []struct {
			email, pw string
			role      Role
			org       string
			want      error
		}{
			{"alice@EXAMPLE.com", pw, Viewer, o.ID, ErrExists},
			{"not-an-email", pw, Viewer, o.ID, ErrInvalid},
			{"v@example.com", "short", Viewer, o.ID, ErrInvalid},
			{"v@example.com", pw, "boss", o.ID, ErrInvalid},
			{"v@example.com", pw, Superadmin, o.ID, ErrInvalid},
			{"v@example.com", pw, Viewer, "", ErrInvalid},
			{"v@example.com", pw, Viewer, "ghost", ErrNotFound},
		} {
			if _, err := d.AddUser(ctx, c.org, c.email, c.role, c.pw); !errors.Is(err, c.want) {
				t.Errorf("%+v: %v", c, err)
			}
		}
		viewer, err := d.AddUser(ctx, o.ID, "v@example.com", Viewer, pw)
		if err != nil {
			t.Fatal(err)
		}

		// The last owner stays.
		if _, err := d.SetRole(ctx, owner.ID, Admin); !errors.Is(err, ErrLastOwner) {
			t.Fatalf("demote last owner: %v", err)
		}
		if err := d.RemoveUser(ctx, owner.ID); !errors.Is(err, ErrLastOwner) {
			t.Fatalf("remove last owner: %v", err)
		}
		if u, err := d.SetRole(ctx, viewer.ID, Owner); err != nil || u.Tokens != viewer.Tokens+1 {
			t.Fatalf("promote: %+v %v (a role change revokes)", u, err)
		}
		if _, err := d.SetRole(ctx, owner.ID, Admin); err != nil {
			t.Fatalf("two owners, one may step down: %v", err)
		}
		if u, _ := d.Revoke(ctx, owner.ID); u.Tokens != owner.Tokens+2 {
			t.Fatalf("revoke: %+v", u)
		}
		if _, err := d.SetPassword(ctx, owner.ID, "wrong", "another good password"); !errors.Is(err, ErrInvalid) {
			t.Fatalf("wrong current password: %v", err)
		}
		if _, err := d.SetPassword(ctx, owner.ID, pw, "another good password"); err != nil {
			t.Fatal(err)
		}
		if _, ok := d.Authenticate("alice@example.com", "another good password"); !ok {
			t.Fatal("new password")
		}

		// Tenants and keys.
		if _, err := d.CreateTenant(ctx, Tenant{ID: "web", Org: o.ID, Tier: "free"}); err != nil {
			t.Fatal(err)
		}
		if _, err := d.CreateTenant(ctx, Tenant{ID: "web", Tier: "free"}); !errors.Is(err, ErrExists) {
			t.Fatalf("duplicate tenant: %v", err)
		}
		if _, err := d.CreateTenant(ctx, Tenant{ID: "bad id!", Tier: "free"}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("bad id: %v", err)
		}
		k, plain, err := d.CreateKey(ctx, "web")
		if err != nil || !strings.HasPrefix(plain, k.Prefix) || strings.Contains(k.Hash, plain) {
			t.Fatalf("key %+v %q %v", k, plain, err)
		}
		if _, _, err := d.CreateKey(ctx, "policy-tenant"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("keys only for tenants created here: %v", err)
		}
		if _, err := d.PlaceTenant(ctx, "policy-tenant", o.ID); err != nil {
			t.Fatal(err)
		}
		p := d.Snapshot().Policy()
		if p.Keys[policy.HashKey(plain)] != "web" || p.Tenants["policy-tenant"].Org != o.ID || p.Tenants["web"].Tier != "free" {
			t.Fatalf("policy %+v", p)
		}
		if err := d.DeleteOrg(ctx, o.ID); !errors.Is(err, ErrConflict) {
			t.Fatalf("delete an org with tenants: %v", err)
		}
		if err := d.DeleteTenant(ctx, "policy-tenant"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a policy tenant is unplaced, not deleted: %v", err)
		}
		d.PlaceTenant(ctx, "policy-tenant", "")
		if err := d.DeleteTenant(ctx, "web"); err != nil || len(d.Snapshot().Keys) != 0 {
			t.Fatalf("delete tenant: %v, keys %v", err, d.Snapshot().Keys)
		}
		if err := d.DeleteOrg(ctx, o.ID); err != nil || len(d.Snapshot().Users) != 0 || len(d.Snapshot().Tenants) != 0 {
			t.Fatalf("delete org: %v %+v", err, d.Snapshot())
		}

		// Everything was persisted: a fresh open sees the same version.
		if again := open(); again.Snapshot().Version != d.Snapshot().Version {
			t.Fatalf("reopened at %d, want %d", again.Snapshot().Version, d.Snapshot().Version)
		}
	})
}

func TestFilePersistence(t *testing.T) {
	dir := t.TempDir()
	d, _ := OpenFile(dir)
	fast(d).Signup(ctx, "acme", "a@example.com", pw)
	d2, err := OpenFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := d2.Authenticate("a@example.com", pw); !ok {
		t.Fatal("user lost on reopen")
	}
	fi, err := os.Stat(filepath.Join(dir, "orgs.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v %v", fi, err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.tmp-*")); len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
	os.WriteFile(filepath.Join(dir, "orgs.json"), []byte("{oops"), 0o600)
	if _, err := OpenFile(dir); err == nil {
		t.Fatal("a corrupt file must stop the start, not be replaced by an empty directory")
	}
}

// Two replicas: one email can't be claimed twice, a stale snapshot retries, and a change on one
// reaches the other through pub/sub.
func TestRedisReplicas(t *testing.T) {
	addr := os.Getenv("LIMITPLANE_REDIS")
	if addr == "" {
		t.Skip("LIMITPLANE_REDIS not set")
	}
	c := redisClient(t, addr)
	a, b := fast(NewRedis(c)), fast(NewRedis(c))
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() { b.Watch(wctx) })
	defer cancel()
	o, _, err := a.Signup(ctx, "acme", "owner@example.com", pw)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for b.Snapshot().Orgs[o.ID].ID == "" {
		if time.Now().After(deadline) {
			t.Fatal("the other replica never saw the org")
		}
		time.Sleep(5 * time.Millisecond)
	}

	var wins sync.WaitGroup
	errs := make(chan error, 20)
	for i := range 20 {
		d := []*Directory{a, b}[i%2]
		wins.Go(func() {
			_, err := d.AddUser(ctx, o.ID, "same@example.com", Viewer, pw)
			errs <- err
		})
	}
	wins.Wait()
	close(errs)
	ok := 0
	for err := range errs {
		if err == nil {
			ok++
		} else if !errors.Is(err, ErrExists) && !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d replicas created the same email", ok)
	}
	// a's snapshot may be behind b's commit: its write still lands, after a reload.
	if _, err := a.AddUser(ctx, o.ID, "user"+strconv.Itoa(2)+"@example.com", Admin, pw); err != nil {
		t.Fatal(err)
	}
	if n := len(fast(NewRedis(c)).mustLoad(t).Snapshot().Members(o.ID)); n != 3 {
		t.Fatalf("%d members, want 3", n)
	}
}

func (d *Directory) mustLoad(t *testing.T) *Directory {
	if err := d.Load(ctx); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{"Acme Corp": "acme-corp", "  --x--  ": "x", "Ünïcode Inc.": "n-code-inc", strings.Repeat("ab ", 30): "ab-ab-ab-ab-ab-ab-ab-ab-ab-ab-ab-ab-ab-a"} {
		if got := Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
	}
}
