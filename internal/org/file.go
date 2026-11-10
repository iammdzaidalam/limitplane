package org

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// fileBackend keeps the directory in one JSON file, rewritten whole on every change: a temp file
// in the same directory, fsynced, then renamed over the old one, so a crash leaves either version
// and never half of one. It is for one process; replicas share a directory through Redis.
type fileBackend struct {
	path string // "": memory only
	mu   sync.Mutex
	st   *State
}

type disk struct {
	Version int64             `json:"version"`
	Orgs    map[string]Org    `json:"orgs"`
	Users   map[string]User   `json:"users"`
	Tenants map[string]Tenant `json:"tenants"`
	Keys    map[string]Key    `json:"keys"`
}

// NewMemory is a directory that lives and dies with the process.
func NewMemory() *Directory { return newDirectory(&fileBackend{st: newState()}) }

// OpenFile keeps the directory in dir/orgs.json, created on the first change.
func OpenFile(dir string) (*Directory, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	b := &fileBackend{path: filepath.Join(dir, "orgs.json")}
	d := newDirectory(b)
	if err := d.Load(context.Background()); err != nil {
		return nil, err
	}
	return d, nil
}

func (b *fileBackend) load(context.Context) (*State, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.path == "" {
		return b.st, nil
	}
	raw, err := os.ReadFile(b.path)
	if errors.Is(err, fs.ErrNotExist) {
		b.st = newState()
		return b.st, nil
	}
	if err != nil {
		return nil, err
	}
	var v disk
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("org: %s: %w", b.path, err) // refuse to start over a directory we can't read
	}
	b.st = (&State{Version: v.Version, Orgs: orEmpty(v.Orgs), Users: orEmpty(v.Users), Tenants: orEmpty(v.Tenants), Keys: orEmpty(v.Keys)}).index()
	return b.st, nil
}

func orEmpty[T any](m map[string]T) map[string]T {
	if m == nil {
		return map[string]T{}
	}
	return m
}

func (b *fileBackend) commit(_ context.Context, v int64, cs []change) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.st == nil || b.st.Version != v {
		return 0, errStale
	}
	n, err := b.st.with(cs, v+1)
	if err != nil {
		return 0, err
	}
	if b.path != "" {
		raw, _ := json.MarshalIndent(disk{n.Version, n.Orgs, n.Users, n.Tenants, n.Keys}, "", "  ")
		if err := writeAtomic(b.path, raw); err != nil {
			return 0, err
		}
	}
	b.st = n
	return n.Version, nil
}

// writeAtomic replaces path with data: temp file, fsync, rename, fsync the directory.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // a no-op after the rename
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), path) // CreateTemp made it 0600: it holds password hashes
	}
	if err != nil {
		return fmt.Errorf("org: write %s: %w", path, err)
	}
	if d, err := os.Open(dir); err == nil { // make the rename itself durable
		d.Sync()
		d.Close()
	}
	return nil
}
