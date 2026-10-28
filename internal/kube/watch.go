package kube

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"maps"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// errGone means our resourceVersion was compacted away (HTTP 410): only a fresh list can recover.
var errGone = errors.New("kube: resourceVersion too old")

// Cache keeps a local copy of every object of one resource in the namespace.
// It lists once, then watches from the list's resourceVersion. A dropped watch resumes from
// the last version seen; 410 Gone forces a relist. OnChange runs after every change.
type Cache[T any] struct {
	c        *Client
	res      Resource
	onChange func()

	mu     sync.RWMutex
	items  map[string]T
	synced atomic.Bool
	rv     string // only touched by Run's goroutine
}

func NewCache[T any](c *Client, r Resource, onChange func()) *Cache[T] {
	return &Cache[T]{c: c, res: r, onChange: onChange, items: map[string]T{}}
}

// Synced reports whether the first list has completed.
func (k *Cache[T]) Synced() bool { return k.synced.Load() }

func (k *Cache[T]) Get(name string) (T, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	v, ok := k.items[name]
	return v, ok
}

// Items returns a snapshot keyed by object name.
func (k *Cache[T]) Items() map[string]T {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return maps.Clone(k.items)
}

// Run lists and watches until ctx ends.
func (k *Cache[T]) Run(ctx context.Context) {
	for ctx.Err() == nil {
		var err error
		if k.rv == "" {
			err = k.list(ctx)
		}
		if err == nil {
			err = k.watch(ctx) // nil: the server closed the stream normally, so resume from k.rv
		}
		if errors.Is(err, errGone) {
			log.Printf("kube: %s watch expired, relisting", k.res.Plural)
			k.rv = ""
			continue
		}
		if err != nil && ctx.Err() == nil {
			log.Printf("kube: %s: %v", k.res.Plural, err)
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
		}
	}
}

func (k *Cache[T]) list(ctx context.Context) error {
	var l struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Items []json.RawMessage `json:"items"`
	}
	if err := k.c.Get(ctx, k.c.Path(k.res, ""), &l); err != nil {
		return err
	}
	items := make(map[string]T, len(l.Items))
	for _, raw := range l.Items {
		meta, obj, err := decode[T](raw)
		if err != nil {
			return err
		}
		items[meta.Name] = obj
	}
	k.mu.Lock()
	k.items = items // replace wholesale: objects deleted while we weren't watching disappear
	k.mu.Unlock()
	k.rv = l.Metadata.ResourceVersion
	k.synced.Store(true)
	k.onChange()
	return nil
}

func (k *Cache[T]) watch(ctx context.Context) error {
	q := url.Values{"watch": {"1"}, "resourceVersion": {k.rv}, "allowWatchBookmarks": {"true"}, "timeoutSeconds": {"300"}}
	res, err := k.c.request(ctx, http.MethodGet, k.c.Path(k.res, "")+"?"+q.Encode(), "", nil)
	if IsStatus(err, http.StatusGone) {
		return errGone
	}
	if err != nil {
		return err
	}
	defer res.Body.Close()
	// The body is a stream of {"type": ..., "object": ...} documents.
	dec := json.NewDecoder(res.Body)
	for {
		var ev struct {
			Type   string          `json:"type"`
			Object json.RawMessage `json:"object"`
		}
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if ev.Type == "ERROR" {
			var st struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}
			json.Unmarshal(ev.Object, &st)
			if st.Code == http.StatusGone {
				return errGone
			}
			return &APIError{Code: st.Code, Message: st.Message}
		}
		meta, obj, err := decode[T](ev.Object)
		if err != nil {
			return err
		}
		k.rv = meta.ResourceVersion
		switch ev.Type {
		case "ADDED", "MODIFIED":
			k.mu.Lock()
			k.items[meta.Name] = obj
			k.mu.Unlock()
		case "DELETED":
			k.mu.Lock()
			delete(k.items, meta.Name)
			k.mu.Unlock()
		default: // BOOKMARK only moves the resourceVersion forward
			continue
		}
		k.onChange()
	}
}

func decode[T any](raw json.RawMessage) (ObjectMeta, T, error) {
	var m struct {
		Metadata ObjectMeta `json:"metadata"`
	}
	var obj T
	err := json.Unmarshal(raw, &m)
	if err == nil {
		err = json.Unmarshal(raw, &obj)
	}
	return m.Metadata, obj, err
}
