package kube

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAPI is a tiny in-memory API server: enough of list, watch (with history and 410), get,
// create, update (with resourceVersion conflicts) and status merge patches for these tests.
type fakeAPI struct {
	mu        sync.Mutex
	rv        int
	compacted int                       // watches from a version below this get 410
	objs      map[string]map[string]obj // collection path -> name -> object
	history   map[string][]watchEvent   // collection path -> every change, for resuming watches
	watchers  map[chan watchEvent]string
	reqs      []string // "token METHOD path?query"
}

type obj = map[string]any

type watchEvent struct {
	Type   string `json:"type"`
	Object obj    `json:"object"`
	rv     int
}

func newFake(t *testing.T) (*fakeAPI, *httptest.Server) {
	f := &fakeAPI{objs: map[string]map[string]obj{}, history: map[string][]watchEvent{}, watchers: map[chan watchEvent]string{}}
	srv := httptest.NewServer(f)
	t.Cleanup(func() {
		f.dropWatches()
		srv.Close()
	})
	return f, srv
}

func clientFor(srv *httptest.Server, token string) *Client {
	return &Client{Base: srv.URL, Namespace: "ns", HTTP: srv.Client(), Token: func() string { return token }}
}

// split turns /api(s)/.../namespaces/ns/<plural>[/name[/status]] into its collection, name and subresource.
func split(path string) (coll, name, sub string) {
	i := strings.Index(path, "/namespaces/ns/")
	parts := strings.Split(path[i+len("/namespaces/ns/"):], "/")
	coll = path[:i] + "/namespaces/ns/" + parts[0]
	if len(parts) > 1 {
		name = parts[1]
	}
	if len(parts) > 2 {
		sub = parts[2]
	}
	return
}

func meta(o obj) obj {
	m, _ := o["metadata"].(obj)
	if m == nil {
		m = obj{}
		o["metadata"] = m
	}
	return m
}

// put stores o under a new resourceVersion and records the change. Caller holds mu.
func (f *fakeAPI) put(coll, typ string, o obj) {
	f.rv++
	m := meta(o)
	m["resourceVersion"] = strconv.Itoa(f.rv)
	if f.objs[coll] == nil {
		f.objs[coll] = map[string]obj{}
	}
	name := m["name"].(string)
	if typ == "DELETED" {
		delete(f.objs[coll], name)
	} else {
		f.objs[coll][name] = o
	}
	ev := watchEvent{Type: typ, Object: clone(o), rv: f.rv}
	f.history[coll] = append(f.history[coll], ev)
	for ch, c := range f.watchers {
		if c == coll {
			ch <- ev
		}
	}
}

func clone(o obj) obj {
	b, _ := json.Marshal(o)
	var c obj
	json.Unmarshal(b, &c)
	return c
}

// seed creates or replaces an object the way kubectl apply would (bumping generation).
func (f *fakeAPI) seed(coll string, o obj) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := meta(o)
	name := m["name"].(string)
	typ := "ADDED"
	gen := 1.0
	if old, ok := f.objs[coll][name]; ok {
		typ = "MODIFIED"
		gen = meta(old)["generation"].(float64) + 1
		if st, ok := old["status"]; ok {
			o["status"] = st
		}
	}
	m["generation"], m["uid"], m["namespace"] = gen, "uid-"+name, "ns"
	f.put(coll, typ, clone(o))
}

func (f *fakeAPI) get(coll, name string) obj {
	f.mu.Lock()
	defer f.mu.Unlock()
	if o, ok := f.objs[coll][name]; ok {
		return clone(o)
	}
	return nil
}

// event returns a recorded Event with this reason.
func (f *fakeAPI) event(reason string) obj {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.objs["/api/v1/namespaces/ns/events"] {
		if e["reason"] == reason {
			return clone(e)
		}
	}
	return nil
}

// dropWatches ends every open watch stream, as an API server restart or timeout would.
func (f *fakeAPI) dropWatches() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for ch := range f.watchers {
		close(ch)
		delete(f.watchers, ch)
	}
}

// expire deletes an object while no watch is open, then compacts history past the delete,
// so a watcher can only learn about it by relisting.
func (f *fakeAPI) expire(coll, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for ch := range f.watchers {
		close(ch)
		delete(f.watchers, ch)
	}
	f.put(coll, "DELETED", f.objs[coll][name])
	f.compacted = f.rv
}

// requests returns the recorded requests that contain every one of the substrings.
func (f *fakeAPI) requests(subs ...string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.reqs {
		ok := true
		for _, s := range subs {
			ok = ok && strings.Contains(r, s)
		}
		if ok {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	coll, name, sub := split(r.URL.Path)
	q := r.URL.Query()
	f.mu.Lock()
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.reqs = append(f.reqs, fmt.Sprintf("%s %s %s?%s", tok, r.Method, r.URL.Path, r.URL.RawQuery))
	if r.Method == http.MethodGet && q.Get("watch") == "1" {
		f.watch(w, r, coll, q.Get("resourceVersion")) // unlocks
		return
	}
	defer f.mu.Unlock()

	fail := func(code int, msg string) {
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(obj{"kind": "Status", "code": code, "message": msg})
	}
	var body obj
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&body)
	}
	cur, exists := f.objs[coll][name]
	switch {
	case r.Method == http.MethodGet && name == "":
		items := []obj{}
		for _, n := range slices.Sorted(maps.Keys(f.objs[coll])) {
			o := f.objs[coll][n]
			if sel := q.Get("labelSelector"); sel != "" {
				k, v, _ := strings.Cut(sel, "=")
				if l, _ := meta(o)["labels"].(obj); l[k] != v {
					continue
				}
			}
			items = append(items, o)
		}
		json.NewEncoder(w).Encode(obj{"metadata": obj{"resourceVersion": strconv.Itoa(f.rv)}, "items": items})
	case r.Method == http.MethodGet:
		if !exists {
			fail(404, "not found")
			return
		}
		json.NewEncoder(w).Encode(cur)
	case r.Method == http.MethodPost:
		m := meta(body)
		if g, _ := m["generateName"].(string); g != "" {
			m["name"] = g + strconv.Itoa(f.rv+1)
		}
		if _, dup := f.objs[coll][m["name"].(string)]; dup {
			fail(409, "already exists")
			return
		}
		m["uid"] = "uid-" + m["name"].(string)
		f.put(coll, "ADDED", body)
		json.NewEncoder(w).Encode(body)
	case r.Method == http.MethodPut:
		if !exists {
			fail(404, "not found")
			return
		}
		if meta(body)["resourceVersion"] != meta(cur)["resourceVersion"] {
			fail(409, "the object has been modified")
			return
		}
		f.put(coll, "MODIFIED", body)
		json.NewEncoder(w).Encode(body)
	case r.Method == http.MethodPatch && sub == "status":
		if !exists {
			fail(404, "not found")
			return
		}
		o := clone(cur)
		o["status"] = body["status"]
		f.put(coll, "MODIFIED", o)
		json.NewEncoder(w).Encode(o)
	default:
		fail(405, "unsupported")
	}
}

// watch replays history after rv, then streams live changes. Called with mu held.
func (f *fakeAPI) watch(w http.ResponseWriter, r *http.Request, coll, rvs string) {
	rv, _ := strconv.Atoi(rvs)
	if rv < f.compacted {
		f.mu.Unlock()
		w.WriteHeader(http.StatusGone)
		json.NewEncoder(w).Encode(obj{"kind": "Status", "code": 410, "message": "too old resource version"})
		return
	}
	ch := make(chan watchEvent, 100)
	for _, ev := range f.history[coll] {
		if ev.rv > rv {
			ch <- ev
		}
	}
	f.watchers[ch] = coll
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		delete(f.watchers, ch)
		f.mu.Unlock()
	}()

	w.WriteHeader(200)
	w.(http.Flusher).Flush()
	enc := json.NewEncoder(w)
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			enc.Encode(ev)
			w.(http.Flusher).Flush()
		}
	}
}

// sendGone pushes an in-stream 410 ERROR event to every open watch, the other way a server reports expiry.
func (f *fakeAPI) sendGone() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for ch := range f.watchers {
		ch <- watchEvent{Type: "ERROR", Object: obj{"kind": "Status", "code": 410}}
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}
