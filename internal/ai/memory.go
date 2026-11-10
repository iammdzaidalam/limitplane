package ai

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Doc is one remembered incident: a ban, a storm, a quota alert, a degraded window, a policy
// reload. Tenant "" means fleet-wide.
type Doc struct {
	ID     int       `json:"id"`
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"`
	Tenant string    `json:"tenant,omitempty"`
	Client string    `json:"client,omitempty"`
	Text   string    `json:"text"`
	Note   string    `json:"note,omitempty"`   // what it likely means and what to do
	NoteBy string    `json:"noteBy,omitempty"` // "rules", or the provider that rewrote it
}

// Ref is how answers cite a doc.
func (d Doc) Ref() string { return "M" + strconv.Itoa(d.ID) }

type Hit struct {
	Doc
	Ref   string  `json:"ref"`
	Score float64 `json:"score"`
}

// Store persists docs across restarts. Save is called off the request path.
type Store interface {
	Save(ctx context.Context, d Doc) error
	Load(ctx context.Context) ([]Doc, error) // oldest first
}

type entry struct {
	Doc
	tf  map[string]int
	len int
}

// Memory is a bounded BM25 index. It is small (a few thousand docs), so a query scans every
// doc: no posting lists to keep in step with eviction, and term statistics can be taken over
// only the docs the caller may see, so scores never reflect another tenant's incidents.
type Memory struct {
	mu   sync.RWMutex
	docs []*entry // oldest first
	byID map[int]*entry
	next int
	size int
	save chan Doc
}

const (
	defaultMemory = 2000
	bm25K1        = 1.2
	bm25B         = 0.75
)

func NewMemory(size int) *Memory {
	if size <= 0 {
		size = defaultMemory
	}
	return &Memory{byID: map[int]*entry{}, next: 1, size: size, save: make(chan Doc, 256)}
}

// Add indexes d and returns it with its ID. persist false holds the write back until the note
// is final (SetNote), so a stored doc carries its enriched note.
func (m *Memory) Add(d Doc, persist bool) Doc {
	m.mu.Lock()
	d.ID = m.next
	m.next++
	m.put(d)
	m.mu.Unlock()
	if persist {
		m.persist(d)
	}
	return d
}

func (m *Memory) put(d Doc) {
	e := &entry{Doc: d}
	e.tf, e.len = termFreq(d)
	m.docs = append(m.docs, e)
	m.byID[d.ID] = e
	if over := len(m.docs) - m.size; over > 0 {
		for _, old := range m.docs[:over] {
			delete(m.byID, old.ID)
		}
		m.docs = slices.Delete(m.docs, 0, over)
	}
}

// SetNote replaces a doc's note and persists it. False if the doc was already evicted.
func (m *Memory) SetNote(id int, note, by string) (Doc, bool) {
	m.mu.Lock()
	e, ok := m.byID[id]
	if ok {
		e.Note, e.NoteBy = note, by
		e.tf, e.len = termFreq(e.Doc)
	}
	var d Doc
	if ok {
		d = e.Doc
	}
	m.mu.Unlock()
	if ok {
		m.persist(d)
	}
	return d, ok
}

func (m *Memory) persist(d Doc) {
	select {
	case m.save <- d:
	default: // the store is slow or down: the in-memory copy still answers
	}
}

func (m *Memory) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.docs)
}

// Restore loads stored docs (oldest first) and renumbers them; IDs are only cited locally.
func (m *Memory) Restore(ctx context.Context, s Store) error {
	docs, err := s.Load(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range docs[max(0, len(docs)-m.size):] {
		d.ID = m.next
		m.next++
		m.put(d)
	}
	return nil
}

// Persist writes docs to s until ctx ends.
func (m *Memory) Persist(ctx context.Context, s Store) {
	for {
		select {
		case <-ctx.Done():
			return
		case d := <-m.save:
			c, cancel := context.WithTimeout(ctx, 2*time.Second)
			s.Save(c, d) // best effort: losing one incident beats blocking the hub
			cancel()
		}
	}
}

// Query asks for incidents. Visible scopes them to tenants the caller may see (nil: all).
type Query struct {
	Text    string
	Visible func(tenant string) bool
	Now     time.Time
	Zone    *time.Location // the asker's zone, for "last night"; nil: UTC
	K       int
}

// Search ranks visible docs in the question's time window by BM25. A question that is only a
// time window ("what happened last night?") lists that window newest first.
func (m *Memory) Search(q Query) []Hit {
	k := cmp.Or(q.K, 8)
	zone := q.Zone
	if zone == nil {
		zone = time.UTC
	}
	from, to, rest := window(strings.ToLower(q.Text), q.Now.In(zone))
	terms := slices.Compact(slices.Sorted(func(yield func(string) bool) {
		for _, t := range tokens(rest) {
			if !yield(t) {
				return
			}
		}
	}))

	m.mu.RLock()
	defer m.mu.RUnlock()
	var pool []*entry
	for _, e := range m.docs {
		if (q.Visible == nil || q.Visible(e.Tenant)) && !e.Time.Before(from) && e.Time.Before(to) {
			pool = append(pool, e)
		}
	}
	hits := make([]Hit, 0, k)
	if len(terms) == 0 {
		for i := len(pool) - 1; i >= 0 && len(hits) < k; i-- {
			hits = append(hits, Hit{Doc: pool[i].Doc, Ref: pool[i].Ref()})
		}
		return hits
	}
	// Statistics over the visible pool only.
	n, total := float64(len(pool)), 0
	df := make(map[string]int, len(terms))
	for _, e := range pool {
		total += e.len
		for _, t := range terms {
			if e.tf[t] > 0 {
				df[t]++
			}
		}
	}
	avg := float64(total) / max(n, 1)
	for _, e := range pool {
		s := 0.0
		for _, t := range terms {
			f := float64(e.tf[t])
			if f == 0 {
				continue
			}
			idf := math.Log(1 + (n-float64(df[t])+0.5)/(float64(df[t])+0.5))
			s += idf * f * (bm25K1 + 1) / (f + bm25K1*(1-bm25B+bm25B*float64(e.len)/avg))
		}
		if s > 0 {
			hits = append(hits, Hit{Doc: e.Doc, Ref: e.Ref(), Score: math.Round(s*1000) / 1000})
		}
	}
	slices.SortStableFunc(hits, func(a, b Hit) int {
		return cmp.Or(cmp.Compare(b.Score, a.Score), b.Time.Compare(a.Time))
	})
	return hits[:min(k, len(hits))]
}

func termFreq(d Doc) (map[string]int, int) {
	ts := tokens(strings.Join([]string{d.Kind, d.Tenant, d.Client, d.Text, d.Note}, " "))
	tf := make(map[string]int, len(ts))
	for _, t := range ts {
		tf[t]++
	}
	return tf, len(ts)
}

var (
	wordRe  = regexp.MustCompile(`[a-z0-9][a-z0-9._:/-]*`)
	partsRe = regexp.MustCompile(`[._:/-]+`)
)

var stop = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`a an and any are as at be been by did do does for from had has have how i in is it
		its me of on or our show so tell than that the their them there these this those to us was we were what when
		where which who why will with about after before happen happened happening going on anything something`) {
		stop[w] = true
	}
}

// tokens lowercases and splits text. Compound tokens (IPs, tenant-ids, paths) are kept whole and
// also split into parts, so "acme" finds "acme-corp" and an exact IP scores highest.
func tokens(s string) []string {
	var out []string
	for _, w := range wordRe.FindAllString(strings.ToLower(s), -1) {
		w = strings.TrimRight(w, "._:/-")
		if !strings.ContainsAny(w, "._:/-") {
			if !stop[w] && len(w) > 1 {
				out = append(out, stem(w))
			}
			continue
		}
		out = append(out, w)
		for _, p := range partsRe.Split(w, -1) {
			if len(p) > 1 && !stop[p] {
				out = append(out, stem(p))
			}
		}
	}
	return out
}

var synonyms = map[string]string{
	"outage": "degrad", "down": "degrad", "fallback": "degrad", "cap": "quota", "reload": "policy",
	"attack": "storm", "flood": "storm", "spike": "storm", "hammer": "storm", "budget": "quota",
}

// stem folds the endings ops questions vary on: bans/banned/banning -> ban, blocks/blocked -> block.
func stem(w string) string {
	if s, ok := synonyms[w]; ok {
		return s
	}
	if len(w) <= 3 || w[0] >= '0' && w[0] <= '9' {
		return w
	}
	switch {
	case strings.HasSuffix(w, "ies") && len(w) > 4:
		w = w[:len(w)-3] + "y"
	case strings.HasSuffix(w, "s") && !strings.HasSuffix(w, "ss"):
		w = w[:len(w)-1]
	}
	switch {
	case strings.HasSuffix(w, "ing") && len(w) > 5:
		w = w[:len(w)-3]
	case strings.HasSuffix(w, "ed") && len(w) > 4:
		w = w[:len(w)-2]
	case strings.HasSuffix(w, "e") && len(w) > 4:
		w = w[:len(w)-1]
	}
	if n := len(w); n > 3 && w[n-1] == w[n-2] && !strings.ContainsRune("lsz", rune(w[n-1])) {
		w = w[:n-1] // bann -> ban
	}
	if s, ok := synonyms[w]; ok {
		return s
	}
	return w
}

var (
	lastN   = regexp.MustCompile(`\b(?:last|past)\s+(\d{1,3})\s*(m|min|mins|minutes?|h|hrs?|hours?|d|days?)\b`)
	phrases = regexp.MustCompile(`\b(?:last night|overnight|yesterday|today|this morning|this afternoon|this evening|tonight|(?:last|past) hour|(?:last|past) day|this week|last week)\b`)
)

// window reads a time phrase from q (lowercase), in now's zone, and returns [from, to) and q
// without the phrase. No phrase: all time.
func window(q string, now time.Time) (time.Time, time.Time, string) {
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	end := now.Add(time.Minute) // docs stamped a moment ago still count
	if m := lastN.FindStringSubmatch(q); m != nil {
		n, _ := strconv.Atoi(m[1])
		unit := map[byte]time.Duration{'m': time.Minute, 'h': time.Hour, 'd': 24 * time.Hour}[m[2][0]]
		return now.Add(-time.Duration(n) * unit), end, strings.Replace(q, m[0], " ", 1)
	}
	p := phrases.FindString(q)
	rest := strings.Replace(q, p, " ", 1)
	at := func(d, h int) time.Time { return day.AddDate(0, 0, d).Add(time.Duration(h) * time.Hour) }
	switch p {
	case "last night", "overnight":
		return at(-1, 18), at(0, 8), rest
	case "yesterday":
		return at(-1, 0), day, rest
	case "today":
		return day, end, rest
	case "this morning":
		return day, at(0, 12), rest
	case "this afternoon":
		return at(0, 12), at(0, 18), rest
	case "this evening", "tonight":
		return at(0, 18), at(1, 0), rest
	case "last hour", "past hour":
		return now.Add(-time.Hour), end, rest
	case "last day", "past day":
		return now.Add(-24 * time.Hour), end, rest
	case "this week", "last week":
		monday := at(-(int(now.Weekday())+6)%7, 0)
		if p == "this week" {
			return monday, end, rest
		}
		return monday.AddDate(0, 0, -7), monday, rest
	}
	return time.Time{}, end, q
}

// RedisStore keeps the newest Cap docs in one Redis list (one key, so one Cluster slot).
type RedisStore struct {
	R interface {
		Do(context.Context, ...any) (any, error)
	}
	Key string // default lp:{ai}:memory
	Cap int    // default 2000
}

func (s RedisStore) key() string { return cmp.Or(s.Key, "lp:{ai}:memory") }

func (s RedisStore) Save(ctx context.Context, d Doc) error {
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if _, err := s.R.Do(ctx, "LPUSH", s.key(), string(b)); err != nil {
		return err
	}
	_, err = s.R.Do(ctx, "LTRIM", s.key(), 0, cmp.Or(s.Cap, defaultMemory)-1)
	return err
}

func (s RedisStore) Load(ctx context.Context) ([]Doc, error) {
	v, err := s.R.Do(ctx, "LRANGE", s.key(), 0, cmp.Or(s.Cap, defaultMemory)-1)
	if err != nil {
		return nil, err
	}
	items, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("ai: LRANGE returned %T", v)
	}
	docs := make([]Doc, 0, len(items))
	for i := len(items) - 1; i >= 0; i-- { // the list is newest first
		var d Doc
		if s, ok := items[i].(string); ok && json.Unmarshal([]byte(s), &d) == nil {
			docs = append(docs, d)
		}
	}
	return docs, nil
}
