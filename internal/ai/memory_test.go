package ai

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func refs(hs []Hit) []string {
	var out []string
	for _, h := range hs {
		out = append(out, h.Kind+":"+h.Tenant)
	}
	return out
}

func seeded() *Memory {
	m := NewMemory(0)
	add := func(at time.Time, kind, tenant, text, note string) {
		m.Add(Doc{Time: at, Kind: kind, Tenant: tenant, Text: text, Note: note}, false)
	}
	night := time.Date(2026, 11, 10, 23, 14, 0, 0, time.UTC)
	add(night.Add(-30*time.Hour), "quota", "acme", "Quota alert: acme passed 80% of its monthly quota.", "")
	add(night, "ban", "acme", "Banned 203.0.113.7 (tenant acme) for 5m, reason storm.", "Retry loop: fix its backoff.")
	add(night.Add(time.Hour), "storm", "globex", "Block storm on globex: 300 of 400 requests blocked.", "")
	add(night.Add(2*time.Hour), "degraded", "", "Shared backend unreachable from 01:14 to 01:20: decisions made by local fallbacks.", "")
	add(t0.Add(-10*time.Minute), "ban", "globex", "Banned 198.51.100.4 (tenant globex) for 5m, reason manual.", "")
	return m
}

func TestSearchRanking(t *testing.T) {
	m := seeded()
	q := func(text string) []Hit { return m.Search(Query{Text: text, Now: t0}) }

	// "acme" ranks both acme docs; the exact IP finds the one ban that names it.
	if got := refs(q("what happened to acme?")); !slices.Equal(got, []string{"ban:acme", "quota:acme"}) && !slices.Equal(got, []string{"quota:acme", "ban:acme"}) {
		t.Fatalf("acme: %v", got)
	}
	if got := refs(q("203.0.113.7")); len(got) != 1 || got[0] != "ban:acme" {
		t.Fatalf("ip: %v", got)
	}
	// Word forms fold: "bans" and "banned" meet; "outage" finds the degraded window.
	if got := refs(q("which clients were banned")); len(got) != 2 || got[0][:3] != "ban" {
		t.Fatalf("banned: %v", got)
	}
	if got := refs(q("any outage?")); len(got) != 1 || got[0] != "degraded:" {
		t.Fatalf("outage: %v", got)
	}
	// The note is indexed too.
	if got := refs(q("retry loops")); len(got) != 1 || got[0] != "ban:acme" {
		t.Fatalf("note: %v", got)
	}
	// BM25 prefers the doc where the rarer term appears.
	hs := q("globex storm")
	if hs[0].Kind != "storm" || hs[0].Score <= hs[1].Score || hs[0].Ref != hs[0].Doc.Ref() {
		t.Fatalf("globex storm: %+v", hs)
	}
	if got := q("nothing like this zebra"); len(got) != 0 {
		t.Fatalf("no match should be empty: %v", refs(got))
	}
}

func TestSearchWindow(t *testing.T) {
	m := seeded()
	// "last night" is 18:00 yesterday to 08:00 today in the asker's zone.
	got := refs(m.Search(Query{Text: "what happened to acme last night?", Now: t0}))
	if !slices.Equal(got, []string{"ban:acme"}) {
		t.Fatalf("acme last night: %v", got)
	}
	// Only a window: everything in it, newest first.
	got = refs(m.Search(Query{Text: "what happened last night", Now: t0}))
	if !slices.Equal(got, []string{"degraded:", "storm:globex", "ban:acme"}) {
		t.Fatalf("last night: %v", got)
	}
	got = refs(m.Search(Query{Text: "bans in the last 30 minutes", Now: t0}))
	if !slices.Equal(got, []string{"ban:globex"}) {
		t.Fatalf("last 30 minutes: %v", got)
	}
	// In UTC-10, 23:14 UTC on the 10th is 13:14 on the 10th: yesterday afternoon, not last night.
	hst := time.FixedZone("", -10*3600)
	got = refs(m.Search(Query{Text: "acme last night", Now: t0, Zone: hst}))
	if len(got) != 0 {
		t.Fatalf("acme last night in UTC-10: %v", got)
	}
	got = refs(m.Search(Query{Text: "acme yesterday", Now: t0, Zone: hst}))
	if !slices.Equal(got, []string{"ban:acme"}) {
		t.Fatalf("acme yesterday in UTC-10: %v", got)
	}
}

func TestWindowPhrases(t *testing.T) {
	now := time.Date(2026, 11, 11, 14, 0, 0, 0, time.UTC) // a Wednesday
	for _, c := range []struct {
		q, from, to, rest string
	}{
		{"acme today", "11 00:00", "11 14:01", "acme"},
		{"this morning", "11 00:00", "11 12:00", ""},
		{"yesterday bans", "10 00:00", "11 00:00", "bans"},
		{"past 2 hours", "11 12:00", "11 14:01", ""},
		{"last 3 days", "08 14:00", "11 14:01", ""},
		{"this week", "09 00:00", "11 14:01", ""},
		{"last week", "02 00:00", "09 00:00", ""},
	} {
		from, to, rest := window(c.q, now)
		if f := from.Format("02 15:04"); f != c.from || to.Format("02 15:04") != c.to || strings.TrimSpace(rest) != c.rest {
			t.Errorf("%q: %s..%s rest %q", c.q, f, to.Format("02 15:04"), rest)
		}
	}
}

func TestSearchScope(t *testing.T) {
	m := seeded()
	onlyAcme := func(t string) bool { return t == "acme" }
	for _, q := range []string{"globex", "ban", "what happened last night", "198.51.100.4", "outage"} {
		for _, h := range m.Search(Query{Text: q, Now: t0, Visible: onlyAcme}) {
			if h.Tenant != "acme" {
				t.Fatalf("%q leaked %s's incident: %s", q, h.Tenant, h.Text)
			}
		}
	}
	// Scores come from the visible docs alone: the same acme doc scores the same whether or not
	// other tenants have incidents with the same words.
	alone := NewMemory(0)
	for _, h := range m.Search(Query{Visible: onlyAcme, Now: t0}) {
		alone.Add(h.Doc, false)
	}
	a := m.Search(Query{Text: "banned storm", Visible: onlyAcme, Now: t0})
	b := alone.Search(Query{Text: "banned storm", Now: t0})
	if len(a) == 0 || a[0].Score != b[0].Score {
		t.Fatalf("scores depend on hidden docs: %v vs %v", a, b)
	}
}

func TestMemoryBounded(t *testing.T) {
	m := NewMemory(3)
	for i := range 5 {
		m.Add(Doc{Time: t0, Kind: "ban", Text: fmt.Sprintf("doc%d", i)}, false)
	}
	if m.Len() != 3 {
		t.Fatalf("len %d", m.Len())
	}
	if hs := m.Search(Query{Text: "doc0", Now: t0}); len(hs) != 0 {
		t.Fatal("evicted doc still found")
	}
	if _, ok := m.SetNote(1, "x", "rules"); ok {
		t.Fatal("note set on an evicted doc")
	}
	if d, ok := m.SetNote(5, "fix the client", "rules"); !ok || d.Note != "fix the client" {
		t.Fatal("note on a live doc")
	}
	if hs := m.Search(Query{Text: "fix client", Now: t0}); len(hs) != 1 || hs[0].ID != 5 {
		t.Fatalf("note not reindexed: %v", hs)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); !ok(); time.Sleep(2 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
	}
}

// fakeRedis implements the three list commands RedisStore uses.
type fakeRedis struct {
	mu   sync.Mutex
	list []string
}

func (f *fakeRedis) Do(_ context.Context, args ...any) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch args[0] {
	case "LPUSH":
		f.list = append([]string{args[2].(string)}, f.list...)
	case "LTRIM":
		f.list = f.list[:min(len(f.list), args[3].(int)+1)]
	case "LRANGE":
		out := make([]any, 0, len(f.list))
		for _, s := range f.list[:min(len(f.list), args[3].(int)+1)] {
			out = append(out, s)
		}
		out = append(out, "not json") // a bad record is skipped, not fatal
		return out, nil
	}
	return "OK", nil
}

func TestRedisStore(t *testing.T) {
	r := &fakeRedis{}
	s := Service{} // only Memory is used here
	s.Memory = NewMemory(0)
	st := RedisStore{R: r, Cap: 3}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Memory.Persist(ctx, st); close(done) }()
	for i := range 4 {
		s.Memory.Add(Doc{Time: t0.Add(time.Duration(i) * time.Minute), Kind: "ban", Tenant: "acme", Text: fmt.Sprintf("ban %d", i)}, true)
	}
	held := s.Memory.Add(Doc{Time: t0.Add(time.Hour), Kind: "quota", Text: "alert"}, false)
	head := func(sub string) func() bool {
		return func() bool {
			r.mu.Lock()
			defer r.mu.Unlock()
			return len(r.list) > 0 && strings.Contains(r.list[0], sub)
		}
	}
	waitFor(t, head("ban 3"))
	s.Memory.SetNote(held.ID, "enriched", "anthropic/x") // persisted only now, with its note
	waitFor(t, head("enriched"))
	cancel()
	<-done

	m := NewMemory(0)
	if err := m.Restore(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	hs := m.Search(Query{Now: t0.Add(2 * time.Hour)})
	var got []string
	for _, h := range hs {
		got = append(got, h.Text+"/"+h.Note)
	}
	if !slices.Equal(got, []string{"alert/enriched", "ban 3/", "ban 2/"}) {
		t.Fatalf("restored newest first: %v", got)
	}
	if hs[0].ID != 3 {
		t.Fatalf("restored docs are renumbered oldest first: %v", hs[0].ID)
	}
}
