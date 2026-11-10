package ai

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/autopilot"
	"github.com/iammdzaidalam/limitplane/internal/gateway"
	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

func TestStormAndDegradedWindow(t *testing.T) {
	s := New(Config{})
	for i := range 150 {
		d := gateway.Decision{Time: t0.Add(time.Duration(i) * 100 * time.Millisecond), Tenant: "acme", Client: "203.0.113.7", Reason: "burst"}
		if i%10 == 0 {
			d.Client = "198.51.100.1"
		}
		if i < 40 {
			d.Degraded = true
		}
		s.Observe(d)
	}
	s.Observe(gateway.Decision{Time: t0.Add(time.Minute), Tenant: "acme", Allowed: true, Reason: "ok"}) // closes the minute
	s.Observe(gateway.Decision{Time: t0.Add(61 * time.Second), Tenant: "acme", Allowed: true, Reason: "ok"})
	hs := s.Memory.Search(Query{Text: "storm", Now: t0.Add(time.Hour)})
	if len(hs) != 1 || hs[0].Tenant != "acme" || hs[0].Client != "203.0.113.7" ||
		!strings.Contains(hs[0].Text, "150 of 150 requests blocked in the minute from 14:02 UTC (burst 150), from 2 clients; 203.0.113.7 caused 135") ||
		!strings.Contains(hs[0].Note, "One client, 203.0.113.7") {
		t.Fatalf("storm: %+v", hs)
	}
	// A second storm within ten minutes isn't news.
	for i := range 150 {
		s.Observe(gateway.Decision{Time: t0.Add(2*time.Minute + time.Duration(i)*time.Millisecond), Tenant: "acme", Reason: "burst"})
	}
	s.tick(t0.Add(4 * time.Minute))
	if n := len(s.Memory.Search(Query{Text: "storm", Now: t0.Add(time.Hour)})); n != 1 {
		t.Fatalf("storms: %d", n)
	}
	// tick also ended the degraded window, quiet since 14:02:03.9
	hs = s.Memory.Search(Query{Text: "redis outage", Now: t0.Add(time.Hour)})
	if len(hs) != 1 || hs[0].Kind != "degraded" || hs[0].Tenant != "" || !strings.Contains(hs[0].Text, "from 14:02:00 UTC to 14:02:03 UTC (3.9s): 40 decisions") {
		t.Fatalf("degraded: %+v", hs)
	}
}

func TestBanNoteWithoutModel(t *testing.T) {
	s := New(Config{})
	audit := burstRun("203.0.113.7", 30, 100*time.Millisecond)
	d := s.Ban(limiter.Ban{Client: "203.0.113.7", Until: t0.Add(5 * time.Minute), Reason: "storm"}, Input{Now: t0, Audit: audit, Policy: testPolicy(), Rules: autopilot.DefaultRules})
	if d.ID == 0 || d.Tenant != "acme" || d.NoteBy != "rules" || !strings.Contains(d.Note, "Autopilot banned 203.0.113.7 for a storm") || !strings.Contains(d.Note, "retry loop") {
		t.Fatalf("%+v", d)
	}
	a := s.Alert(autopilot.Alert{Tenant: "acme", Month: "2026-11", Used: 41000, Limit: 50000}, Input{Now: t0, Policy: testPolicy()})
	if !strings.Contains(a.Text, "41,000 of 50,000 units (82%)") || !strings.HasPrefix(a.Note, "acme is on pace to run out of its monthly quota on 2026-11-13") {
		t.Fatalf("%+v", a)
	}
}

func TestBanNoteEnriched(t *testing.T) {
	answer := "Retry loop from 203.0.113.7 [F0]: it kept retrying after 429s [F3]; fix its backoff."
	f := &fake{reply: anthropicReply(answer, "end_turn")}
	var mu sync.Mutex
	var events []Doc
	s := anthropicService(t, f, Config{Publish: func(ev string, v any) {
		mu.Lock()
		defer mu.Unlock()
		if ev == "note" {
			events = append(events, v.(Doc))
		}
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	audit := burstRun("203.0.113.7", 30, 100*time.Millisecond)
	d := s.Ban(limiter.Ban{Client: "203.0.113.7", Until: t0.Add(5 * time.Minute), Reason: "storm"}, Input{Now: t0, Audit: audit, Policy: testPolicy(), Rules: autopilot.DefaultRules})
	if d.NoteBy != "rules" || d.Note == "" {
		t.Fatalf("the rule note is there at once: %+v", d)
	}
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(events) == 1 })
	e := events[0]
	stored := "Retry loop from 203.0.113.7: it kept retrying after 429s; fix its backoff."
	if e.ID != d.ID || e.Note != stored || e.NoteBy != "anthropic/claude-haiku-5-5" {
		t.Fatalf("note event: %+v", e)
	}
	if hs := s.Memory.Search(Query{Text: "backoff", Now: t0}); len(hs) != 1 || hs[0].Note != stored {
		t.Fatalf("memory: %+v", hs)
	}
	if !strings.Contains(f.bodies[0]["messages"].([]any)[0].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string), "F0: Banned ip-") {
		t.Fatal("the incident itself should be fact F0, with the IP hashed")
	}
}

func TestBanNoteEnrichFails(t *testing.T) {
	f := &fake{reply: func(w http.ResponseWriter, _ map[string]any) { w.WriteHeader(503) }}
	var mu sync.Mutex
	published := 0
	s := anthropicService(t, f, Config{Publish: func(string, any) { mu.Lock(); published++; mu.Unlock() }})
	st := RedisStore{R: &fakeRedis{}}
	s.c.Store = st
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	d := s.Alert(autopilot.Alert{Tenant: "acme", Month: "2026-11", Used: 41000, Limit: 50000}, Input{Now: t0, Policy: testPolicy()})
	// The rule note is persisted once the model has failed; nothing extra goes out on SSE.
	waitFor(t, func() bool {
		docs, _ := st.Load(context.Background())
		return len(docs) == 1 && docs[0].Note == d.Note && docs[0].NoteBy == "rules"
	})
	mu.Lock()
	defer mu.Unlock()
	if published != 0 {
		t.Fatalf("published %d", published)
	}
}

func TestPolicyChanged(t *testing.T) {
	s := New(Config{})
	old, cur := testPolicy(), testPolicy()
	snap := func(c policy.Config) snapshot { return snapshot{c, TenantTiers(c)} }
	s.policyChanged(snap(old), snap(cur), t0)
	if s.Memory.Len() != 0 {
		t.Fatal("no change, no incident")
	}
	cur.Tiers = map[string]policy.Tier{"free": cur.Tiers["free"], "pro": {Rate: limiter.Rate{Limit: 200, Period: time.Second, Burst: 400}}, "team": cur.Tiers["free"]}
	cur.Routes = []policy.Route{{Prefix: "/v1/generate", Cost: 8}, {Prefix: "/v1/embed", Cost: 2}}
	cur.Keys = map[string]policy.Tenant{"sk-secret-1": {ID: "acme", Tier: "pro"}, "sk-secret-3": {ID: "initech", Tier: "team"}}
	s.policyChanged(snap(old), snap(cur), t0)
	all := s.Memory.Search(Query{Now: t0, K: 10})
	var texts []string
	for _, h := range all {
		if strings.Contains(h.Text, "sk-secret") {
			t.Fatalf("API key in an incident: %s", h.Text)
		}
		texts = append(texts, h.Tenant+"|"+h.Text)
	}
	slices.Sort(texts)
	want := []string{
		"acme|Tenant acme moved from tier free to pro.",
		"globex|Tenant globex removed (was on tier pro).",
		"initech|Tenant initech added on tier team.",
		"|Policy reloaded: tier pro changed from 100 per second, burst 200 to 200 per second, burst 400; tier team added (1 per second, burst 20, 50,000 a month); route /v1 removed; route /v1/embed added at 2 units; route /v1/generate cost 5 to 8; 3 tenants added, removed or moved.",
	}
	if !slices.Equal(texts, want) {
		t.Fatalf("got\n%s", strings.Join(texts, "\n"))
	}
	// acme's own org sees its move, not the others'.
	hs := s.Memory.Search(Query{Text: "policy", Now: t0, Visible: func(t string) bool { return t == "acme" }})
	if len(hs) != 1 || hs[0].Tenant != "acme" {
		t.Fatalf("scoped: %+v", hs)
	}
}

// Tenants from an org directory (not in Policy.Keys) are diffed and explained too.
func TestDirectoryTenants(t *testing.T) {
	dir := map[string]string{"initech": "pro"}
	s := New(Config{Policy: testPolicy, Tenants: func() map[string]string { return dir }})
	was := s.snapshot()
	dir = map[string]string{"initech": "free"}
	s.policyChanged(was, s.snapshot(), t0)
	if hs := s.Memory.Search(Query{Text: "initech", Now: t0}); len(hs) != 1 || hs[0].Text != "Tenant initech moved from tier pro to free." {
		t.Fatalf("%+v", hs)
	}
	e := Explain(Input{Now: t0, Tenant: "initech", Policy: testPolicy(), Tenants: dir, Used: 50000, UsedOK: true})
	has(t, e.Findings, "initech has used its whole monthly quota")
}

func TestAsk(t *testing.T) {
	s := New(Config{})
	s.Memory = seeded()
	live := Explain(Input{Now: t0, Tenant: "acme", Policy: testPolicy(), Used: 45000, UsedOK: true})
	a := s.Ask(context.Background(), Question{Query: Query{Text: "what happened to acme last night?", Now: t0}, Live: []Explanation{live}})
	if len(a.Hits) != 1 || !strings.Contains(a.Answer, "Now, tenant acme: acme is on pace") || !strings.Contains(a.Answer, "1 incident matches") ||
		!strings.Contains(a.Answer, "Nov 10 23:14 UTC ban: Banned 203.0.113.7") || !strings.Contains(a.Answer, "["+a.Hits[0].Ref+"]") {
		t.Fatalf("answer:\n%s", a.Answer)
	}
	if a.Narrative != (Narrative{}) {
		t.Fatal("no model, no narrative")
	}
	if a := s.Ask(context.Background(), Question{Query: Query{Text: "zebras", Now: t0}}); a.Answer != "No remembered incidents match that." {
		t.Fatalf("%q", a.Answer)
	}

	// With a model: incident ids and renumbered live facts are both citable; nothing else is.
	ref := a.Hits[0].Ref
	f := &fake{reply: anthropicReply("acme's client 203.0.113.7 was banned for a retry loop ["+ref+"] and acme is near its quota [F2].", "end_turn")}
	s = anthropicService(t, f, Config{})
	s.Memory = seeded()
	a = s.Ask(context.Background(), Question{Query: Query{Text: "what happened to acme last night?", Now: t0}, Live: []Explanation{live}})
	if a.Narrative.Text == "" || !strings.Contains(a.Narrative.Text, "203.0.113.7") {
		t.Fatalf("narrative: %+v", a.Narrative)
	}
	sent := f.bodies[0]["messages"].([]any)[0].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(sent, ref+": 2026-11-10 23:14 UTC ban: Banned ip-") || !strings.Contains(sent, "Question: what happened to acme last night?") {
		t.Fatalf("prompt:\n%s", sent)
	}
}

func TestMentions(t *testing.T) {
	got := Mentions("What happened to ACME and acme-corp, not acmeish?", []string{"acme", "acme-corp", "globex", "acmeish2"})
	if !slices.Equal(got, []string{"acme", "acme-corp"}) {
		t.Fatalf("%v", got)
	}
}
