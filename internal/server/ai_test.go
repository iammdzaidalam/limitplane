package server

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/ai"
	"github.com/iammdzaidalam/limitplane/internal/autopilot"
	"github.com/iammdzaidalam/limitplane/internal/gateway"
	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

const aiPolicy = `{
 "tiers": {"free": {"rate": {"limit": 1, "period": "1h", "burst": 5}, "monthly": 1000}},
 "keys": {"acme-key": {"id": "acme", "tier": "free"}, "globex-key": {"id": "globex", "tier": "free"}},
 "anonymous": "free"
}`

func aiServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	cfg, err := policy.Parse([]byte(aiPolicy))
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{Policy: policy.NewStore(cfg), Limits: limiter.NewMemory(), AdminKey: "admin-key", Backend: "memory"})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	ts := httptest.NewServer(s.Handler(nil))
	t.Cleanup(func() { cancel(); ts.Close() })
	return s, ts
}

func post(t *testing.T, url, tok, body string, out any) int {
	t.Helper()
	res := do(t, "POST", url, tok, body)
	if out != nil {
		json.NewDecoder(res.Body).Decode(out)
	}
	return res.StatusCode
}

func traffic(t *testing.T, s *Server, ts *httptest.Server, key string, n int) {
	t.Helper()
	for range n {
		req, _ := http.NewRequest("GET", ts.URL+"/v1/ping", nil)
		req.Header.Set("X-API-Key", key)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(s.Hub.Audit(auditSize)) < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAIExplainEndpoints(t *testing.T) {
	s, ts := aiServer(t)
	tok := login(t, ts.URL)
	traffic(t, s, ts, "acme-key", 8) // 5 pass, 3 burst blocks
	blocked := s.Hub.Audit(1)[0]

	var e ai.Explanation
	b, _ := json.Marshal(map[string]any{"decision": blocked})
	if code := post(t, ts.URL+"/api/ai/explain", tok, string(b), &e); code != 200 || e.Reason != "burst" || !strings.Contains(e.Summary, "burst limit") {
		t.Fatalf("decision: %d %+v", code, e)
	}
	if code := post(t, ts.URL+"/api/ai/explain", tok, `{"client":"127.0.0.1"}`, &e); code != 200 || e.Subject != "client 127.0.0.1" {
		t.Fatalf("client: %d %+v", code, e)
	}
	e = ai.Explanation{}
	if code := post(t, ts.URL+"/api/ai/explain", tok, `{"tenant":"acme"}`, &e); code != 200 || !strings.Contains(e.Facts[1].Text, "acme has used 5 of 1000 monthly units") {
		t.Fatalf("tenant: %d %+v", code, e)
	}
	for _, bad := range []string{`{}`, `{"client":"x","tenant":"acme"}`, `nope`} {
		if code := post(t, ts.URL+"/api/ai/explain", tok, bad, nil); code != 400 {
			t.Fatalf("%s: %d", bad, code)
		}
	}
	if code := post(t, ts.URL+"/api/ai/explain", "", `{"tenant":"acme"}`, nil); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	var st ai.Status
	json.NewDecoder(do(t, "GET", ts.URL+"/api/ai/status", tok, "").Body).Decode(&st)
	if st.Model != "" || st.ShareIPs || st.Calls != "60 per 1h0m0s, bursts of 10" {
		t.Fatalf("status %+v", st)
	}
	m := httptest.NewRecorder()
	s.metrics(m, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(m.Body.String(), "limitplane_ai_requests_total 0") {
		t.Fatalf("metrics lack the AI series:\n%s", m.Body.String())
	}
}

// An org member explains and asks about its own org only; anything else is not there.
func TestAIScope(t *testing.T) {
	rg := newOrgRig(t)
	for range 3 {
		rg.send(t, rg.keys["acme-web"], "203.0.113.1")
		rg.send(t, rg.keys["globex-web"], "198.51.100.2")
	}
	waitAudit(t, rg, 6)
	var globex, acme gateway.Decision
	for _, d := range rg.s.Hub.Audit(6) {
		if d.Tenant == "globex-web" {
			globex = d
		} else {
			acme = d
		}
	}
	viewer, url := rg.tok["acme/viewer"], rg.ts.URL+"/api/ai/explain"
	dec := func(d gateway.Decision) string { b, _ := json.Marshal(map[string]any{"decision": d}); return string(b) }
	for _, body := range []string{dec(globex), `{"tenant":"globex-web"}`, `{"client":"198.51.100.2"}`, `{"tenant":"loose"}`} {
		if code := post(t, url, viewer, body, nil); code != 404 {
			t.Errorf("acme viewer explains %s: %d, want 404", body, code)
		}
	}
	for _, body := range []string{dec(acme), `{"tenant":"acme-web"}`, `{"client":"203.0.113.1"}`} {
		var e ai.Explanation
		if code := post(t, url, viewer, body, &e); code != 200 || len(e.Facts) == 0 {
			t.Errorf("acme viewer explains %s: %d %+v", body, code, e)
		}
		if b, _ := json.Marshal(e); strings.Contains(string(b), "globex") || strings.Contains(string(b), "198.51.100.2") {
			t.Errorf("another org leaked into %s: %s", body, b)
		}
	}
	// The superadmin's ?org= view is scoped the same way.
	if code := post(t, url+"?org=acme", rg.tok["staff"], `{"tenant":"globex-web"}`, nil); code != 404 {
		t.Errorf("staff as acme: %d", code)
	}

	rg.s.ai.svc.Remember(ai.Doc{Time: time.Now(), Kind: "ban", Tenant: "globex-web", Text: "Banned 198.51.100.2 (tenant globex-web)"})
	rg.s.ai.svc.Remember(ai.Doc{Time: time.Now(), Kind: "quota", Tenant: "acme-web", Text: "Quota alert: acme-web passed 80%"})
	rg.s.ai.svc.Remember(ai.Doc{Time: time.Now(), Kind: "degraded", Text: "Shared backend unreachable"})
	var a ai.Answer
	post(t, rg.ts.URL+"/api/ai/chat", viewer, `{"question":"what happened to acme-web and globex-web today?","tz":"60"}`, &a)
	if len(a.Hits) != 1 || a.Hits[0].Tenant != "acme-web" {
		t.Fatalf("chat hits: %+v", a.Hits)
	}
	if strings.Contains(a.Answer, "globex") || !strings.Contains(a.Answer, "Now, tenant acme-web") {
		t.Fatalf("live state must be scoped too:\n%s", a.Answer)
	}
	var hits []ai.Hit
	json.NewDecoder(do(t, "GET", rg.ts.URL+"/api/ai/incidents", viewer, "").Body).Decode(&hits)
	if len(hits) != 1 || hits[0].Tenant != "acme-web" {
		t.Fatalf("incidents: %+v", hits)
	}
	json.NewDecoder(do(t, "GET", rg.ts.URL+"/api/ai/incidents", rg.tok["admin-key"], "").Body).Decode(&hits)
	if len(hits) != 3 {
		t.Fatalf("the platform admin sees every incident: %+v", hits)
	}
}

// A block by the org's shared budget is explained as that, with the org's spend.
func TestAIOrgBudget(t *testing.T) {
	rg := newOrgRig(t)
	if r := do(t, "PATCH", rg.ts.URL+"/api/orgs/acme", rg.tok["acme/owner"], `{"budget":3}`); r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	for range 4 {
		rg.send(t, rg.keys["acme-web"], "203.0.113.1")
	}
	waitAudit(t, rg, 4)
	d := rg.s.Hub.Audit(1)[0]
	if d.Reason != gateway.ReasonOrg {
		t.Fatalf("last decision %+v", d)
	}
	b, _ := json.Marshal(map[string]any{"decision": d})
	var e ai.Explanation
	post(t, rg.ts.URL+"/api/ai/explain", rg.tok["acme/viewer"], string(b), &e)
	if e.Reason != gateway.ReasonOrg || !strings.HasPrefix(e.Summary, "Organisation Acme has used its whole shared monthly budget") {
		t.Fatalf("%+v", e)
	}
	if !strings.Contains(e.Facts[len(e.Facts)-1].Text, "Organisation Acme has spent 3 of its 3 budget (100%)") {
		t.Fatalf("budget fact: %+v", e.Facts)
	}
}

// Incidents and their notes reach only the org of the tenant they name.
func TestScopedIncidentEvents(t *testing.T) {
	rg := newOrgRig(t)
	rg.send(t, rg.keys["globex-web"], "198.51.100.2")
	rg.send(t, rg.keys["acme-web"], "203.0.113.1")
	waitAudit(t, rg, 2)
	sse := do(t, "GET", rg.ts.URL+"/api/events?token="+rg.tok["acme/viewer"], "", "")
	got := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(sse.Body)
		var event string
		for sc.Scan() {
			if e, ok := strings.CutPrefix(sc.Text(), "event: "); ok {
				event = e
			} else if d, ok := strings.CutPrefix(sc.Text(), "data: "); ok && (event == "incident" || event == "note") {
				got <- event + " " + d
			}
		}
	}()
	// globex's: a ban of its client (incident), a note, and a fleet-wide incident with no tenant.
	if r := do(t, "POST", rg.ts.URL+"/api/bans", rg.tok["admin-key"], `{"client":"198.51.100.2","minutes":5}`); r.StatusCode != 204 {
		t.Fatal(r.StatusCode)
	}
	rg.s.Hub.Publish("note", ai.Doc{ID: 99, Kind: "ban", Tenant: "globex-web", Client: "198.51.100.2", Note: "globex's"})
	rg.s.Hub.Publish("incident", ai.Doc{ID: 98, Kind: "degraded", Text: "fleet-wide"})
	// acme's, last: the first incident or note the acme viewer gets must be this one.
	rg.s.Hub.Publish("note", ai.Doc{ID: 97, Kind: "quota", Tenant: "acme-web", Note: "acme's"})
	select {
	case d := <-got:
		if !strings.HasPrefix(d, "note ") || !strings.Contains(d, `"note":"acme's"`) {
			t.Fatalf("acme's viewer got %s", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("acme's own note never arrived")
	}
	if r := do(t, "POST", rg.ts.URL+"/api/bans", rg.tok["admin-key"], `{"client":"203.0.113.1","minutes":5}`); r.StatusCode != 204 {
		t.Fatal(r.StatusCode)
	}
	select {
	case d := <-got:
		if !strings.HasPrefix(d, "incident ") || !strings.Contains(d, `"tenant":"acme-web"`) {
			t.Fatalf("acme's ban incident: %s", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("acme's ban incident never arrived")
	}
}

func TestAIEndpointLimit(t *testing.T) {
	_, ts := aiServer(t)
	tok := login(t, ts.URL)
	got429 := false
	for range aiRate.Burst + 2 {
		res := do(t, "POST", ts.URL+"/api/ai/chat", tok, `{"question":"anything"}`)
		if res.StatusCode == 429 {
			got429 = res.Header.Get("Retry-After") != ""
			break
		}
	}
	if !got429 {
		t.Fatal("the AI endpoints should spend from the gateway's own limiter")
	}
}

func TestAIHooks(t *testing.T) {
	s, ts := aiServer(t)
	tok := login(t, ts.URL)
	traffic(t, s, ts, "acme-key", 8)

	d := s.ai.ban(autopilot.Ban{Client: "127.0.0.1", Until: time.Now().Add(5 * time.Minute), Reason: "storm"})
	if d.Kind != "ban" || d.Client != "127.0.0.1" || d.Tenant != "acme" || d.ID == 0 || !strings.Contains(d.Note, "storm") {
		t.Fatalf("ban incident %+v", d)
	}
	d = s.ai.alert(autopilot.Alert{Tenant: "acme", Month: "2026-11", Used: 800, Limit: 1000})
	if d.Kind != "quota" || d.Tenant != "acme" || d.Note == "" {
		t.Fatalf("alert incident %+v", d)
	}
	var hits []ai.Hit
	json.NewDecoder(do(t, "GET", ts.URL+"/api/ai/incidents?q=acme", tok, "").Body).Decode(&hits)
	if len(hits) != 2 {
		t.Fatalf("incidents: %+v", hits)
	}
	var m strings.Builder
	s.ai.writeMetrics(&m)
	if !strings.Contains(m.String(), `limitplane_ai_tokens_total{dir="in"} 0`) || !strings.Contains(m.String(), "limitplane_ai_memory_docs 2") {
		t.Fatalf("metrics:\n%s", m.String())
	}
}
