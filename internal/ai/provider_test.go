package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/limiter"
)

var sampleFacts = []Fact{
	{ID: "F1", Kind: "decision", Text: "GET /v1/ping from client 203.0.113.7 (tenant acme) was blocked (burst) at 14:02:00 UTC; burst 20, retry after 1.0s."},
	{ID: "F2", Kind: "timing", Text: "Over the 8.3s up to then, 203.0.113.7 sent 50 requests: 47 blocked by burst."},
}

func TestGrounded(t *testing.T) {
	for _, c := range []struct {
		text string
		ok   bool
	}{
		{"The client hit its burst of 20 [F1] and kept retrying: 47 blocks in 8.3s [F2].", true},
		{"Retry loop [F1, F2]; tell the client to back off.", true},
		{"It was blocked [F1][F2] with a 429.", true},
		{"Blocked twice, 3 times maybe [F1].", true}, // small counts are phrasing, not claims
		{"Blocked by burst.", false},                 // no citation
		{"Blocked [F9].", false},                     // unknown fact
		{"Blocked [M1].", false},                     // incidents weren't given
		{"Blocked [see above].", false},              // not a fact id
		{"Blocked [].", false},
		{"It sent 480 requests [F2].", false}, // a number no fact has
		{"Blocked at 14:02 after 50 requests [F1].", true},
		{"ok [F1] " + strings.Repeat("x", maxNarrative), false},
	} {
		if got := grounded(c.text, sampleFacts); got != c.ok {
			t.Errorf("grounded(%q) = %v, want %v", c.text, got, c.ok)
		}
	}
}

func TestRedactor(t *testing.T) {
	r := newRedactor()
	in := "client 203.0.113.7 and 2001:db8::1 in 10.0.0.0/24 at 14:02:07, tenant v1.2"
	out := r.redact(in)
	for _, ip := range []string{"203.0.113.7", "2001:db8::1", "10.0.0.0/24"} {
		if strings.Contains(out, ip) {
			t.Fatalf("%s left in %q", ip, out)
		}
	}
	if !strings.Contains(out, "14:02:07") || !strings.Contains(out, "v1.2") {
		t.Fatalf("redacted too much: %q", out)
	}
	if r.redact("203.0.113.7") != r.redact("203.0.113.7") {
		t.Fatal("one client should keep one name")
	}
	if back := r.restore(out); back != in {
		t.Fatalf("restore: %q", back)
	}
}

// fake is a provider endpoint: it records requests and answers with reply.
type fake struct {
	mu     sync.Mutex
	bodies []map[string]any
	heads  []http.Header
	paths  []string
	reply  func(w http.ResponseWriter, body map[string]any)
}

func (f *fake) server(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.bodies, f.heads, f.paths = append(f.bodies, body), append(f.heads, r.Header.Clone()), append(f.paths, r.URL.Path)
		f.mu.Unlock()
		f.reply(w, body)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func anthropicReply(text, stop string) func(http.ResponseWriter, map[string]any) {
	return func(w http.ResponseWriter, _ map[string]any) {
		json.NewEncoder(w).Encode(map[string]any{
			"type": "message", "role": "assistant", "stop_reason": stop,
			"content": []map[string]any{{"type": "thinking", "thinking": "", "signature": "sig"}, {"type": "text", "text": text}},
			"usage":   map[string]int{"input_tokens": 300, "cache_read_input_tokens": 20, "output_tokens": 40},
		})
	}
}

func anthropicService(t *testing.T, f *fake, c Config) *Service {
	ts := f.server(t)
	c.Provider = &Anthropic{BaseURL: ts.URL, Key: "sk-test", Model: "claude-haiku-5-5", Effort: "low", HTTP: ts.Client()}
	return New(c)
}

func TestAnthropicRequestShape(t *testing.T) {
	f := &fake{reply: anthropicReply("The client 203.0.113.7 retried 47 times in 8.3s [F2]; fix its backoff [F1].", "end_turn")}
	s := anthropicService(t, f, Config{})
	n := s.narrate(context.Background(), "role", "task about 203.0.113.7", sampleFacts)
	if n.Fallback != "" || n.Model != "anthropic/claude-haiku-5-5" {
		t.Fatalf("narrative: %+v", n)
	}
	// The model saw a hash; the operator sees the address again.
	if !strings.Contains(n.Text, "203.0.113.7") || strings.Contains(n.Text, "ip-") {
		t.Fatalf("text not restored: %q", n.Text)
	}
	h, b := f.heads[0], f.bodies[0]
	if f.paths[0] != "/v1/messages" || h.Get("X-Api-Key") != "sk-test" || h.Get("Anthropic-Version") != "2026-10-21" || h.Get("Content-Type") != "application/json" {
		t.Fatalf("path %s headers %v", f.paths[0], h)
	}
	if b["model"] != "claude-haiku-5-5" || b["max_tokens"] != float64(replyTokens) || b["output_config"].(map[string]any)["effort"] != "low" {
		t.Fatalf("body: %v", b)
	}
	for _, k := range []string{"temperature", "top_p", "top_k", "thinking"} {
		if _, ok := b[k]; ok {
			t.Fatalf("%s must not be sent on API version 2026-10-21", k)
		}
	}
	raw, _ := json.Marshal(b)
	if strings.Contains(string(raw), "203.0.113.7") || !strings.Contains(string(raw), "ip-") {
		t.Fatalf("raw IP sent to the model: %s", raw)
	}
	msgs := b["messages"].([]any)
	if len(msgs) != 1 || msgs[0].(map[string]any)["role"] != "user" {
		t.Fatalf("messages: %v", msgs)
	}
	if sys := b["system"].([]any)[0].(map[string]any); sys["type"] != "text" || !strings.Contains(sys["text"].(string), "square brackets") {
		t.Fatalf("system: %v", sys)
	}
	var m strings.Builder
	s.WriteMetrics(&m)
	for _, want := range []string{`limitplane_ai_tokens_total{dir="in"} 320`, `limitplane_ai_tokens_total{dir="out"} 40`, "limitplane_ai_requests_total 1", "limitplane_ai_errors_total 0"} {
		if !strings.Contains(m.String(), want) {
			t.Fatalf("metrics missing %q:\n%s", want, m.String())
		}
	}
}

func TestShareIPs(t *testing.T) {
	f := &fake{reply: anthropicReply("Blocked [F1].", "end_turn")}
	s := anthropicService(t, f, Config{ShareIPs: true})
	s.narrate(context.Background(), "role", "task", sampleFacts)
	raw, _ := json.Marshal(f.bodies[0])
	if !strings.Contains(string(raw), "203.0.113.7") {
		t.Fatal("opted in, but the IP was hashed")
	}
}

func TestOpenAIRequestShape(t *testing.T) {
	f := &fake{reply: func(w http.ResponseWriter, _ map[string]any) {
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"Burst of 20 used up [F1]."},"finish_reason":"stop"}],"usage":{"prompt_tokens":200,"completion_tokens":12}}`)
	}}
	ts := f.server(t)
	p, err := NewProvider(Options{BaseURL: ts.URL + "/openai/v1/", Model: "llama-3.3-70b", HTTP: ts.Client()}, func(k string) string {
		return map[string]string{"LIMITPLANE_AI_KEY": "gsk-test", "ANTHROPIC_API_KEY": "ignored"}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{Provider: p})
	n := s.narrate(context.Background(), "role", "task", sampleFacts)
	if n.Text != "Burst of 20 used up [F1]." || n.Model != "openai/llama-3.3-70b" {
		t.Fatalf("%+v", n)
	}
	b := f.bodies[0]
	msgs := b["messages"].([]any)
	if f.paths[0] != "/openai/v1/chat/completions" || f.heads[0].Get("Authorization") != "Bearer gsk-test" ||
		b["model"] != "llama-3.3-70b" || b["max_tokens"] != float64(replyTokens) || len(msgs) != 2 || msgs[0].(map[string]any)["role"] != "system" {
		t.Fatalf("path %s auth %q body %v", f.paths[0], f.heads[0].Get("Authorization"), b)
	}
	if s.m.in.Load() != 200 || s.m.out.Load() != 12 {
		t.Fatalf("tokens %d/%d", s.m.in.Load(), s.m.out.Load())
	}
}

func TestNewProvider(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if p, err := NewProvider(Options{}, env(nil)); p != nil || err != nil {
		t.Fatalf("nothing configured: %v %v", p, err)
	}
	p, err := NewProvider(Options{}, env(map[string]string{"ANTHROPIC_API_KEY": "k"}))
	if err != nil || p.Name() != "anthropic/claude-haiku-5-5" {
		t.Fatalf("auto anthropic: %v %v", p, err)
	}
	if _, err := NewProvider(Options{Provider: "anthropic"}, env(nil)); err == nil {
		t.Fatal("anthropic without a key should fail")
	}
	if _, err := NewProvider(Options{Provider: "openai", BaseURL: "http://localhost:11434/v1"}, env(nil)); err == nil {
		t.Fatal("openai without a model should fail")
	}
	if p, err := NewProvider(Options{Provider: "off"}, env(map[string]string{"ANTHROPIC_API_KEY": "k"})); p != nil || err != nil {
		t.Fatal("off is off")
	}
	if _, err := NewProvider(Options{Provider: "gpt"}, env(nil)); err == nil {
		t.Fatal("unknown provider should fail")
	}
}

func TestFallbacks(t *testing.T) {
	big := strings.Repeat("x", maxBody+10)
	for _, c := range []struct {
		name  string
		reply func(http.ResponseWriter, map[string]any)
		why   string
	}{
		{"timeout", func(w http.ResponseWriter, _ map[string]any) { time.Sleep(300 * time.Millisecond) }, whyTimeout},
		{"500", func(w http.ResponseWriter, _ map[string]any) {
			w.WriteHeader(500)
			io.WriteString(w, `{"type":"error","error":{"type":"api_error","message":"boom"}}`)
		}, whyError},
		{"529", func(w http.ResponseWriter, _ map[string]any) { w.WriteHeader(529) }, whyError},
		{"empty", anthropicReply("", "end_turn"), whyError},
		{"garbage", func(w http.ResponseWriter, _ map[string]any) { io.WriteString(w, "<html>bad gateway") }, whyError},
		{"oversize", func(w http.ResponseWriter, _ map[string]any) {
			io.WriteString(w, `{"content":[{"type":"text","text":"`+big+`"}]}`)
		}, whyError},
		{"refusal", anthropicReply("I can't help with that [F1].", "refusal"), whyError},
		{"cut off", anthropicReply("The client [F1", "max_tokens"), whyError},
		{"unknown id", anthropicReply("Blocked [F7].", "end_turn"), whyInvalid},
		{"uncited", anthropicReply("Blocked by burst.", "end_turn"), whyInvalid},
		{"invented number", anthropicReply("It sent 5000 requests [F2].", "end_turn"), whyInvalid},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := &fake{reply: c.reply}
			s := anthropicService(t, f, Config{Timeout: 100 * time.Millisecond})
			n := s.narrate(context.Background(), "role", "task", sampleFacts)
			if n.Text != "" || n.Fallback != c.why {
				t.Fatalf("got %+v, want fallback %s", n, c.why)
			}
			var m strings.Builder
			s.WriteMetrics(&m)
			if !strings.Contains(m.String(), `limitplane_ai_fallbacks_total{reason="`+c.why+`"} 1`) {
				t.Fatalf("metrics:\n%s", m.String())
			}
			if c.why != whyInvalid && !strings.Contains(m.String(), "limitplane_ai_errors_total 1") {
				t.Fatalf("error not counted:\n%s", m.String())
			}
		})
	}
	// The explanation itself survives every one of these.
	f := &fake{reply: func(w http.ResponseWriter, _ map[string]any) { w.WriteHeader(500) }}
	s := anthropicService(t, f, Config{})
	audit := burstRun("203.0.113.7", 20, 100*time.Millisecond)
	e := s.Explain(context.Background(), Input{Now: t0, Decision: &audit[0], Audit: audit, Policy: testPolicy()})
	if e.Summary == "" || e.Narrative.Fallback != whyError {
		t.Fatalf("%+v", e)
	}
}

func TestInFlightCap(t *testing.T) {
	entered, release := make(chan struct{}, 4), make(chan struct{})
	f := &fake{reply: func(w http.ResponseWriter, b map[string]any) {
		entered <- struct{}{}
		<-release
		anthropicReply("Blocked [F1].", "end_turn")(w, b)
	}}
	s := anthropicService(t, f, Config{InFlight: 1, Timeout: 5 * time.Second})
	done := make(chan Narrative)
	go func() { done <- s.narrate(context.Background(), "r", "t", sampleFacts) }()
	<-entered
	if n := s.narrate(context.Background(), "r", "t", sampleFacts); n.Fallback != whyBusy {
		t.Fatalf("second call while the slot is taken: %+v", n)
	}
	close(release)
	if n := <-done; n.Text != "Blocked [F1]." {
		t.Fatalf("first call: %+v", n)
	}
	if n := s.narrate(context.Background(), "r", "t", sampleFacts); n.Fallback != "" {
		t.Fatalf("slot not released: %+v", n)
	}
}

func TestOwnLimiter(t *testing.T) {
	f := &fake{reply: anthropicReply("Blocked [F1].", "end_turn")}
	s := anthropicService(t, f, Config{Limits: limiter.NewMemory(), Calls: limiter.Rate{Limit: 1, Period: time.Hour, Burst: 2}})
	for i := range 2 {
		if n := s.narrate(context.Background(), "r", "t", sampleFacts); n.Fallback != "" {
			t.Fatalf("call %d: %+v", i, n)
		}
	}
	if n := s.narrate(context.Background(), "r", "t", sampleFacts); n.Fallback != whyLimited {
		t.Fatalf("third call: %+v", n)
	}
	if len(f.bodies) != 2 {
		t.Fatalf("a limited call reached the provider: %d calls", len(f.bodies))
	}
}

func TestNoProvider(t *testing.T) {
	s := New(Config{})
	if n := s.narrate(context.Background(), "r", "t", sampleFacts); n != (Narrative{}) {
		t.Fatalf("%+v", n)
	}
	var m strings.Builder
	s.WriteMetrics(&m)
	if strings.Contains(m.String(), "} 1") {
		t.Fatalf("rules-only answers aren't fallbacks:\n%s", m.String())
	}
}
