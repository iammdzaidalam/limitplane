// Package ai explains rate-limit decisions, remembers incidents and answers ops questions.
//
// Rules first: every answer is built from gateway state by plain code and is useful on its own.
// A model, when configured, only rewrites that answer from a numbered list of facts, and its
// text is dropped unless every citation names a real fact and every number appears in one.
// IPs are swapped for keyed hashes before anything leaves the process, unless the operator
// opts in; API keys and request bodies are never in the facts at all.
package ai

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iammdzaidalam/limitplane/internal/limiter"
	"github.com/iammdzaidalam/limitplane/internal/policy"
)

type Config struct {
	Provider Provider        // nil: rules only
	Limits   limiter.Limiter // the gateway's own limiter, spent on every model call
	Calls    limiter.Rate    // model calls allowed; zero: 60 an hour, bursts of 10
	ShareIPs bool            // send raw client IPs to the model (default: keyed hashes)
	Timeout  time.Duration   // per model call; default 10s
	InFlight int             // model calls at once; default 4
	Memory   int             // incidents kept; default 2000
	Store    Store           // where incidents persist; nil: in memory only
	// Publish sends an SSE event; enriched incident notes go out as "note".
	Publish func(event string, v any)
	// Policy is polled for reloads, which become incidents. nil: not watched.
	Policy func() policy.Config
	// Tenants maps each tenant to its tier, when tenants live outside Policy.Keys (an org
	// directory). nil: read them from Policy.Keys.
	Tenants func() map[string]string
}

type Service struct {
	c      Config
	llm    *guard // nil without a provider
	m      meter
	Memory *Memory
	jobs   chan job

	mu      sync.Mutex
	deg     degWindow
	minutes map[string]*minute // tenant -> blocks this minute, for storms
	stormAt map[string]time.Time
}

func New(c Config) *Service {
	if c.Calls.Limit == 0 {
		c.Calls = limiter.Rate{Limit: 60, Period: time.Hour, Burst: 10}
	}
	c.Timeout = cmp.Or(c.Timeout, 10*time.Second)
	c.InFlight = cmp.Or(c.InFlight, 4)
	s := &Service{c: c, Memory: NewMemory(c.Memory), jobs: make(chan job, 64), minutes: map[string]*minute{}, stormAt: map[string]time.Time{}}
	if c.Provider != nil {
		s.llm = &guard{p: c.Provider, timeout: c.Timeout, slots: make(chan struct{}, c.InFlight), m: &s.m}
	}
	return s
}

// Status is what the dashboard shows about the AI layer.
type Status struct {
	Model    string `json:"model,omitempty"` // empty: rules only
	ShareIPs bool   `json:"shareIPs"`
	Memory   int    `json:"memory,omitempty"`
	Calls    string `json:"calls"`
}

func (s *Service) Status() Status {
	st := Status{ShareIPs: s.c.ShareIPs, Memory: s.Memory.Len(), Calls: fmt.Sprintf("%d per %s, bursts of %d", s.c.Calls.Limit, s.c.Calls.Period, burstOf(s.c.Calls))}
	if s.c.Provider != nil {
		st.Model = s.c.Provider.Name()
	}
	return st
}

// Run restores and persists memory, closes degraded windows, watches the policy and enriches
// incident notes, until ctx ends.
func (s *Service) Run(ctx context.Context) {
	if s.c.Store != nil {
		rc, cancel := context.WithTimeout(ctx, 5*time.Second)
		s.Memory.Restore(rc, s.c.Store)
		cancel()
		go s.Memory.Persist(ctx, s.c.Store)
	}
	for range s.c.InFlight {
		go s.enrich(ctx)
	}
	var last snapshot
	if s.c.Policy != nil {
		last = s.snapshot()
	}
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.tick(now)
			if s.c.Policy != nil {
				cur := s.snapshot()
				s.policyChanged(last, cur, now)
				last = cur
			}
		}
	}
}

// Fallback reasons, a fixed set so the metric stays small.
const (
	whyLimited = "limited" // our own limiter said no
	whyBusy    = "busy"    // the in-flight cap was full
	whyTimeout = "timeout"
	whyError   = "error"   // transport, status, refusal, cut-off, empty, oversize
	whyInvalid = "invalid" // the answer failed grounding checks
)

var whys = []string{whyLimited, whyBusy, whyTimeout, whyError, whyInvalid}

type meter struct {
	in, out, requests, errors atomic.Int64
	fallbacks                 sync.Map // reason -> *atomic.Int64
}

func (m *meter) fallback(why string) {
	v, _ := m.fallbacks.LoadOrStore(why, new(atomic.Int64))
	v.(*atomic.Int64).Add(1)
}

// WriteMetrics appends the AI series in Prometheus text format.
func (s *Service) WriteMetrics(w io.Writer) {
	fmt.Fprintf(w, "# HELP limitplane_ai_tokens_total Model tokens used, by direction.\n# TYPE limitplane_ai_tokens_total counter\nlimitplane_ai_tokens_total{dir=\"in\"} %d\nlimitplane_ai_tokens_total{dir=\"out\"} %d\n", s.m.in.Load(), s.m.out.Load())
	fmt.Fprintf(w, "# HELP limitplane_ai_requests_total Model calls made.\n# TYPE limitplane_ai_requests_total counter\nlimitplane_ai_requests_total %d\n", s.m.requests.Load())
	fmt.Fprintf(w, "# HELP limitplane_ai_errors_total Model calls that failed.\n# TYPE limitplane_ai_errors_total counter\nlimitplane_ai_errors_total %d\n", s.m.errors.Load())
	fmt.Fprint(w, "# HELP limitplane_ai_fallbacks_total Answers served from rules alone although a model is configured, by reason.\n# TYPE limitplane_ai_fallbacks_total counter\n")
	for _, why := range whys {
		n := int64(0)
		if v, ok := s.m.fallbacks.Load(why); ok {
			n = v.(*atomic.Int64).Load()
		}
		fmt.Fprintf(w, "limitplane_ai_fallbacks_total{reason=%q} %d\n", why, n)
	}
	fmt.Fprintf(w, "# HELP limitplane_ai_memory_docs Incidents in memory.\n# TYPE limitplane_ai_memory_docs gauge\nlimitplane_ai_memory_docs %d\n", s.Memory.Len())
}

// Narrative is the model's rewrite, or why there is none.
type Narrative struct {
	Text     string `json:"text,omitempty"`
	Model    string `json:"model,omitempty"`
	Fallback string `json:"fallback,omitempty"` // set when a model is configured but its text wasn't used
}

const groundRules = `Use only the numbered facts in the message. Cite the facts each sentence rests on in square brackets, like [F2] or [M4, F1]. Do not add numbers, names, addresses, causes or advice that the facts do not support; if the facts don't settle something, say so. Identifiers like ip-1a2b3c4d stand for client addresses: repeat them as written. Plain text, no markdown, no preamble.`

// narrate asks the model to write task from fs and checks the answer. It never fails: on any
// problem the caller keeps its rule-based text and Fallback says why.
func (s *Service) narrate(ctx context.Context, role, task string, fs []Fact) Narrative {
	if s.llm == nil {
		return Narrative{}
	}
	n := Narrative{Model: s.c.Provider.Name()}
	fail := func(why string) Narrative {
		s.m.fallback(why)
		return Narrative{Model: n.Model, Fallback: why}
	}
	if s.c.Limits != nil {
		res, err := s.c.Limits.Allow(ctx, "ai:model", s.c.Calls, 1)
		if err == nil && !res.Allowed {
			return fail(whyLimited)
		}
	}
	var r *redactor
	if !s.c.ShareIPs {
		r = newRedactor()
	}
	if r != nil {
		task = r.redact(task)
	}
	rep, err := s.llm.Complete(ctx, Request{System: role + "\n\n" + groundRules, User: "Facts:\n" + shown(fs, r) + "\n" + task, MaxTokens: replyTokens})
	switch {
	case errors.Is(err, ErrBusy):
		return fail(whyBusy)
	case errors.Is(err, context.DeadlineExceeded):
		return fail(whyTimeout)
	case err != nil:
		return fail(whyError)
	}
	if !grounded(rep.Text, fs) {
		return fail(whyInvalid)
	}
	if r != nil {
		rep.Text = r.restore(rep.Text)
	}
	n.Text = rep.Text
	return n
}

var (
	citeRe   = regexp.MustCompile(`\[([^\[\]]{0,60})\]`)
	idRe     = regexp.MustCompile(`^[A-Z]\d+$`)
	numberRe = regexp.MustCompile(`\d[\d,]*(?:\.\d+)?`)
)

const maxNarrative = 1200

// replyTokens is the model's max_tokens. The answer is a few sentences (maxNarrative caps it),
// but on current Claude models thinking counts toward the cap too, so leave it room.
const replyTokens = 2048

// grounded reports whether text cites at least one fact, cites only facts in fs, and uses no
// number (10 or more) that no cited-or-not fact contains. Small counts and the status code
// 429 are let through: they come up in plain phrasing without being claims.
func grounded(text string, fs []Fact) bool {
	if text == "" || len(text) > maxNarrative {
		return false
	}
	ids := map[string]bool{}
	nums := map[string]bool{"429": true}
	for _, f := range fs {
		ids[f.ID] = true
		for _, x := range numberRe.FindAllString(f.Text, -1) {
			nums[strings.ReplaceAll(x, ",", "")] = true
		}
	}
	cites := citeRe.FindAllStringSubmatch(text, -1)
	if len(cites) == 0 {
		return false
	}
	for _, c := range cites {
		parts := strings.FieldsFunc(c[1], func(r rune) bool { return r == ',' || r == ' ' })
		if len(parts) == 0 {
			return false
		}
		for _, p := range parts {
			if !idRe.MatchString(p) || !ids[p] {
				return false
			}
		}
	}
	bare := ipToken.ReplaceAllString(citeRe.ReplaceAllString(text, ""), "")
	for _, x := range numberRe.FindAllString(bare, -1) {
		x = strings.TrimRight(strings.ReplaceAll(x, ",", ""), ".")
		if len(strings.TrimLeft(x, "0")) > 1 && !nums[x] {
			return false
		}
	}
	return true
}

// sortedKeys is maps.Keys, sorted.
func sortedKeys[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }
