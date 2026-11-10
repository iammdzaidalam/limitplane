package ai

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Provider is one chat model behind an HTTP API.
type Provider interface {
	Name() string // "anthropic/<model>" or "openai/<model>", for status and docs
	Complete(ctx context.Context, req Request) (Reply, error)
}

type Request struct {
	System    string
	User      string
	MaxTokens int
}

type Reply struct {
	Text    string
	In, Out int64 // tokens, as the provider counted them
}

var (
	ErrBusy     = errors.New("ai: too many model calls in flight")
	ErrTooLarge = errors.New("ai: response over the size cap")
	ErrEmpty    = errors.New("ai: empty answer")
	ErrRefused  = errors.New("ai: model declined")
	ErrCut      = errors.New("ai: answer cut off at max_tokens")
)

// Options picks and configures a provider. Keys come from the environment, never flags.
type Options struct {
	Provider string // "auto" (default), "anthropic", "openai" or "off"
	Model    string
	BaseURL  string
	HTTP     *http.Client
}

const (
	anthropicURL     = "https://api.anthropic.com"
	anthropicVersion = "2026-10-21"
	// Fast and cheap: a few sentences over a short fact list don't need a bigger model.
	defaultAnthropicModel = "claude-haiku-5-5"
)

// NewProvider returns nil (deterministic only) when nothing is configured. auto: an
// OpenAI-compatible endpoint if a base URL is given (Groq, Ollama, vLLM...), since that is an
// explicit choice; else Anthropic if ANTHROPIC_API_KEY is set; else none.
func NewProvider(o Options, getenv func(string) string) (Provider, error) {
	kind := o.Provider
	if kind == "" || kind == "auto" {
		switch {
		case o.BaseURL != "":
			kind = "openai"
		case getenv("ANTHROPIC_API_KEY") != "":
			kind = "anthropic"
		default:
			return nil, nil
		}
	}
	hc := o.HTTP
	if hc == nil {
		hc = &http.Client{}
	}
	switch kind {
	case "off":
		return nil, nil
	case "anthropic":
		key := getenv("ANTHROPIC_API_KEY")
		if key == "" {
			return nil, errors.New("ai: anthropic needs ANTHROPIC_API_KEY")
		}
		return &Anthropic{BaseURL: cmp.Or(o.BaseURL, anthropicURL), Key: key, Model: cmp.Or(o.Model, defaultAnthropicModel), Effort: "low", HTTP: hc}, nil
	case "openai":
		if o.BaseURL == "" || o.Model == "" {
			return nil, errors.New("ai: an OpenAI-compatible provider needs a base URL and a model")
		}
		return &OpenAI{BaseURL: o.BaseURL, Key: getenv("LIMITPLANE_AI_KEY"), Model: o.Model, HTTP: hc}, nil
	}
	return nil, fmt.Errorf("ai: unknown provider %q (want auto, anthropic, openai or off)", kind)
}

// Anthropic calls the Messages API directly: one POST, no SDK (the root module is stdlib only).
type Anthropic struct {
	BaseURL, Key, Model string
	Effort              string // output_config.effort; empty leaves the model's default
	HTTP                *http.Client
}

func (a *Anthropic) Name() string { return "anthropic/" + a.Model }

func (a *Anthropic) Complete(ctx context.Context, r Request) (Reply, error) {
	type text struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	body := map[string]any{
		"model":      a.Model,
		"max_tokens": r.MaxTokens,
		"system":     []text{{"text", r.System}},
		"messages":   []map[string]any{{"role": "user", "content": []text{{"text", r.User}}}},
	}
	if a.Effort != "" {
		body["output_config"] = map[string]string{"effort": a.Effort}
	}
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			In          int64 `json:"input_tokens"`
			CacheRead   int64 `json:"cache_read_input_tokens"`
			CacheCreate int64 `json:"cache_creation_input_tokens"`
			Out         int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	h := http.Header{"X-Api-Key": {a.Key}, "Anthropic-Version": {anthropicVersion}}
	if err := post(ctx, a.HTTP, strings.TrimSuffix(a.BaseURL, "/")+"/v1/messages", h, body, &out); err != nil {
		return Reply{}, err
	}
	rep := Reply{In: out.Usage.In + out.Usage.CacheRead + out.Usage.CacheCreate, Out: out.Usage.Out}
	// Thinking blocks may come first: read text blocks by type, never by position.
	var b strings.Builder
	for _, c := range out.Content {
		if c.Type == "text" {
			b.WriteString(c.Text)
		}
	}
	rep.Text = strings.TrimSpace(b.String())
	return rep, stopErr(out.StopReason, "refusal", "max_tokens", rep.Text)
}

// OpenAI speaks the chat-completions dialect that Groq, Ollama, vLLM and most local servers share.
type OpenAI struct {
	BaseURL, Key, Model string // BaseURL includes the version, e.g. https://api.groq.com/openai/v1
	HTTP                *http.Client
}

func (o *OpenAI) Name() string { return "openai/" + o.Model }

func (o *OpenAI) Complete(ctx context.Context, r Request) (Reply, error) {
	body := map[string]any{
		"model":      o.Model,
		"max_tokens": r.MaxTokens,
		"messages":   []map[string]string{{"role": "system", "content": r.System}, {"role": "user", "content": r.User}},
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
				Refusal string `json:"refusal"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			In  int64 `json:"prompt_tokens"`
			Out int64 `json:"completion_tokens"`
		} `json:"usage"`
	}
	h := http.Header{}
	if o.Key != "" { // a local Ollama needs none
		h.Set("Authorization", "Bearer "+o.Key)
	}
	if err := post(ctx, o.HTTP, strings.TrimSuffix(o.BaseURL, "/")+"/chat/completions", h, body, &out); err != nil {
		return Reply{}, err
	}
	rep := Reply{In: out.Usage.In, Out: out.Usage.Out}
	if len(out.Choices) == 0 {
		return rep, ErrEmpty
	}
	c := out.Choices[0]
	rep.Text = strings.TrimSpace(c.Message.Content)
	stop := c.FinishReason
	if c.Message.Refusal != "" {
		stop = "refusal"
	}
	return rep, stopErr(stop, "refusal", "length", rep.Text)
}

func stopErr(stop, refusal, cut, text string) error {
	switch {
	case stop == refusal:
		return ErrRefused
	case stop == cut: // a cut answer may end mid-citation
		return ErrCut
	case text == "":
		return ErrEmpty
	}
	return nil
}

// maxBody caps what we read from a provider; a reply here is a few hundred bytes of JSON.
const maxBody = 256 << 10

// post sends JSON and decodes the reply. Errors carry the status and the provider's error type,
// never the request headers, so a key can't end up in a log line.
func post(ctx context.Context, hc *http.Client, url string, h http.Header, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header = h
	req.Header.Set("Content-Type", "application/json")
	res, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("ai: provider unreachable")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("ai: reading reply: %w", err)
	}
	if len(raw) > maxBody {
		return ErrTooLarge
	}
	if res.StatusCode != http.StatusOK {
		var e struct {
			Error struct {
				Type string `json:"type"`
			} `json:"error"`
		}
		json.Unmarshal(raw, &e)
		return fmt.Errorf("ai: provider returned %d %s", res.StatusCode, e.Error.Type)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return errors.New("ai: provider reply is not the expected JSON")
	}
	return nil
}

// guard wraps a provider with a timeout and a cap on calls in flight. Over the cap it fails
// fast with ErrBusy instead of queueing: a queued call would only burn its timeout waiting.
type guard struct {
	p       Provider
	timeout time.Duration
	slots   chan struct{}
	m       *meter
}

func (g *guard) Complete(ctx context.Context, r Request) (Reply, error) {
	select {
	case g.slots <- struct{}{}:
	default:
		return Reply{}, ErrBusy
	}
	defer func() { <-g.slots }()
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	g.m.requests.Add(1)
	rep, err := g.p.Complete(ctx, r)
	g.m.in.Add(rep.In)
	g.m.out.Add(rep.Out)
	if err != nil {
		g.m.errors.Add(1)
	}
	return rep, err
}
