package ai

import (
	"context"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Question struct {
	Query
	// Live is the current state of tenants the question names, already scoped by the caller.
	Live []Explanation
}

type Answer struct {
	Answer    string    `json:"answer"` // rule-based: the matching incidents and live state, cited
	Hits      []Hit     `json:"hits"`
	Facts     []Fact    `json:"facts"`  // live facts, renumbered so they can be cited next to incidents
	Recent    bool      `json:"recent"` // nothing matched, so Hits are the latest incidents instead
	Narrative Narrative `json:"narrative"`
}

const maxQuestion = 500

// Ask answers an ops question from incident memory and live state. Without a model, or when
// the model's answer fails its checks, the answer is the matches themselves, formatted.
func (s *Service) Ask(ctx context.Context, q Question) Answer {
	if len(q.Text) > maxQuestion {
		q.Text = q.Text[:maxQuestion]
		for !utf8.ValidString(q.Text) {
			q.Text = q.Text[:len(q.Text)-1]
		}
	}
	a := Answer{Hits: s.Memory.Search(q.Query)}
	// Vague questions ("anything bad?", "hi") share no words with any incident: show the latest instead.
	if len(a.Hits) == 0 {
		recent := q.Query
		recent.Text = ""
		a.Hits, a.Recent = s.Memory.Search(recent), true
	}
	var b strings.Builder
	f := facts{prefix: "F"}
	for _, e := range q.Live {
		fmt.Fprintf(&b, "Now, %s: %s", e.Subject, e.Summary)
		ids := map[string]string{}
		for _, x := range e.Facts {
			ids[x.ID] = f.add(x.Kind, "%s", x.Text)
		}
		var cites []string
		for _, p := range e.Findings[:min(1, len(e.Findings))] {
			for _, id := range p.Facts {
				cites = append(cites, ids[id])
			}
		}
		if len(cites) > 0 {
			b.WriteString(" [" + strings.Join(cites, ", ") + "]")
		}
		b.WriteString("\n")
	}
	a.Facts = f.list
	switch n := len(a.Hits); {
	case n == 0:
		b.WriteString("No incidents recorded yet.")
	case a.Recent:
		fmt.Fprintf(&b, "Nothing matched those words. The latest %s, newest first:", plural(n, "incident", fmt.Sprint(n, " incidents")))
	default:
		fmt.Fprintf(&b, "%d %s, best match first:", n, plural(n, "incident matches", "incidents match"))
	}
	for _, h := range a.Hits {
		fmt.Fprintf(&b, "\n- %s %s: %s", h.Time.UTC().Format("Jan 2 15:04 UTC"), h.Kind, h.Text)
		if h.Note != "" {
			b.WriteString(" " + h.Note)
		}
		fmt.Fprintf(&b, " [%s]", h.Ref)
	}
	a.Answer = b.String()
	if len(a.Hits) == 0 && len(a.Facts) == 0 {
		return a // nothing to ground an answer on: don't spend a call
	}
	all := make([]Fact, 0, len(a.Hits)+len(a.Facts))
	for _, h := range a.Hits {
		text := h.Time.UTC().Format("2006-01-02 15:04 UTC") + " " + h.Kind + ": " + h.Text
		if h.Note != "" {
			text += " Note: " + h.Note
		}
		all = append(all, Fact{ID: h.Ref, Kind: "incident", Text: text})
	}
	all = append(all, a.Facts...)
	a.Narrative = s.narrate(ctx, "You answer an operator's questions about their rate limiter from its incident history (M ids) and live state (F ids).",
		"Question: "+q.Text+"\n\nAnswer in at most four sentences. If nothing listed answers it, say that.", all)
	return a
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Mentions returns the names that appear in q as whole words, case-insensitively.
func Mentions(q string, names []string) []string {
	q = strings.ToLower(q)
	var out []string
	for _, n := range names {
		ln := strings.ToLower(n)
		for i := 0; ln != ""; {
			j := strings.Index(q[i:], ln)
			if j < 0 {
				break
			}
			j += i
			before, _ := utf8.DecodeLastRuneInString(q[:j])
			after, _ := utf8.DecodeRuneInString(q[j+len(ln):])
			if !word(before) && !word(after) {
				out = append(out, n)
				break
			}
			i = j + 1
		}
	}
	return out
}

func word(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' }
