package ai

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Fact is one statement taken from gateway state. The model may only say what facts say,
// and must cite them by ID.
type Fact struct {
	ID   string `json:"id"`
	Kind string `json:"kind"` // decision, policy, route, usage, ban, client, timing, tenant, backend, budget
	Text string `json:"text"`
}

// Point is a finding or an action, with the facts it rests on.
type Point struct {
	Text  string   `json:"text"`
	Facts []string `json:"facts,omitempty"`
}

type facts struct {
	list   []Fact
	prefix string
}

// add records a fact and returns its ID.
func (f *facts) add(kind, format string, a ...any) string {
	id := fmt.Sprintf("%s%d", f.prefix, len(f.list)+1)
	f.list = append(f.list, Fact{ID: id, Kind: kind, Text: fmt.Sprintf(format, a...)})
	return id
}

// redactor swaps IPs and CIDRs for keyed hashes before text leaves for a model, and swaps them
// back in the answer. The key is random per process, so a hash can't be reversed by hashing
// all 2^32 IPv4 addresses, yet one client keeps one name within a prompt.
type redactor struct {
	key  []byte
	back map[string]string // token -> original
}

var processKey = func() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}()

func newRedactor() *redactor { return &redactor{key: processKey, back: map[string]string{}} }

// ipLike finds candidates; netip decides. IPv6 needs two colons so times like 14:02 don't match.
var ipLike = regexp.MustCompile(`[0-9A-Fa-f]*:[0-9A-Fa-f]*:[0-9A-Fa-f:.]*(?:/\d{1,3})?|\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?`)

func (r *redactor) redact(s string) string {
	return ipLike.ReplaceAllStringFunc(s, func(m string) string {
		if _, err := netip.ParsePrefix(m); err != nil {
			if _, err := netip.ParseAddr(m); err != nil {
				return m
			}
		}
		mac := hmac.New(sha256.New, r.key)
		mac.Write([]byte(m))
		tok := "ip-" + hex.EncodeToString(mac.Sum(nil)[:4])
		r.back[tok] = m
		return tok
	})
}

var ipToken = regexp.MustCompile(`ip-[0-9a-f]{8}`)

func (r *redactor) restore(s string) string {
	return ipToken.ReplaceAllStringFunc(s, func(t string) string {
		if ip, ok := r.back[t]; ok {
			return ip
		}
		return t
	})
}

// shown is how a fact list goes to a model: one "ID: text" per line.
func shown(fs []Fact, r *redactor) string {
	var b strings.Builder
	for _, f := range fs {
		t := f.Text
		if r != nil {
			t = r.redact(t)
		}
		fmt.Fprintf(&b, "%s: %s\n", f.ID, t)
	}
	return b.String()
}
