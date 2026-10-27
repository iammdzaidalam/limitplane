package server

import (
	"strings"
	"testing"
	"time"
)

func TestJWT(t *testing.T) {
	sec, now := []byte("s3cret"), time.Now()
	tok := signJWT(sec, "admin", now, time.Hour)
	if c, err := verifyJWT(sec, tok, now); err != nil || c.Sub != "admin" {
		t.Fatalf("valid token rejected: %v %+v", err, c)
	}
	h, rest, _ := strings.Cut(tok, ".")
	p, _, _ := strings.Cut(rest, ".")
	none := b64.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	bad := map[string]string{
		"expired":      tok,
		"wrong secret": signJWT([]byte("other"), "admin", now, time.Hour),
		"alg none":     none + "." + p + ".",
		"tampered":     h + "." + b64.EncodeToString([]byte(`{"sub":"admin","exp":9999999999}`)) + "." + strings.Split(tok, ".")[2],
		"garbage":      "a.b",
		"empty":        "",
	}
	for name, tk := range bad {
		at := now
		if name == "expired" {
			at = now.Add(2 * time.Hour)
		}
		if _, err := verifyJWT(sec, tk, at); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
