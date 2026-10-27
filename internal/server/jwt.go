package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var b64 = base64.RawURLEncoding

// Fixed header: we only ever issue HS256, so verify compares against these exact bytes.
var jwtHeader = b64.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

type claims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

var errToken = errors.New("invalid token")

func signJWT(secret []byte, sub string, now time.Time, ttl time.Duration) string {
	c, _ := json.Marshal(claims{Sub: sub, Iat: now.Unix(), Exp: now.Add(ttl).Unix()})
	msg := jwtHeader + "." + b64.EncodeToString(c)
	return msg + "." + b64.EncodeToString(mac(secret, msg))
}

func verifyJWT(secret []byte, tok string, now time.Time) (claims, error) {
	h, rest, ok := strings.Cut(tok, ".")
	p, s, ok2 := strings.Cut(rest, ".")
	if !ok || !ok2 {
		return claims{}, errToken
	}
	// Check alg before trusting anything: rejects "none" and alg-confusion tokens.
	var hdr struct{ Alg, Typ string }
	if hb, err := b64.DecodeString(h); err != nil || json.Unmarshal(hb, &hdr) != nil || hdr.Alg != "HS256" {
		return claims{}, errToken
	}
	sig, err := b64.DecodeString(s)
	if err != nil || !hmac.Equal(sig, mac(secret, h+"."+p)) {
		return claims{}, errToken
	}
	var c claims
	pb, err := b64.DecodeString(p)
	if err != nil || json.Unmarshal(pb, &c) != nil {
		return claims{}, errToken
	}
	if now.Unix() >= c.Exp {
		return claims{}, errors.New("token expired")
	}
	return c, nil
}

func mac(secret []byte, msg string) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(msg))
	return m.Sum(nil)
}
