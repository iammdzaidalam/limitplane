package org

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

// Iterations is PBKDF2-HMAC-SHA256's work factor: OWASP's 2023 figure, about 0.1-0.2s per check
// here. It is stored with each hash, so raising it never breaks existing passwords.
const Iterations = 600_000

const (
	minPassword = 10
	maxPassword = 256 // bounds the hashing work one request can ask for
)

var b64 = base64.RawStdEncoding

// hashPassword encodes pbkdf2-sha256$<iterations>$<salt>$<key>, with a fresh 16-byte salt.
func hashPassword(pw string, iter int) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	k, _ := pbkdf2.Key(sha256.New, pw, salt, iter, 32)
	return "pbkdf2-sha256$" + strconv.Itoa(iter) + "$" + b64.EncodeToString(salt) + "$" + b64.EncodeToString(k)
}

// dummy is checked against when the user doesn't exist, so a wrong email costs as long as a
// wrong password and the timing doesn't say which emails have accounts.
var dummy = hashPassword("not a password", Iterations)

// checkPassword reports whether pw matches the encoded hash, comparing in constant time.
func checkPassword(encoded, pw string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" || len(pw) > maxPassword {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	salt, err2 := b64.DecodeString(parts[2])
	want, err3 := b64.DecodeString(parts[3])
	if err != nil || err2 != nil || err3 != nil || iter < 1 || iter > 10*Iterations || len(want) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

func validPassword(pw string) error {
	if n := len(pw); n < minPassword || n > maxPassword {
		return errors.New("a password needs " + strconv.Itoa(minPassword) + " to " + strconv.Itoa(maxPassword) + " characters")
	}
	return nil
}

// NewPassword is a random password for an invite that didn't set one: 16 bytes, base64.
func NewPassword() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
