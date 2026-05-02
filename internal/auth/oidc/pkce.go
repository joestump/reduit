package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// pkceVerifierBytes is the entropy length for the code_verifier. RFC
// 7636 mandates 43-128 base64url chars; 64 random bytes encode to 86
// chars, comfortably inside the range and well above the 256-bit
// security floor.
const pkceVerifierBytes = 64

// PKCE bundles a fresh PKCE code_verifier and its S256 challenge.
// Stored together in the pre-session record between /auth/login and
// /auth/callback; the verifier is sent on the token-exchange call,
// the challenge is sent on the authorize redirect.
//
// Governing: SPEC-0005 REQ "OIDC Login Flow" (auth-code-with-PKCE).
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE generates a cryptographically random code_verifier and
// derives the S256 code_challenge. "plain" PKCE is intentionally not
// supported — every IdP Reduit aims at (Pocket ID, Authelia, Keycloak)
// supports S256, and "plain" exposes the verifier on the wire.
func NewPKCE() (PKCE, error) {
	buf := make([]byte, pkceVerifierBytes)
	if _, err := rand.Read(buf); err != nil {
		return PKCE{}, fmt.Errorf("pkce: read random: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	return PKCE{Verifier: verifier, Challenge: challenge}, nil
}

// RandomState returns a fresh url-safe state value. Used both for
// CSRF protection on the authorize redirect and as the pre-session
// lookup key in the in-memory PreSessionStore.
func RandomState() (string, error) {
	return randomURLToken(32)
}

// RandomNonce returns a fresh url-safe nonce, bound into the ID
// token via the `nonce` claim and verified on callback.
func RandomNonce() (string, error) {
	return randomURLToken(32)
}

func randomURLToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("oidc: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
