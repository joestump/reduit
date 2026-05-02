package oidc_test

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	auth "github.com/joestump/reduit/internal/auth/oidc"
)

// TestPKCEDerivation checks the verifier hashes to the challenge using
// the S256 method. This is the property RFC 7636 §4.6 requires the
// verifier to satisfy server-side; if it ever drifts, every login
// fails.
func TestPKCEDerivation(t *testing.T) {
	t.Parallel()
	for i := 0; i < 16; i++ {
		p, err := auth.NewPKCE()
		if err != nil {
			t.Fatalf("NewPKCE: %v", err)
		}
		sum := sha256.Sum256([]byte(p.Verifier))
		want := base64.RawURLEncoding.EncodeToString(sum[:])
		if p.Challenge != want {
			t.Fatalf("challenge != sha256(verifier)\n  got:  %s\n  want: %s", p.Challenge, want)
		}
		if len(p.Verifier) < 43 || len(p.Verifier) > 128 {
			t.Fatalf("verifier length %d outside RFC 7636 [43,128]", len(p.Verifier))
		}
		if strings.ContainsAny(p.Verifier, "+/=") {
			t.Fatalf("verifier %q has non-url-safe base64 chars", p.Verifier)
		}
	}
}

func TestPKCEUniqueness(t *testing.T) {
	t.Parallel()
	const n = 64
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		p, err := auth.NewPKCE()
		if err != nil {
			t.Fatalf("NewPKCE: %v", err)
		}
		if _, dup := seen[p.Verifier]; dup {
			t.Fatalf("duplicate verifier on iter %d", i)
		}
		seen[p.Verifier] = struct{}{}
	}
}
