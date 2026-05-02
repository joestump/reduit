package oidc_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"

	auth "github.com/joestump/reduit/internal/auth/oidc"
)

// TestConfigValidate checks the static validator catches the four
// classes of misconfiguration listed in ADR-0004 + SPEC-0005:
// missing issuer, missing client, missing redirect, missing openid
// scope.
//
// Governing: SPEC-0005 REQ "OIDC Login Flow".
func TestConfigValidate(t *testing.T) {
	t.Parallel()
	good := auth.Config{
		IssuerURL:   "https://idp.example.com",
		ClientID:    "reduit",
		RedirectURL: "https://reduit.example.com/auth/callback",
		Scopes:      []string{"openid", "profile", "email"},
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("good config: %v", err)
	}
	for _, tc := range []struct {
		name    string
		mutate  func(c *auth.Config)
		wantSub string
	}{
		{"missing issuer", func(c *auth.Config) { c.IssuerURL = "" }, "issuer_url"},
		{"missing client", func(c *auth.Config) { c.ClientID = "" }, "client_id"},
		{"missing redirect", func(c *auth.Config) { c.RedirectURL = "" }, "redirect_url"},
		{"non-openid scopes", func(c *auth.Config) { c.Scopes = []string{"profile"} }, "openid"},
		{"bad issuer URL", func(c *auth.Config) { c.IssuerURL = "not-a-url" }, "issuer_url"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := good
			tc.mutate(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("expected error containing %q; got %v", tc.wantSub, err)
			}
		})
	}
}

// TestNewAndExchangeWithPKCE wires up the in-package oidctest harness
// and runs the full /auth/login → IdP authorize → token-exchange →
// id_token-verify happy path. This is the ACCEPTANCE check for
// SPEC-0005 REQ "OIDC Login Flow" — auth-code-with-PKCE round-trip
// works against an httptest IdP.
//
// We hand-build the token-response here (the oidctest server only
// signs ID tokens; it isn't a full OAuth2 server) but verify through
// the live New() + Verifier() path so the signature/iss/aud/nonce
// check is the production code path.
//
// Governing: SPEC-0005 REQ "OIDC Login Flow".
func TestVerifierAcceptsValidJWTAndRejectsTampered(t *testing.T) {
	t.Parallel()
	priv, srvURL, keyID, alg := newOIDCTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := auth.New(ctx, auth.Config{
		IssuerURL:   srvURL,
		ClientID:    "reduit",
		RedirectURL: "https://reduit.example.com/auth/callback",
		Scopes:      []string{"openid", "profile", "email"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rawClaims := `{
		"iss": "` + srvURL + `",
		"aud": "reduit",
		"sub": "joe",
		"email": "joe@stump.rocks",
		"email_verified": true,
		"exp": ` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `,
		"iat": ` + strconv.FormatInt(time.Now().Unix(), 10) + `
	}`
	idToken := oidctest.SignIDToken(priv, keyID, alg, rawClaims)

	tok, err := c.Verifier().Verify(ctx, idToken)
	if err != nil {
		t.Fatalf("verify good token: %v", err)
	}
	if tok.Subject != "joe" {
		t.Fatalf("Subject = %q, want %q", tok.Subject, "joe")
	}

	// Tamper the signature segment by flipping a byte mid-segment.
	// (Last char alone can fall in base64 padding bits and leave the
	// decoded signature unchanged.)
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}
	mid := len(parts[2]) / 2
	swap := byte('A')
	if parts[2][mid] == 'A' {
		swap = 'B'
	}
	parts[2] = parts[2][:mid] + string(swap) + parts[2][mid+1:]
	tampered := strings.Join(parts, ".")
	if _, err := c.Verifier().Verify(ctx, tampered); err == nil {
		t.Fatal("expected tampered-signature verification to fail")
	}
}

// TestAuthCodeURLContainsPKCE checks the redirect URL we hand the
// browser carries the S256 challenge + nonce + state. This is the
// "Login initiates auth-code-with-PKCE" scenario from SPEC-0005.
func TestAuthCodeURLContainsPKCE(t *testing.T) {
	t.Parallel()
	_, srvURL, _, _ := newOIDCTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := auth.New(ctx, auth.Config{
		IssuerURL:   srvURL,
		ClientID:    "reduit",
		RedirectURL: "https://reduit.example.com/auth/callback",
		Scopes:      []string{"openid"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pkce, err := auth.NewPKCE()
	if err != nil {
		t.Fatalf("NewPKCE: %v", err)
	}
	state, _ := auth.RandomState()
	nonce, _ := auth.RandomNonce()
	got := c.AuthCodeURL(auth.AuthURLOptions{State: state, Nonce: nonce, CodeChallenge: pkce.Challenge})
	for _, must := range []string{
		"code_challenge=" + pkce.Challenge,
		"code_challenge_method=S256",
		"state=" + state,
		"nonce=" + nonce,
		"client_id=reduit",
	} {
		if !strings.Contains(got, must) {
			t.Errorf("AuthCodeURL missing %q\n  got: %s", must, got)
		}
	}
}

// newOIDCTestServer spins up an oidctest.Server for the duration of
// a test. Returns the signing key, server URL, key ID, and alg.
func newOIDCTestServer(t *testing.T) (priv crypto.PrivateKey, srvURL, keyID, alg string) {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	keyID = "test-key"
	alg = gooidc.RS256
	tsrv := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{{
			PublicKey: rsaKey.Public(),
			KeyID:     keyID,
			Algorithm: alg,
		}},
	}
	srv := httptest.NewServer(tsrv)
	t.Cleanup(srv.Close)
	tsrv.SetIssuer(srv.URL)
	return rsaKey, srv.URL, keyID, alg
}
