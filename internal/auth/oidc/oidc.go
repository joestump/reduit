// Package oidc wraps github.com/coreos/go-oidc/v3 + golang.org/x/oauth2
// into a Reduit-flavored Relying Party client. The handler-level login
// and callback flow lives in the http server (issue #23); this package
// owns:
//
//   - OIDC discovery + provider construction at startup
//   - Building the auth-code-with-PKCE redirect URL
//   - Exchanging an auth code (with code_verifier) for tokens
//   - Validating the resulting ID token (signature, iss, aud, nonce)
//
// Configuration validation is strict: missing issuer/client/redirect
// errors at startup, so an operator never sees a runtime nil-deref
// when an OIDC env var is forgotten.
//
// Governing: ADR-0004 (OIDC control-plane auth), SPEC-0005 REQ "OIDC
// Login Flow", SPEC-0006 REQ "Bearer Authentication Required" (the
// JWT verifier exposed here is reused by the bearer-token validator).
package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config configures the Relying Party.
//
// The fields mirror config.OIDCConfig 1:1 — the wiring layer (cli/serve)
// is the only place that should depend on both packages, so this type
// can stay narrow and dependency-free.
type Config struct {
	// IssuerURL is the OIDC discovery base URL (without
	// /.well-known/openid-configuration).
	IssuerURL string
	// ClientID is the client_id assigned by the IdP.
	ClientID string
	// ClientSecret is the client_secret. Optional for public clients
	// using PKCE alone, required for confidential clients (Pocket ID's
	// default).
	ClientSecret string
	// RedirectURL is the absolute https://host/auth/callback URL the
	// IdP will redirect to. MUST match what's registered on the IdP.
	RedirectURL string
	// Scopes are the OAuth2 scopes requested. Reduit always asks for
	// "openid"; "profile" and "email" are added by the default config.
	Scopes []string
}

// Validate checks the configuration before the network call. Failures
// are joined with errors.Join so an operator with multiple missing
// values gets the full list, not just the first.
func (c Config) Validate() error {
	var errs []error
	if c.IssuerURL == "" {
		errs = append(errs, errors.New("oidc: issuer_url is required"))
	} else if u, err := url.Parse(c.IssuerURL); err != nil || u.Scheme == "" || u.Host == "" {
		errs = append(errs, fmt.Errorf("oidc: issuer_url %q is not a valid absolute URL", c.IssuerURL))
	}
	if c.ClientID == "" {
		errs = append(errs, errors.New("oidc: client_id is required"))
	}
	if c.RedirectURL == "" {
		errs = append(errs, errors.New("oidc: redirect_url is required"))
	} else if u, err := url.Parse(c.RedirectURL); err != nil || u.Scheme == "" || u.Host == "" {
		errs = append(errs, fmt.Errorf("oidc: redirect_url %q is not a valid absolute URL", c.RedirectURL))
	}
	if !containsScope(c.Scopes, gooidc.ScopeOpenID) {
		errs = append(errs, fmt.Errorf("oidc: scopes must include %q", gooidc.ScopeOpenID))
	}
	return errors.Join(errs...)
}

func containsScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

// Client is the assembled Relying Party. Construct exactly one per
// process at startup; it is safe for concurrent use.
type Client struct {
	cfg      Config
	provider *gooidc.Provider
	verifier *gooidc.IDTokenVerifier
	oauth2   *oauth2.Config
}

// New performs OIDC discovery against cfg.IssuerURL and returns a
// configured Client. Failures here are fatal: the operator MUST fix
// the IdP / network / config before Reduit can serve OIDC.
//
// Governing: ADR-0004 (OIDC discovery at startup), SPEC-0005 REQ
// "OIDC Login Flow".
func New(ctx context.Context, cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	provider, err := gooidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery failed for %q: %w", cfg.IssuerURL, err)
	}
	verifier := provider.Verifier(&gooidc.Config{ClientID: cfg.ClientID})
	oa := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
	}
	return &Client{cfg: cfg, provider: provider, verifier: verifier, oauth2: oa}, nil
}

// Provider returns the underlying go-oidc Provider. Callers needing
// the JWKS or other discovery metadata can reach it through here;
// most callers should stick to the higher-level methods on Client.
func (c *Client) Provider() *gooidc.Provider { return c.provider }

// Verifier returns the configured IDTokenVerifier. Bearer-token
// validation (SPEC-0006) reuses this for OIDC-JWT bearers.
func (c *Client) Verifier() *gooidc.IDTokenVerifier { return c.verifier }

// AuthURLOptions controls the values baked into AuthCodeURL.
type AuthURLOptions struct {
	// State is the opaque CSRF / pre-session correlation value. Caller
	// MUST persist it server-side and check it on callback.
	State string
	// Nonce is bound into the resulting ID token's `nonce` claim.
	// Caller MUST persist it and verify on callback.
	Nonce string
	// CodeChallenge is the base64url(sha256(code_verifier)).
	CodeChallenge string
}

// AuthCodeURL builds the IdP authorize URL with PKCE. The caller is
// responsible for generating + persisting state, nonce, and the PKCE
// verifier in a pre-session record (see internal/auth/oidc.PreSession);
// this method only assembles the URL. The S256 method is hard-coded —
// "plain" PKCE is not acceptable.
//
// Governing: SPEC-0005 REQ "OIDC Login Flow" (auth-code-with-PKCE).
func (c *Client) AuthCodeURL(opts AuthURLOptions) string {
	return c.oauth2.AuthCodeURL(opts.State,
		gooidc.Nonce(opts.Nonce),
		oauth2.SetAuthURLParam("code_challenge", opts.CodeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange swaps an authorization code for an OAuth2 token bundle,
// then extracts and validates the embedded ID token's signature, iss,
// aud, expiry, and nonce. The returned ExchangeResult exposes only the
// fields callers should ever need — the raw access/refresh tokens stay
// on this side of the boundary unless explicitly asked for.
//
// Governing: SPEC-0005 REQ "OIDC Login Flow" (callback validation).
func (c *Client) Exchange(ctx context.Context, code, codeVerifier, expectedNonce string) (*ExchangeResult, error) {
	if code == "" {
		return nil, errors.New("oidc: empty authorization code")
	}
	if codeVerifier == "" {
		return nil, errors.New("oidc: empty pkce code_verifier")
	}
	tok, err := c.oauth2.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return nil, fmt.Errorf("oidc: token exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return nil, errors.New("oidc: token response missing id_token")
	}
	idToken, err := c.verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("oidc: id_token verify: %w", err)
	}
	if expectedNonce != "" && idToken.Nonce != expectedNonce {
		return nil, errors.New("oidc: id_token nonce mismatch")
	}
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
		Name     string `json:"name"`
	}
	// Best-effort claim extraction — failures on extra claims must not
	// fail the login; the contract is that `sub` always works.
	_ = idToken.Claims(&claims)
	return &ExchangeResult{
		Subject:       idToken.Subject,
		Email:         claims.Email,
		EmailVerified: claims.Verified,
		Name:          claims.Name,
		IDToken:       idToken,
		AccessToken:   tok.AccessToken,
		RefreshToken:  tok.RefreshToken,
		Expiry:        tok.Expiry,
		RawIDToken:    rawID,
	}, nil
}

// ExchangeResult is the validated outcome of the callback exchange.
// Callers (the future #23 callback handler) consume Subject + Email
// to find/create the account row; AccessToken / RefreshToken are kept
// available for downstream IdP-side calls (logout, userinfo) but
// MUST NOT be confused with the Proton refresh token.
type ExchangeResult struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	IDToken       *gooidc.IDToken
	AccessToken   string
	RefreshToken  string
	Expiry        time.Time
	// RawIDToken is the on-the-wire JWT. Stored only if the caller
	// explicitly opts in — by default, we don't persist it.
	RawIDToken string
}

// EndSessionEndpoint returns the IdP's RP-Initiated Logout endpoint
// if it advertises one in discovery, or "" otherwise. The login flow
// (in #23) wires this into POST /auth/logout per ADR-0004.
func (c *Client) EndSessionEndpoint() string {
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := c.provider.Claims(&meta); err != nil {
		return ""
	}
	return meta.EndSession
}
