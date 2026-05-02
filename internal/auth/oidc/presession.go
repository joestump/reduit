package oidc

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// DefaultPreSessionTTL bounds how long a partially-completed login
// can sit between /auth/login and /auth/callback. Per the issue body,
// 10 minutes is the upper bound — enough for a real human round-trip
// (open IdP, type password, complete MFA), short enough that an
// abandoned authorize URL becomes useless quickly.
//
// Governing: issue #13 ("PKCE pre-session storage, short-lived, 10
// minute TTL"); SPEC-0005 REQ "OIDC Login Flow".
const DefaultPreSessionTTL = 10 * time.Minute

// BindCookieName is the canonical browser-binding cookie set by
// /auth/login and verified at /auth/callback. The `__Host-` prefix
// pins the cookie to a single origin (no Domain attr, Path=/, Secure)
// — see RFC 6265bis §4.1.3.2 — so a network attacker who controls a
// sibling subdomain cannot inject the cookie into a victim's browser
// to forge a binding.
const BindCookieName = "__Host-Reduit-Bind"

// bindTokenEntropyBytes is the size of the cryptographic browser-bind
// token. 32 bytes (256 bits) from crypto/rand, base64-url encoded
// without padding for use in a cookie value.
const bindTokenEntropyBytes = 32

// PreSession is the server-side correlation record between the
// /auth/login redirect and the /auth/callback exchange. It carries
// just enough to validate the callback and recover the post-login
// landing target.
//
// BindToken defends against the OIDC login-CSRF / authorization-code
// injection attack described in RFC 9700 §4.5: state alone is not
// enough to prove the callback's browser is the same browser that
// initiated /auth/login, because state travels through the IdP and
// back as a query parameter and an attacker who initiates a flow
// observes their own state value. The bind token never leaves the
// browser-server channel — it lives in a `__Host-`-prefixed cookie
// set at /auth/login and read at /auth/callback — so the callback
// handler can prove the browser delivering the auth code is the same
// browser that started the flow.
//
// Governing: SPEC-0005 REQ "OIDC Login Flow" (Scenario "Callback
// validates state, nonce, and code"); RFC 9700 §4.5.
type PreSession struct {
	State        string
	Nonce        string
	CodeVerifier string
	ReturnTo     string
	BindToken    string // 32-byte base64url; required to Take this PreSession
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// PreSessionStore is the in-memory, TTL-bounded store of pending
// auth-code transactions. Production-scale Reduit (one host, one
// process, low login QPS) does not need a persistent store for these:
// they are 10-minute-lived and a process restart simply forces the
// user to re-click "Login". A persistent store would add complexity
// (encryption-at-rest, sweep) for negligible gain.
//
// Concurrent use is safe.
type PreSessionStore struct {
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	entries map[string]PreSession
}

// NewPreSessionStore returns a fresh in-memory store. Pass ttl=0 to
// use DefaultPreSessionTTL.
func NewPreSessionStore(ttl time.Duration) *PreSessionStore {
	if ttl <= 0 {
		ttl = DefaultPreSessionTTL
	}
	return &PreSessionStore{
		ttl:     ttl,
		now:     time.Now,
		entries: make(map[string]PreSession),
	}
}

// ErrPreSessionNotFound is returned when state is unknown, expired,
// or the bind token does not match the stored value. The same error
// is returned for all three failure modes so the caller cannot use
// /auth/callback as an oracle to distinguish "state not in store"
// from "state in store but bind token wrong".
var ErrPreSessionNotFound = errors.New("oidc: pre-session not found, expired, or bind mismatch")

// NewBindToken returns a freshly generated, base64-url-encoded
// browser-binding token. Issue #23's /auth/login handler MUST call
// this once per pre-session, store it on the PreSession before Put,
// AND set it on the response as the BindCookie returned by
// BuildBindCookie below. The same value is then read back from the
// request at /auth/callback and supplied to Take.
func NewBindToken() (string, error) {
	buf := make([]byte, bindTokenEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("oidc: read bind-token random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// BuildBindCookie returns the response-side cookie that /auth/login
// MUST set alongside the redirect to the IdP authorize URL. The
// cookie carries the BindToken back to the browser; /auth/callback
// reads it via ReadBindCookie and supplies it to Take.
//
// Attributes:
//   - Name: BindCookieName ("__Host-Reduit-Bind"). The `__Host-`
//     prefix is browser-enforced: the cookie is rejected if it lacks
//     Secure, lacks Path=/, or carries a Domain attribute, so a
//     sibling-subdomain attacker cannot forge it on the victim's
//     browser.
//   - Path "/": required by the `__Host-` prefix.
//   - Secure: true. Required by the `__Host-` prefix; production
//     callers MUST serve over HTTPS. Set insecure=true ONLY for
//     httptest.NewServer (plain HTTP).
//   - HttpOnly: true. The token is server-state, not page-state — JS
//     has no business reading it.
//   - SameSite=Lax. The cookie MUST survive the IdP's cross-site
//     302→/auth/callback navigation; Strict drops the cookie and
//     breaks the flow.
//   - MaxAge: tied to DefaultPreSessionTTL. The cookie expires when
//     the underlying PreSession does, so a stale browser tab cannot
//     re-use a long-since-evicted bind token.
//
// Governing: SPEC-0005 REQ "OIDC Login Flow"; RFC 9700 §4.5;
// RFC 6265bis §4.1.3.2 (`__Host-` prefix semantics).
func BuildBindCookie(token string, insecure bool) *http.Cookie {
	return &http.Cookie{
		Name:     BindCookieName,
		Value:    token,
		Path:     "/",
		Secure:   !insecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(DefaultPreSessionTTL / time.Second),
	}
}

// ClearBindCookie returns a zeroed cookie suitable for instructing
// the browser to drop the bind cookie. /auth/callback SHOULD set this
// once Take has succeeded so the spent bind token is not lying around
// in the browser jar.
func ClearBindCookie(insecure bool) *http.Cookie {
	return &http.Cookie{
		Name:     BindCookieName,
		Value:    "",
		Path:     "/",
		Secure:   !insecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

// ReadBindCookie extracts the bind-token value from r. Returns "" if
// the cookie is absent. /auth/callback supplies the result to Take.
func ReadBindCookie(r *http.Request) string {
	if r == nil {
		return ""
	}
	c, err := r.Cookie(BindCookieName)
	if err != nil || c == nil {
		return ""
	}
	return c.Value
}

// Put records a pre-session keyed by state. CreatedAt and ExpiresAt
// are set automatically; callers should fill State / Nonce /
// CodeVerifier / ReturnTo / BindToken and leave the timestamps zero.
//
// BindToken MUST be a freshly generated value (via NewBindToken). An
// empty BindToken is accepted at storage time but Take will fail on
// the resulting record, so callers cannot accidentally short-circuit
// the binding by passing "".
func (s *PreSessionStore) Put(p PreSession) {
	now := s.now()
	p.CreatedAt = now
	p.ExpiresAt = now.Add(s.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[p.State] = p
}

// Take atomically loads-and-deletes a pre-session whose State matches
// state AND whose stored BindToken matches bindToken. The pre-session
// is single-use: a successful callback consumes it; a re-replayed
// callback (e.g. the user double-clicks) returns ErrPreSessionNotFound
// the second time. Expired entries also return ErrPreSessionNotFound
// and are removed in passing.
//
// Bind-token comparison is constant-time so an attacker cannot
// distinguish "state present, bind wrong" from "state absent" by
// timing the response. An empty bindToken always fails (a stored
// PreSession with an empty BindToken — should one ever land — is
// also rejected).
//
// Governing: SPEC-0005 REQ "OIDC Login Flow"; RFC 9700 §4.5.
func (s *PreSessionStore) Take(state, bindToken string) (PreSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.entries[state]
	if !ok {
		// Still run a constant-time compare on a dummy of equal length
		// so a missing-state lookup takes roughly the same time as a
		// present-but-mismatched one. Length-mismatch is treated as a
		// failure regardless.
		_ = subtle.ConstantTimeCompare([]byte(bindToken), []byte(bindToken))
		return PreSession{}, ErrPreSessionNotFound
	}
	// State match found — DELETE first, validate after, so a
	// mismatched bind token still consumes the entry and prevents an
	// attacker from probing the same state slot repeatedly with
	// different bind tokens.
	delete(s.entries, state)
	if s.now().After(p.ExpiresAt) {
		return PreSession{}, ErrPreSessionNotFound
	}
	if !constantTimeStringEq(p.BindToken, bindToken) {
		return PreSession{}, ErrPreSessionNotFound
	}
	if p.BindToken == "" {
		// Defence in depth: a PreSession that was put with an empty
		// BindToken is unusable. Should never happen in production
		// because /auth/login MUST call NewBindToken first, but the
		// store refuses to be the layer that lets a misuse slip through.
		return PreSession{}, ErrPreSessionNotFound
	}
	return p, nil
}

// constantTimeStringEq reports whether a == b in time independent of
// the input contents. Length-mismatch returns false fast, but only
// after a same-length compare so the timing leak is bounded by the
// length of the supplied (attacker-controlled) value.
func constantTimeStringEq(a, b string) bool {
	if len(a) != len(b) {
		// Run a same-length compare to flatten the timing of the
		// trivially-different-length case.
		_ = subtle.ConstantTimeCompare([]byte(b), []byte(b))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// SweepExpired removes every entry whose ExpiresAt has passed and
// returns the number of entries deleted. Callers MAY run this on a
// timer; functionally Take() also drops expired entries on access,
// so the sweep is just memory hygiene.
func (s *PreSessionStore) SweepExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for k, p := range s.entries {
		if now.After(p.ExpiresAt) {
			delete(s.entries, k)
			n++
		}
	}
	return n
}

// Len reports the current number of stored pre-sessions. Test-only
// helper; production callers don't need it.
func (s *PreSessionStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}
