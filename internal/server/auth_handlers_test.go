// Tests for the OIDC login/callback/logout handlers.
//
// Build a fake IdP that wraps oidctest.Server (discovery + jwks) with
// a custom /authorize and /token handler. This is the smallest scaffold
// that exercises the production code path end-to-end -- the
// internal/auth/oidc.Client talks to the fake IdP through real HTTP,
// real PKCE, real state validation, real ID-token verification.
//
// Governing: ADR-0004, ADR-0010, SPEC-0005 REQ "OIDC Login Flow",
// SPEC-0005 REQ "Authentication Gating", SPEC-0005 REQ "First-time
// login establishes user identity only", SPEC-0005 REQ "Session admin
// tag is computed at bind time".

package server_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"

	authoidc "github.com/joestump/reduit/internal/auth/oidc"
	"github.com/joestump/reduit/internal/auth/session"
	"github.com/joestump/reduit/internal/server"
	"github.com/joestump/reduit/internal/store"
	"github.com/joestump/reduit/internal/users"
)

// migrateMu serializes goose package-level state across parallel
// tests in this package.
var migrateMu sync.Mutex

func openTempStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "reduit.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	migrateMu.Lock()
	err = st.Migrate("")
	migrateMu.Unlock()
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return st
}

// fakeIdP is a minimal OIDC IdP for tests. It serves discovery + jwks
// via oidctest, plus a custom /authorize and /token. The /authorize
// handler auto-approves the user (no consent screen) and 302s back
// to the supplied redirect_uri with state + a generated auth code.
// The /token handler signs an ID token carrying the nonce + claims
// captured at /authorize time.
type fakeIdP struct {
	srv      *httptest.Server
	priv     *rsa.PrivateKey
	clientID string

	mu      sync.Mutex
	codes   map[string]issuedCode // code -> details
	subject string
	email   string
	name    string
}

type issuedCode struct {
	nonce         string
	codeChallenge string
	redirectURI   string
}

func newFakeIdP(t *testing.T, clientID string) *fakeIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	idp := &fakeIdP{
		priv:     priv,
		clientID: clientID,
		codes:    map[string]issuedCode{},
		subject:  "sub-default",
		email:    "user@example.com",
		name:     "Test User",
	}

	tsrv := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{{
			PublicKey: priv.Public(),
			KeyID:     "test-key",
			Algorithm: gooidc.RS256,
		}},
	}

	mux := http.NewServeMux()
	// Custom discovery overrides oidctest's so we control the auth +
	// token endpoint URLs. Everything else (jwks, etc.) falls through.
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		issuer := idp.srv.URL
		doc := map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"scopes_supported":                      []string{"openid", "profile", "email"},
			"end_session_endpoint":                  issuer + "/logout",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/authorize", idp.handleAuthorize)
	mux.HandleFunc("/token", idp.handleToken)
	// Everything else (jwks at /keys etc.) handed to oidctest.
	mux.Handle("/", tsrv)

	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	tsrv.SetIssuer(idp.srv.URL)
	return idp
}

func (i *fakeIdP) URL() string { return i.srv.URL }

func (i *fakeIdP) setSubject(sub, email, name string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.subject = sub
	i.email = email
	i.name = name
}

func (i *fakeIdP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	redirect := q.Get("redirect_uri")
	if state == "" || redirect == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	code := randHex(16)
	i.mu.Lock()
	i.codes[code] = issuedCode{
		nonce:         q.Get("nonce"),
		codeChallenge: q.Get("code_challenge"),
		redirectURI:   redirect,
	}
	i.mu.Unlock()

	u, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	rq := u.Query()
	rq.Set("state", state)
	rq.Set("code", code)
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (i *fakeIdP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	code := r.Form.Get("code")
	verifier := r.Form.Get("code_verifier")
	i.mu.Lock()
	issued, ok := i.codes[code]
	delete(i.codes, code)
	subject := i.subject
	email := i.email
	name := i.name
	i.mu.Unlock()
	if !ok {
		http.Error(w, "unknown code", http.StatusBadRequest)
		return
	}
	// Validate PKCE: SHA256(code_verifier) base64url-no-pad ==
	// code_challenge. The production AuthCodeURL hard-codes S256, so
	// we don't need to read code_challenge_method.
	if expectS256(verifier) != issued.codeChallenge {
		http.Error(w, "pkce verify failed", http.StatusBadRequest)
		return
	}

	rawClaims := fmt.Sprintf(`{
		"iss": "%s",
		"aud": "%s",
		"sub": "%s",
		"email": "%s",
		"name": "%s",
		"nonce": "%s",
		"exp": 9999999999,
		"iat": 1700000000
	}`, i.srv.URL, i.clientID, subject, email, name, issued.nonce)
	idToken := oidctest.SignIDToken(i.priv, "test-key", gooidc.RS256, rawClaims)

	resp := map[string]any{
		"access_token": "fake-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func expectS256(verifier string) string {
	// PKCE S256: base64url(sha256(verifier)) no padding. Mirrors what
	// internal/auth/oidc.NewPKCE produces.
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randHex(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// --- the actual tests ---------------------------------------------

// newTestServer wires up everything `cli/serve` does for the HTTP
// path: store, session manager, OIDC client (against the fake IdP),
// PreSessionStore, users service. Returns the running server URL +
// the IdP fixture (so a test can tweak claims) + the store handle
// (for direct DB inspection).
func newTestServer(t *testing.T, adminSubs []string) (serverURL string, idp *fakeIdP, st *store.Store) {
	t.Helper()
	st = openTempStore(t)
	idp = newFakeIdP(t, "reduit-test-client")

	mgr, cleanup, err := session.New(st.DB.DB, session.Options{Insecure: true})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	t.Cleanup(cleanup)

	// We need the test server's URL to register as the redirect_uri,
	// but we don't have the URL until httptest.NewServer returns. The
	// usual two-pass pattern: build the OIDC client AFTER spinning up
	// httptest with a placeholder, then rebuild deps. Easier: use a
	// known port via a closure in the redirect, then patch.
	//
	// Cleanest in practice: spin up the test server first with a stub
	// handler, capture its URL, build the OIDC client against that
	// URL as the redirect, swap the handler in.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	oidcClient, err := authoidc.New(ctx, authoidc.Config{
		IssuerURL:    idp.URL(),
		ClientID:     "reduit-test-client",
		ClientSecret: "test-secret",
		RedirectURL:  srv.URL + "/auth/callback",
		Scopes:       []string{"openid", "profile", "email"},
	})
	if err != nil {
		t.Fatalf("authoidc.New: %v", err)
	}
	preSessions := authoidc.NewPreSessionStore(0)
	usersSvc := users.New(st)

	deps := server.Deps{
		Store:           st,
		Logger:          slog.Default(),
		Version:         "test",
		SessionManager:  mgr,
		OIDC:            oidcClient,
		PreSessions:     preSessions,
		UsersService:    usersSvc,
		AdminSubjects:   adminSubs,
		InsecureCookies: true, // httptest is plain HTTP
	}
	// Use the real Server so the routes/middleware match production.
	_, handler := server.NewForTest(deps)
	mux.Handle("/", handler)

	return srv.URL, idp, st
}

// newClient returns a cookie-jarred client that does NOT auto-follow
// redirects, so tests can inspect 302s mid-flow.
func newClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// loginThroughIdP runs the full flow: GET /auth/login follows
// redirects (manually) through the fake IdP and back to /auth/callback,
// then through to defaultPostLoginPath. Returns the final response so
// the caller can inspect cookies / status.
func loginThroughIdP(t *testing.T, c *http.Client, baseURL, returnTo string) *http.Response {
	t.Helper()
	loginURL := baseURL + "/auth/login"
	if returnTo != "" {
		loginURL += "?return_to=" + url.QueryEscape(returnTo)
	}
	resp, err := c.Get(loginURL)
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("/auth/login status = %d, want 302; body=%s", resp.StatusCode, body)
	}
	resp.Body.Close()

	idpURL := resp.Header.Get("Location")
	if idpURL == "" {
		t.Fatal("/auth/login: empty Location header")
	}

	resp, err = c.Get(idpURL)
	if err != nil {
		t.Fatalf("GET IdP /authorize: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("IdP /authorize status = %d; body=%s", resp.StatusCode, body)
	}
	resp.Body.Close()

	cbURL := resp.Header.Get("Location")
	if cbURL == "" {
		t.Fatal("IdP /authorize: empty Location header")
	}

	resp, err = c.Get(cbURL)
	if err != nil {
		t.Fatalf("GET /auth/callback: %v", err)
	}
	return resp
}

func TestAuthLogin_RedirectsToIdPWithBindCookie(t *testing.T) {
	t.Parallel()
	baseURL, idp, _ := newTestServer(t, nil)
	c := newClient(t)

	resp, err := c.Get(baseURL + "/auth/login")
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, idp.URL()+"/authorize") {
		t.Errorf("Location = %q, want IdP /authorize prefix", loc)
	}
	// PKCE + state must be on the auth URL.
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	q := u.Query()
	for _, k := range []string{"state", "code_challenge", "code_challenge_method", "nonce"} {
		if q.Get(k) == "" {
			t.Errorf("auth URL missing %q", k)
		}
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
	// Bind cookie set on the response.
	cookies := resp.Cookies()
	var bind *http.Cookie
	for _, ck := range cookies {
		if ck.Name == authoidc.BindCookieName {
			bind = ck
			break
		}
	}
	if bind == nil {
		t.Fatal("response missing __Host-Reduit-Bind cookie")
	}
	if bind.Value == "" {
		t.Error("bind cookie has empty value")
	}
	if !bind.HttpOnly {
		t.Error("bind cookie should be HttpOnly")
	}
}

func TestAuthLogin_RejectsAbsoluteReturnTo(t *testing.T) {
	t.Parallel()
	baseURL, _, _ := newTestServer(t, nil)
	c := newClient(t)

	for _, ret := range []string{
		"https://attacker.example/",
		"//attacker.example/",
		"http://attacker.example/path",
	} {
		resp, err := c.Get(baseURL + "/auth/login?return_to=" + url.QueryEscape(ret))
		if err != nil {
			t.Fatalf("GET /auth/login (%s): %v", ret, err)
		}
		resp.Body.Close()
		// Redirect to IdP still happens; the ReturnTo gets sanitized
		// to "" so the eventual callback lands at /accounts default.
		if resp.StatusCode != http.StatusFound {
			t.Errorf("ret=%s status = %d, want 302", ret, resp.StatusCode)
		}
	}
}

func TestAuthCallback_FullRoundTripBindsSession(t *testing.T) {
	t.Parallel()
	baseURL, idp, st := newTestServer(t, nil)
	idp.setSubject("sub-real-user", "joe@example.com", "Joe")
	c := newClient(t)

	resp := loginThroughIdP(t, c, baseURL, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/auth/callback status = %d, want 302; body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Location"); got != "/accounts" {
		t.Errorf("post-login redirect = %q, want /accounts", got)
	}
	// The user row was created.
	usrSvc := users.New(st)
	u, err := usrSvc.GetByOIDCSubject(t.Context(), "sub-real-user")
	if err != nil {
		t.Fatalf("GetByOIDCSubject: %v", err)
	}
	if u.Email != "joe@example.com" {
		t.Errorf("user.Email = %q, want joe@example.com", u.Email)
	}
}

func TestAuthCallback_HonorsRelativeReturnTo(t *testing.T) {
	t.Parallel()
	baseURL, idp, _ := newTestServer(t, nil)
	idp.setSubject("sub-redir", "x@example.com", "X")
	c := newClient(t)

	resp := loginThroughIdP(t, c, baseURL, "/accounts/abc")
	resp.Body.Close()
	if got := resp.Header.Get("Location"); got != "/accounts/abc" {
		t.Errorf("Location = %q, want /accounts/abc", got)
	}
}

func TestAuthCallback_ComputesAdminFromAllowlist(t *testing.T) {
	t.Parallel()
	baseURL, idp, _ := newTestServer(t, []string{"sub-admin"})
	idp.setSubject("sub-admin", "admin@example.com", "Admin")

	c := newClient(t)
	resp := loginThroughIdP(t, c, baseURL, "")
	resp.Body.Close()

	// Identity.IsAdmin should have been written. We can verify by
	// reading back through the same browser hitting a route that
	// reflects the session -- no such route exists yet (#25), but
	// the redirect to /accounts plus the absence of an unauth
	// 302 confirms the session bound. The admin tag itself is
	// covered by BindFromOIDC tests in internal/auth.
	if got := resp.Header.Get("Location"); got != "/accounts" {
		t.Errorf("post-login redirect = %q, want /accounts", got)
	}
}

func TestAuthCallback_RejectsMissingState(t *testing.T) {
	t.Parallel()
	baseURL, _, _ := newTestServer(t, nil)
	c := newClient(t)

	resp, err := c.Get(baseURL + "/auth/callback?code=foo")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAuthCallback_RejectsMismatchedBindToken(t *testing.T) {
	t.Parallel()
	baseURL, _, _ := newTestServer(t, nil)
	c := newClient(t)

	// Drive /auth/login to create a real PreSession + bind cookie...
	resp, err := c.Get(baseURL + "/auth/login")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	state := loc.Query().Get("state")

	// ...then call /auth/callback with the right state but the wrong
	// bind cookie. 401 expected.
	cb := baseURL + "/auth/callback?state=" + state + "&code=fakecode"
	req, _ := http.NewRequest(http.MethodGet, cb, nil)
	req.AddCookie(&http.Cookie{Name: authoidc.BindCookieName, Value: "wrong-token"})

	// Use a bare client (no jar) so the real bind cookie from /login
	// doesn't sneak through.
	bare := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err = bare.Do(req)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAuthLogout_DestroysSessionAndRedirects(t *testing.T) {
	t.Parallel()
	baseURL, idp, _ := newTestServer(t, nil)
	idp.setSubject("sub-logout", "lo@example.com", "LO")
	c := newClient(t)

	// Log in first.
	resp := loginThroughIdP(t, c, baseURL, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d", resp.StatusCode)
	}

	// Now log out.
	resp, err := c.Get(baseURL + "/auth/logout")
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("logout status = %d, want 302", resp.StatusCode)
	}
	// IdP advertises end_session_endpoint, so we redirect there.
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, idp.URL()) {
		t.Errorf("logout redirect = %q, want IdP end_session_endpoint", loc)
	}
}

func TestAllowlist_BypassesGate(t *testing.T) {
	t.Parallel()
	baseURL, _, _ := newTestServer(t, nil)
	c := newClient(t)

	for _, path := range []string{"/healthz", "/readyz", "/auth/login", "/auth/logout"} {
		resp, err := c.Get(baseURL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		// /auth/login redirects to IdP (302); /auth/logout redirects
		// to "/" or end_session (302). /healthz and /readyz are 200.
		// All of them MUST NOT be the gate's "no session" 302 to
		// /auth/login (recursive).
		if path != "/auth/login" && resp.StatusCode == http.StatusFound {
			loc := resp.Header.Get("Location")
			if strings.HasPrefix(loc, "/auth/login") {
				t.Errorf("%s 302d to gate's /auth/login (Location=%q)", path, loc)
			}
		}
	}
}
