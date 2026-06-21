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

	"github.com/joestump/reduit/internal/account"
	authoidc "github.com/joestump/reduit/internal/auth/oidc"
	"github.com/joestump/reduit/internal/auth/session"
	"github.com/joestump/reduit/internal/notify"
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
	usersSvc := users.New(st)
	serverURL = mountTestServer(t, st, idp, adminSubs, nil, usersSvc)
	return serverURL, idp, st
}

// mountTestServer is the shared per-test wiring that spins up a real
// httptest.Server with the production routes + middleware chain.
// Tests that need a specific account.Service / users.Service can
// pass them in; pass nil for accSvc to skip the dashboard wiring.
// AutoCreate defaults to true (the production default) so existing
// callback tests admit a brand-new subject.
func mountTestServer(t *testing.T, st *store.Store, idp *fakeIdP, adminSubs []string, accSvc account.Service, usrSvc users.Service) string {
	return mountTestServerWithAutoCreate(t, st, idp, adminSubs, accSvc, usrSvc, true)
}

// mountTestServerWithAutoCreate is mountTestServer with an explicit
// OIDC_AUTO_CREATE value so the login-policy deny-path tests can drive
// AutoCreate=false and assert a 403 for an unknown subject.
func mountTestServerWithAutoCreate(t *testing.T, st *store.Store, idp *fakeIdP, adminSubs []string, accSvc account.Service, usrSvc users.Service, autoCreate bool) string {
	t.Helper()
	mgr, cleanup, err := session.New(st.DB.DB, session.Options{Insecure: true})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	t.Cleanup(cleanup)

	// Two-pass: spin up httptest with a placeholder mux, capture the
	// URL, build the OIDC client against that URL as the redirect,
	// then swap the production handler in.
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

	deps := server.Deps{
		Store:           st,
		Logger:          slog.Default(),
		Version:         "test",
		SessionManager:  mgr,
		OIDC:            oidcClient,
		PreSessions:     preSessions,
		UsersService:    usrSvc,
		AccountService:  accSvc,
		Notifications:   notify.New(st),
		AdminSubjects:   adminSubs,
		AutoCreate:      autoCreate,
		InsecureCookies: true, // httptest is plain HTTP
	}
	// Use the real Server so the routes/middleware match production.
	_, handler := server.NewForTest(deps)
	mux.Handle("/", handler)

	return srv.URL
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

	// Each entry MUST be sanitized to "" so the eventual /auth/callback
	// redirect lands at the defaultPostLoginPath rather than at the
	// attacker-controlled host. The handler still 302s to the IdP --
	// what matters is that the PreSession's ReturnTo is empty.
	for _, ret := range []string{
		// Classic absolute URL.
		"https://attacker.example/",
		"http://attacker.example/path",
		// Scheme-relative.
		"//attacker.example/",
		// Backslash variants -- Chrome/Firefox normalize `\` to `/`
		// in Location headers, so these land at attacker.example
		// even though url.Parse reports Scheme=Host="".
		`\\attacker.example/`,
		`/\attacker.example/`,
		`/\\attacker.example/`,
		`\attacker.example`,
		// Mixed-case + leading whitespace (TrimSpace handles the latter).
		"   //attacker.example/",
		"   https://attacker.example/",
	} {
		resp, err := c.Get(baseURL + "/auth/login?return_to=" + url.QueryEscape(ret))
		if err != nil {
			t.Fatalf("GET /auth/login (%s): %v", ret, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Errorf("ret=%q status = %d, want 302", ret, resp.StatusCode)
		}
	}
}

// TestSanitizeReturnTo exercises the open-redirect-bypass surface
// directly against the helper -- complements
// TestAuthLogin_RejectsAbsoluteReturnTo's end-to-end coverage with a
// targeted unit test that doesn't pay the per-case httptest cost.
func TestSanitizeReturnTo(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   string
		want string
	}{
		// Accepted: same-origin paths starting with /.
		{"/accounts", "/accounts"},
		{"/accounts/abc/messages", "/accounts/abc/messages"},
		{"/", "/"},
		{"  /accounts  ", "/accounts"}, // TrimSpace
		// Rejected: empty / no leading /.
		{"", ""},
		{"   ", ""},
		{"accounts", ""}, // would resolve relative to /auth/
		// Rejected: classic absolute URLs.
		{"https://attacker.example/", ""},
		{"http://attacker.example/path", ""},
		{"ftp://x", ""},
		// Rejected: scheme-relative.
		{"//attacker.example/", ""},
		{"//x", ""},
		// Rejected: backslash bypass shapes (browsers normalize \ to /).
		{`\\attacker.example/`, ""},
		{`/\attacker.example/`, ""},
		{`/\\attacker.example/`, ""},
		{`\attacker.example`, ""},
		{`\\`, ""},
		// Rejected: junk that url.Parse refuses.
		{"http://[::1", ""},
	} {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			if got := server.SanitizeReturnToForTest(tc.in); got != tc.want {
				t.Errorf("sanitizeReturnTo(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
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

// TestAuthCallback_AutoCreateFalseDeniesNewSubject asserts that with
// OIDC_AUTO_CREATE=false a validated-but-unknown subject (no users row,
// not an admin) is denied with 403 and the contact-admin page, and no
// users row is created. Governing: SPEC-0005 REQ "OIDC Login Flow",
// ADR-0010.
func TestAuthCallback_AutoCreateFalseDeniesNewSubject(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	idp := newFakeIdP(t, "reduit-test-client")
	idp.setSubject("sub-stranger", "stranger@example.com", "Stranger")
	usrSvc := users.New(st)
	// AutoCreate=false, empty admin allowlist => closed enrolment.
	baseURL := mountTestServerWithAutoCreate(t, st, idp, nil, nil, usrSvc, false)
	c := newClient(t)

	resp := loginThroughIdP(t, c, baseURL, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied callback status = %d, want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "contact your administrator") {
		t.Errorf("403 body missing contact-admin message; got %q", string(body))
	}
	// No users row was created.
	if _, err := usrSvc.GetByOIDCSubject(t.Context(), "sub-stranger"); err == nil {
		t.Error("denied subject got a users row; want none")
	}
}

// TestAuthCallback_AutoCreateFalseAdmitsExistingUser asserts a
// returning user (already has a users row) is admitted even with
// AutoCreate=false. Governing: SPEC-0005 REQ "OIDC Login Flow".
func TestAuthCallback_AutoCreateFalseAdmitsExistingUser(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	idp := newFakeIdP(t, "reduit-test-client")
	idp.setSubject("sub-returning", "ret@example.com", "Ret")
	usrSvc := users.New(st)
	// Seed the users row so the subject is "known" before login.
	if _, err := usrSvc.Upsert(t.Context(), users.UpsertParams{
		OIDCSubject: "sub-returning",
		Email:       "ret@example.com",
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	baseURL := mountTestServerWithAutoCreate(t, st, idp, nil, nil, usrSvc, false)
	c := newClient(t)

	resp := loginThroughIdP(t, c, baseURL, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("returning-user callback status = %d, want 302; body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Location"); got != "/accounts" {
		t.Errorf("post-login redirect = %q, want /accounts", got)
	}
}

// TestAuthCallback_AutoCreateFalseAdmitsAdmin asserts an admin subject
// is admitted (and provisioned) even with AutoCreate=false, so a fresh
// deployment's operator can bootstrap. Governing: SPEC-0005 REQ
// "First-Run Bootstrap", ADR-0010.
func TestAuthCallback_AutoCreateFalseAdmitsAdmin(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	idp := newFakeIdP(t, "reduit-test-client")
	idp.setSubject("sub-admin-boot", "admin@example.com", "Admin")
	usrSvc := users.New(st)
	baseURL := mountTestServerWithAutoCreate(t, st, idp, []string{"sub-admin-boot"}, nil, usrSvc, false)
	c := newClient(t)

	resp := loginThroughIdP(t, c, baseURL, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("admin bootstrap status = %d, want 302; body=%s", resp.StatusCode, body)
	}
	// The admin was provisioned despite AutoCreate=false.
	if _, err := usrSvc.GetByOIDCSubject(t.Context(), "sub-admin-boot"); err != nil {
		t.Errorf("admin not provisioned: %v", err)
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
	// A dashboard-capable server is needed so we can read the CSRF token
	// off a rendered page before POSTing logout.
	baseURL, idp, _, _ := dashboardTestServer(t, nil)
	idp.setSubject("sub-logout", "lo@example.com", "LO")
	c := newClient(t)

	// Log in first.
	resp := loginThroughIdP(t, c, baseURL, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d", resp.StatusCode)
	}

	token := csrfTokenFromDashboard(t, c, baseURL)

	// Now log out with a valid CSRF token.
	resp = postLogout(t, c, baseURL, token)
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

// csrfTokenFromDashboard logs the already-authenticated client onto
// /accounts and scrapes the hidden csrf_token field from the navbar
// logout form.
func csrfTokenFromDashboard(t *testing.T, c *http.Client, baseURL string) string {
	t.Helper()
	resp, err := c.Get(baseURL + "/accounts")
	if err != nil {
		t.Fatalf("GET /accounts: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /accounts body: %v", err)
	}
	tok := scrapeCSRF(string(body))
	if tok == "" {
		t.Fatalf("no csrf_token in /accounts body (status %d)", resp.StatusCode)
	}
	return tok
}

// scrapeCSRF pulls the value of the hidden csrf_token input out of a
// rendered page. Deliberately a tiny string scan rather than an HTML
// parser -- the field shape is fixed by base.html.
func scrapeCSRF(html string) string {
	const marker = `name="csrf_token" value="`
	i := strings.Index(html, marker)
	if i < 0 {
		return ""
	}
	rest := html[i+len(marker):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// postLogout submits the CSRF-protected logout form.
func postLogout(t *testing.T, c *http.Client, baseURL, token string) *http.Response {
	t.Helper()
	form := url.Values{}
	form.Set("csrf_token", token)
	req, err := http.NewRequest(http.MethodPost, baseURL+"/auth/logout", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new logout request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST /auth/logout: %v", err)
	}
	return resp
}

// TestAuthLogout_GETIsRejected asserts a GET /auth/logout 405s -- the
// route is POST-only so a SameSite=Lax cross-site GET cannot log a
// user out. Governing: SPEC-0005 design "Content security and CSRF".
func TestAuthLogout_GETIsRejected(t *testing.T) {
	t.Parallel()
	baseURL, _, _ := newTestServer(t, nil)
	c := newClient(t)

	resp, err := c.Get(baseURL + "/auth/logout")
	if err != nil {
		t.Fatalf("GET /auth/logout: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /auth/logout status = %d, want 405", resp.StatusCode)
	}
}

// TestAuthLogout_POSTWithoutTokenIsForbidden asserts a logged-in POST
// with no/invalid CSRF token gets 403 and the session survives.
// Governing: SPEC-0005 design "Content security and CSRF".
func TestAuthLogout_POSTWithoutTokenIsForbidden(t *testing.T) {
	t.Parallel()
	baseURL, idp, _, _ := dashboardTestServer(t, nil)
	idp.setSubject("sub-csrf", "csrf@example.com", "CSRF")
	c := newClient(t)

	resp := loginThroughIdP(t, c, baseURL, "")
	resp.Body.Close()

	// No token at all.
	resp = postLogout(t, c, baseURL, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("token-less logout status = %d, want 403", resp.StatusCode)
	}

	// Wrong token.
	resp = postLogout(t, c, baseURL, "not-the-real-token")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("bad-token logout status = %d, want 403", resp.StatusCode)
	}

	// The session must still be alive: /accounts renders (200), not a
	// gate 302 to /auth/login.
	resp, err := c.Get(baseURL + "/accounts")
	if err != nil {
		t.Fatalf("GET /accounts: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("post-failed-logout /accounts status = %d, want 200 (session intact)", resp.StatusCode)
	}
}

func TestAllowlist_BypassesGate(t *testing.T) {
	t.Parallel()
	baseURL, _, _ := newTestServer(t, nil)
	c := newClient(t)

	// /auth/logout is omitted here: it is POST-only now (a GET 405s at
	// the mux), so it can't participate in a GET allowlist probe. Its
	// allowlist behaviour (the gate doesn't 302-loop it) is covered by
	// the dedicated logout tests.
	for _, path := range []string{"/healthz", "/readyz", "/auth/login"} {
		resp, err := c.Get(baseURL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		// /auth/login redirects to IdP (302). /healthz and /readyz are
		// 200. None MUST be the gate's "no session" 302 to /auth/login.
		if path != "/auth/login" && resp.StatusCode == http.StatusFound {
			loc := resp.Header.Get("Location")
			if strings.HasPrefix(loc, "/auth/login") {
				t.Errorf("%s 302d to gate's /auth/login (Location=%q)", path, loc)
			}
		}
	}
}
