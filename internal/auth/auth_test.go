package auth_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/joestump/reduit/internal/auth"
	"github.com/joestump/reduit/internal/auth/session"
	"github.com/joestump/reduit/internal/store"
)

// TestIsAllowlisted exercises every entry from the SPEC-0005 allowlist.
//
// Governing: SPEC-0005 REQ "Authentication Gating" (Scenario:
// Allowlist bypasses auth).
func TestIsAllowlisted(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/healthz", true},
		{"/readyz", true},
		{"/metrics", true},
		{"/auth/login", true},
		{"/auth/callback", true},
		// /auth/logout is allowlisted per #23 so a stale browser tab
		// can hit it without redirect-looping through /auth/login.
		// The handler always destroys the session (no-op when there
		// isn't one) and redirects to "/" or the IdP's
		// end_session_endpoint.
		{"/auth/logout", true},
		{"/static/app.js", true},
		{"/static/img/logo.svg", true},
		{"/static", true},
		{"/static/", true}, // edge: bare prefix with slash
		{"/favicon.svg", true},
		// /favicon.ico (no SVG suffix) is NOT allowlisted -- the
		// brand mark ships as SVG only; a request for the .ico
		// variant should bounce through the auth gate like any
		// other unknown path. Pinning the absence of an exact .ico
		// match catches a future regression that broadens the
		// allowlist to a /favicon* prefix.
		{"/favicon.ico", false},
		// /mcp is allowlisted because the embedded MCP server has
		// its own bearer-auth middleware (per ADR-0008 / SPEC-0006);
		// without the bypass the SCS session gate would 302-redirect
		// MCP clients to /auth/login -- a redirect they cannot follow.
		{"/mcp", true},
		// /mcp/anything is NOT allowlisted by an exact-match entry.
		// The MCP SDK serves the same path for all methods, so a
		// stray subpath shouldn't grant blanket bypass.
		{"/mcp/extra", false},
		{"/mcpish", false},
		{"/", false},
		{"/accounts", false},
		{"/healthz.json", false},  // exact match required for non-prefix entries
		{"/healthz/extra", false}, // ditto
		{"/staticky", false},      // not a prefix match
		// /accounts/{id}/mcp is the path-prefixed bearer-authenticated
		// MCP route (#15, SPEC-0006 "Selector Precedence"). It bypasses
		// the SCS session gate exactly like /mcp because it carries
		// bearer auth, not a browser session.
		{"/accounts/0190abcd-ef01-7000-8000-000000000000/mcp", true},
		{"/accounts/acct-1/mcp", true},
		// The exemption is structurally narrow: it MUST NOT leak onto
		// the session-gated account dashboard or its sub-routes, and
		// MUST NOT match a deeper or empty-id path.
		{"/accounts/acct-1", false},
		{"/accounts/acct-1/credentials", false},
		{"/accounts/acct-1/mcp/extra", false},
		{"/accounts//mcp", false}, // empty id segment
		{"/accounts/mcp", false},  // missing id segment
	} {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			if got := auth.IsAllowlisted(tc.path); got != tc.want {
				t.Errorf("IsAllowlisted(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// TestRequireSession_RedirectsUnauthenticated covers SPEC-0005's
// "Unauthenticated request redirects to login" scenario: a GET to a
// protected route returns 302 with Location: /auth/login?return_to=...
//
// Governing: SPEC-0005 REQ "Authentication Gating".
func TestRequireSession_RedirectsUnauthenticated(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	mgr, cleanup, err := session.New(st.DB.DB, session.Options{Insecure: true})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	defer cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("/accounts", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("you should not see this"))
	})
	handler := mgr.LoadAndSave(auth.RequireSession(auth.SessionGate{Manager: mgr}, mux))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(srv.URL + "/accounts")
	if err != nil {
		t.Fatalf("GET /accounts: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("Location %q parse: %v", loc, err)
	}
	if u.Path != "/auth/login" {
		t.Errorf("Location.Path = %q, want /auth/login", u.Path)
	}
	if got := u.Query().Get("return_to"); got != "/accounts" {
		t.Errorf("return_to = %q, want /accounts", got)
	}
}

// TestRequireSession_AllowsAuthenticated covers the "Authenticated
// request proceeds" scenario. /auth/login is in the allowlist (so we
// can stash an identity there without redirecting); /accounts is the
// protected route.
func TestRequireSession_AllowsAuthenticated(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	mgr, cleanup, err := session.New(st.DB.DB, session.Options{Insecure: true})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	defer cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if err := session.PutIdentity(r.Context(), mgr, session.Identity{Subject: "joe"}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/accounts", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("welcome"))
	})
	handler := mgr.LoadAndSave(auth.RequireSession(auth.SessionGate{Manager: mgr}, mux))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	resp, err := c.Get(srv.URL + "/auth/login")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login status = %d, want 200", resp.StatusCode)
	}
	resp, err = c.Get(srv.URL + "/accounts")
	if err != nil {
		t.Fatalf("accounts: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestRequireSession_AllowlistBypasses covers the "Allowlist bypasses
// auth" scenario for /healthz with no session cookie.
func TestRequireSession_AllowlistBypasses(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	mgr, cleanup, err := session.New(st.DB.DB, session.Options{Insecure: true})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	defer cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	handler := mgr.LoadAndSave(auth.RequireSession(auth.SessionGate{Manager: mgr}, mux))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// TestRequireSession_NonGETUnauthorized verifies that a stale session
// on a state-changing method does not silently round-trip through the
// IdP — it 401s instead.
func TestRequireSession_NonGETUnauthorized(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	mgr, cleanup, err := session.New(st.DB.DB, session.Options{Insecure: true})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	defer cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("/accounts/me", func(w http.ResponseWriter, r *http.Request) {})
	handler := mgr.LoadAndSave(auth.RequireSession(auth.SessionGate{Manager: mgr}, mux))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/accounts/me", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// TestRequireSession_AccountStateRecheck covers C6 from the round-1
// hostile review. SPEC-0005's "Authenticated request proceeds"
// scenario anchors on "an active session for an account": the bind
// is account-state-sensitive, not just cookie-validity-sensitive. A
// session issued before the account was suspended MUST stop working
// on the very next gated request, not only after idle timeout.
//
// Three sub-cases:
//
//   - active: AccountActive(id) returns (true, nil) → request
//     proceeds.
//   - suspended: AccountActive returns (false, nil) → session is
//     destroyed and the gate denies as if no cookie were present
//     (302 to /auth/login for GET, 401 for non-GET).
//   - DB error: AccountActive returns (_, err) → 503 (fail closed).
//
// Governing: SPEC-0005 REQ "Authentication Gating"; SPEC-0005 REQ
// "Admin Account Management".
func TestRequireSession_AccountStateRecheck(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	mgr, cleanup, err := session.New(st.DB.DB, session.Options{Insecure: true})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	defer cleanup()

	// State the test toggles between sub-cases.
	type checkResult struct {
		ok  bool
		err error
	}
	var (
		checkMu  sync.Mutex
		checkRet checkResult
	)
	setCheck := func(r checkResult) {
		checkMu.Lock()
		defer checkMu.Unlock()
		checkRet = r
	}
	checker := func(ctx context.Context, accountID string) (bool, error) {
		checkMu.Lock()
		defer checkMu.Unlock()
		if accountID != "acct-42" {
			t.Errorf("checker called with accountID=%q, want %q", accountID, "acct-42")
		}
		return checkRet.ok, checkRet.err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		_ = session.PutIdentity(r.Context(), mgr, session.Identity{Subject: "joe", AccountID: "acct-42"})
		_, _ = w.Write([]byte("logged in"))
	})
	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("welcome"))
	})
	gate := auth.SessionGate{
		Manager:       mgr,
		LoginPath:     "/auth/login",
		AccountActive: checker,
	}
	handler := mgr.LoadAndSave(auth.RequireSession(gate, mux))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Log in.
	if _, err := c.Get(srv.URL + "/auth/login"); err != nil {
		t.Fatalf("login: %v", err)
	}

	// Active: 200.
	setCheck(checkResult{ok: true})
	resp, err := c.Get(srv.URL + "/protected")
	if err != nil {
		t.Fatalf("/protected (active): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("active status = %d, want 200", resp.StatusCode)
	}

	// Suspended: 302 to /auth/login (GET path).
	setCheck(checkResult{ok: false})
	resp, err = c.Get(srv.URL + "/protected")
	if err != nil {
		t.Fatalf("/protected (suspended): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("suspended status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/auth/login") {
		t.Errorf("Location = %q, want /auth/login...", loc)
	}

	// Once destroyed, even with the recheck flipped back to active the
	// session cookie is dead — re-login is required.
	setCheck(checkResult{ok: true})
	resp, err = c.Get(srv.URL + "/protected")
	if err != nil {
		t.Fatalf("/protected (post-destroy): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("post-destroy GET status = %d, want 302 (cookie destroyed)", resp.StatusCode)
	}

	// DB error path: with a fresh login + checker erroring, the gate
	// returns 503. Re-login first because the previous Destroy killed
	// the prior session.
	if _, err := c.Get(srv.URL + "/auth/login"); err != nil {
		t.Fatalf("re-login: %v", err)
	}
	setCheck(checkResult{ok: false, err: errors.New("db down")})
	resp, err = c.Get(srv.URL + "/protected")
	if err != nil {
		t.Fatalf("/protected (db err): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("db-err status = %d, want 503", resp.StatusCode)
	}

	// Suspended POST → 401 (non-GET path) after fresh login.
	if _, err := c.Get(srv.URL + "/auth/login"); err != nil {
		t.Fatalf("re-login (post): %v", err)
	}
	setCheck(checkResult{ok: false})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/protected", nil)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatalf("POST /protected (suspended): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("suspended POST status = %d, want 401", resp.StatusCode)
	}
}

// TestRequireSession_PrincipalActiveRecheck pins issue #52's
// ADR-0010-correct, user-scoped re-check. Unlike the account-id-keyed
// AccountActive path, PrincipalActive:
//
//   - receives the whole Identity (so it can gate on users.id, the
//     ADR-0010 binding), and
//   - does NOT treat an empty AccountID as a malformed shape -- the
//     plain dashboard session legitimately has no account in scope.
//
// Sub-cases: active principal -> 200; suspended principal (e.g. all
// owned accounts suspended/soft-deleted) -> session destroyed + 302;
// store error -> 503 fail-closed; and PrincipalActive supersedes
// AccountActive when both are set.
//
// Governing: ADR-0004 (OIDC control-plane auth), ADR-0010 (sessions
// bind to users.id; AccountID optional), SPEC-0005 REQ "Admin Account
// Management", SPEC-0005 REQ "Authentication Gating".
func TestRequireSession_PrincipalActiveRecheck(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	mgr, cleanup, err := session.New(st.DB.DB, session.Options{Insecure: true})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	defer cleanup()

	type checkResult struct {
		ok  bool
		err error
	}
	var (
		checkMu  sync.Mutex
		checkRet checkResult
	)
	setCheck := func(r checkResult) {
		checkMu.Lock()
		defer checkMu.Unlock()
		checkRet = r
	}
	principal := func(ctx context.Context, id session.Identity) (bool, error) {
		checkMu.Lock()
		defer checkMu.Unlock()
		// User-scoped: UserID is the binding, AccountID is empty for the
		// plain dashboard session and MUST NOT be rejected as malformed.
		if id.UserID != "user-7" {
			t.Errorf("principal called with UserID=%q, want %q", id.UserID, "user-7")
		}
		if id.AccountID != "" {
			t.Errorf("dashboard session AccountID=%q, want empty (ADR-0010)", id.AccountID)
		}
		return checkRet.ok, checkRet.err
	}
	// AccountActive must never run when PrincipalActive is wired.
	accountActive := func(ctx context.Context, accountID string) (bool, error) {
		t.Errorf("AccountActive MUST NOT be called when PrincipalActive is set; got accountID=%q", accountID)
		return false, nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		// User-scoped session: UserID set, AccountID empty (ADR-0010).
		_ = session.PutIdentity(r.Context(), mgr, session.Identity{Subject: "joe", UserID: "user-7"})
		_, _ = w.Write([]byte("logged in"))
	})
	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("welcome"))
	})
	gate := auth.SessionGate{
		Manager:         mgr,
		LoginPath:       "/auth/login",
		PrincipalActive: principal,
		AccountActive:   accountActive,
	}
	handler := mgr.LoadAndSave(auth.RequireSession(gate, mux))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if _, err := c.Get(srv.URL + "/auth/login"); err != nil {
		t.Fatalf("login: %v", err)
	}

	// Active principal -> 200.
	setCheck(checkResult{ok: true})
	resp, err := c.Get(srv.URL + "/protected")
	if err != nil {
		t.Fatalf("/protected (active): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("active status = %d, want 200", resp.StatusCode)
	}

	// Suspended principal -> 302, session destroyed.
	setCheck(checkResult{ok: false})
	resp, err = c.Get(srv.URL + "/protected")
	if err != nil {
		t.Fatalf("/protected (suspended): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("suspended status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/auth/login") {
		t.Errorf("Location = %q, want /auth/login...", loc)
	}

	// Cookie is now dead even if the principal flips back to active.
	setCheck(checkResult{ok: true})
	resp, err = c.Get(srv.URL + "/protected")
	if err != nil {
		t.Fatalf("/protected (post-destroy): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("post-destroy status = %d, want 302 (cookie destroyed)", resp.StatusCode)
	}

	// Store-error path -> 503 fail-closed (after fresh login).
	if _, err := c.Get(srv.URL + "/auth/login"); err != nil {
		t.Fatalf("re-login: %v", err)
	}
	setCheck(checkResult{ok: false, err: errors.New("store down")})
	resp, err = c.Get(srv.URL + "/protected")
	if err != nil {
		t.Fatalf("/protected (store err): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("store-err status = %d, want 503", resp.StatusCode)
	}
}

// TestRequireSession_MalformedSessionFailsClosed pins the C6-N1
// hostile-R2 fix. When the gate has AccountActive wired and the
// session ends up with Subject set but AccountID empty (a shape
// currently unreachable through PutIdentity but easy to introduce
// via a future caller wiring bug), the gate MUST fail closed:
// destroy the session, deny the request as if no cookie were
// present, and log a structured warning so operators can spot the
// wiring bug.
//
// Governing: SPEC-0005 REQ "Authentication Gating" (auth code MUST
// fail closed on unexpected identity shapes); hostile-R2 finding
// C6-N1.
func TestRequireSession_MalformedSessionFailsClosed(t *testing.T) {
	// Not parallel — captures slog.Default which is process-global.
	st := openTempStore(t)
	defer st.Close()
	mgr, cleanup, err := session.New(st.DB.DB, session.Options{Insecure: true})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	defer cleanup()

	// Capture slog output. Restore the default at test exit so
	// sibling tests are not poisoned.
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	var logBuf safeLogBuf
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	checker := func(ctx context.Context, accountID string) (bool, error) {
		t.Errorf("AccountActive checker MUST NOT be called on a malformed session; got accountID=%q", accountID)
		return true, nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		// Construct the malformed shape directly: Subject set,
		// AccountID empty. PutIdentity naturally produces this when
		// AccountID is the zero value (it Put()s an empty string for
		// the account key) — bypassing the helper would also work, but
		// this is the simplest reproducer.
		_ = session.PutIdentity(r.Context(), mgr, session.Identity{Subject: "joe"})
		_, _ = w.Write([]byte("logged in (malformed)"))
	})
	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		t.Error("protected handler MUST NOT run on a malformed session")
		_, _ = w.Write([]byte("welcome"))
	})
	gate := auth.SessionGate{
		Manager:       mgr,
		LoginPath:     "/auth/login",
		AccountActive: checker,
	}
	handler := mgr.LoadAndSave(auth.RequireSession(gate, mux))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Establish the malformed session.
	if _, err := c.Get(srv.URL + "/auth/login"); err != nil {
		t.Fatalf("login: %v", err)
	}

	// GET → 302 to /auth/login (matching the missing-cookie branch).
	resp, err := c.Get(srv.URL + "/protected")
	if err != nil {
		t.Fatalf("/protected (malformed GET): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("malformed GET status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/auth/login") {
		t.Errorf("Location = %q, want /auth/login...", loc)
	}

	// Even with the checker still wired and the cookie still on the
	// jar, a follow-up request finds the session destroyed (302).
	resp, err = c.Get(srv.URL + "/protected")
	if err != nil {
		t.Fatalf("/protected (post-destroy): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("post-destroy status = %d, want 302 (cookie destroyed)", resp.StatusCode)
	}

	// POST on a fresh malformed session → 401 (non-GET branch).
	if _, err := c.Get(srv.URL + "/auth/login"); err != nil {
		t.Fatalf("re-login (post): %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/protected", nil)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatalf("POST /protected (malformed): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("malformed POST status = %d, want 401", resp.StatusCode)
	}

	// The structured warning fired at least once.
	if !logBuf.contains("session has Subject but empty AccountID") {
		t.Errorf("expected slog.Warn for malformed session; got logs:\n%s", logBuf.String())
	}
}

// safeLogBuf is a tiny io.Writer that captures slog output for
// assertion. We cannot use bytes.Buffer directly because slog calls
// Write concurrently in some configurations.
type safeLogBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeLogBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeLogBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *safeLogBuf) contains(needle string) bool {
	return strings.Contains(s.String(), needle)
}

// TestRequireSession_NoCheckerSkipsRecheck confirms the foundation
// remains backward-compatible for tests / callers that have not
// wired AccountActive: a session with empty AccountID still gates on
// Subject alone.
func TestRequireSession_NoCheckerSkipsRecheck(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	mgr, cleanup, err := session.New(st.DB.DB, session.Options{Insecure: true})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	defer cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		_ = session.PutIdentity(r.Context(), mgr, session.Identity{Subject: "joe", AccountID: "acct-x"})
	})
	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	handler := mgr.LoadAndSave(auth.RequireSession(auth.SessionGate{Manager: mgr}, mux))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	if _, err := c.Get(srv.URL + "/auth/login"); err != nil {
		t.Fatalf("login: %v", err)
	}
	resp, err := c.Get(srv.URL + "/protected")
	if err != nil {
		t.Fatalf("protected: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestRequireAdmin checks the admin gate: a non-admin session is 403,
// an admin session passes, an unauthenticated request is 403 (not
// redirected — RequireAdmin is composed AFTER RequireSession).
func TestRequireAdmin(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	mgr, cleanup, err := session.New(st.DB.DB, session.Options{Insecure: true})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	defer cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("/login-admin", func(w http.ResponseWriter, r *http.Request) {
		_ = session.PutIdentity(r.Context(), mgr, session.Identity{Subject: "admin", IsAdmin: true})
	})
	mux.HandleFunc("/login-user", func(w http.ResponseWriter, r *http.Request) {
		_ = session.PutIdentity(r.Context(), mgr, session.Identity{Subject: "user"})
	})
	mux.Handle("/admin/", auth.RequireAdmin(mgr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("admin ok"))
	})))
	handler := mgr.LoadAndSave(mux)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// Unauthenticated → 403.
	resp, err := http.Get(srv.URL + "/admin/x")
	if err != nil {
		t.Fatalf("GET /admin/x: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("anonymous status = %d, want 403", resp.StatusCode)
	}

	// User → 403.
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	if _, err := c.Get(srv.URL + "/login-user"); err != nil {
		t.Fatalf("login-user: %v", err)
	}
	resp, err = c.Get(srv.URL + "/admin/x")
	if err != nil {
		t.Fatalf("user GET /admin/x: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("user status = %d, want 403", resp.StatusCode)
	}

	// Admin → 200.
	jar2, _ := cookiejar.New(nil)
	c2 := &http.Client{Jar: jar2}
	if _, err := c2.Get(srv.URL + "/login-admin"); err != nil {
		t.Fatalf("login-admin: %v", err)
	}
	resp, err = c2.Get(srv.URL + "/admin/x")
	if err != nil {
		t.Fatalf("admin GET /admin/x: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("admin status = %d, want 200", resp.StatusCode)
	}
}

// openTempStore mirrors the helper used elsewhere — open + migrate.
func openTempStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir + "/reduit.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Migrate(""); err != nil {
		st.Close()
		t.Fatalf("Migrate: %v", err)
	}
	return st
}
