package auth_test

import (
	"context"
	"errors"
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
		{"/static/app.js", true},
		{"/static/img/logo.svg", true},
		{"/static", true},
		{"/static/", true}, // edge: bare prefix with slash
		{"/", false},
		{"/accounts", false},
		{"/auth/logout", false},
		{"/healthz.json", false},  // exact match required for non-prefix entries
		{"/healthz/extra", false}, // ditto
		{"/staticky", false},      // not a prefix match
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
