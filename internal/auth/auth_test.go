package auth_test

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
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
