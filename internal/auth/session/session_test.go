package session_test

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/joestump/reduit/internal/auth/session"
	"github.com/joestump/reduit/internal/store"
)

// TestNew_RequiresDB checks the constructor's nil-DB guard. Without
// it, the first session write panics deep inside scs.
func TestNew_RequiresDB(t *testing.T) {
	t.Parallel()
	if _, _, err := session.New(nil, session.Options{}); err == nil {
		t.Fatal("New(nil) succeeded")
	}
}

// TestRoundTrip exercises Put/Get against a real *scs.SessionManager
// and a real SQLite-backed sessions table. The flow:
//
//  1. Open a temp store, run migrations.
//  2. Build the session manager.
//  3. GET /login through scs.LoadAndSave; in-handler, PutIdentity.
//  4. Reuse the resulting Set-Cookie on a follow-up GET /me and
//     observe GetIdentity returns the same fields.
//
// Governing: SPEC-0005 REQ "OIDC Login Flow" (the session is the
// post-callback bind point), SPEC-0005 REQ "Authentication Gating".
func TestRoundTrip(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()

	mgr, cleanup, err := session.New(st.DB.DB, session.Options{Insecure: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer cleanup()

	want := session.Identity{Subject: "joe", AccountID: "acct-1", Email: "joe@stump.rocks", IsAdmin: true}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if err := session.PutIdentity(r.Context(), mgr, want); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		got := session.GetIdentity(r.Context(), mgr)
		if got != want {
			http.Error(w, "mismatch", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mgr.LoadAndSave(mux))
	defer srv.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := &http.Client{Jar: jar}

	resp, err := client.Get(srv.URL + "/login")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
	srvURL, _ := url.Parse(srv.URL)
	cookies := jar.Cookies(srvURL)
	found := false
	for _, c := range cookies {
		if c.Name == session.CookieName {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected %q cookie in jar; got %v", session.CookieName, cookies)
	}

	resp, err = client.Get(srv.URL + "/me")
	if err != nil {
		t.Fatalf("me: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("me status = %d (cookie did not round-trip)", resp.StatusCode)
	}
}

// TestCookieAttributes checks the security-relevant cookie attributes
// from SPEC-0005 are set: HttpOnly, SameSite=Lax, Path=/, name
// reduit_session, and Secure unless explicitly opted out.
func TestCookieAttributes(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()

	mgr, cleanup, err := session.New(st.DB.DB, session.Options{}) // production opts
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer cleanup()
	if mgr.Cookie.Name != session.CookieName {
		t.Errorf("Cookie.Name = %q, want %q", mgr.Cookie.Name, session.CookieName)
	}
	if !mgr.Cookie.HttpOnly {
		t.Error("Cookie.HttpOnly = false")
	}
	if !mgr.Cookie.Secure {
		t.Error("Cookie.Secure = false in production opts")
	}
	if mgr.Cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("Cookie.SameSite = %v, want Lax", mgr.Cookie.SameSite)
	}
	if mgr.Cookie.Path != "/" {
		t.Errorf("Cookie.Path = %q, want /", mgr.Cookie.Path)
	}
}

// TestReturnToRoundTrip checks the helper used by login init to
// remember a post-login redirect target.
func TestReturnToRoundTrip(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	mgr, cleanup, err := session.New(st.DB.DB, session.Options{Insecure: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("/stash", func(w http.ResponseWriter, r *http.Request) {
		session.PutReturnTo(r.Context(), mgr, "/accounts")
	})
	mux.HandleFunc("/take", func(w http.ResponseWriter, r *http.Request) {
		got := session.TakeReturnTo(r.Context(), mgr)
		_, _ = w.Write([]byte(got))
	})
	srv := httptest.NewServer(mgr.LoadAndSave(mux))
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	if _, err := c.Get(srv.URL + "/stash"); err != nil {
		t.Fatalf("stash: %v", err)
	}
	resp, err := c.Get(srv.URL + "/take")
	if err != nil {
		t.Fatalf("take: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	if string(buf[:n]) != "/accounts" {
		t.Fatalf("TakeReturnTo = %q, want %q", string(buf[:n]), "/accounts")
	}
}

// openTempStore opens a fresh on-disk SQLite store and runs every
// embedded migration. Mirrors the helper used elsewhere in this repo.
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
