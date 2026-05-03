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

// TestBindAndRevokeSessionsForAccount covers C4 from the round-1
// hostile review: SPEC-0005's "drop sessions on suspend / soft-delete"
// scenarios need an O(log n) DELETE keyed by account_id, which means
// the foundation owns (1) populating sessions.account_id at login
// time and (2) a helper to run the bulk delete.
//
// Flow:
//
//  1. Two browsers (cookie jars) log in as the same account; a
//     third browser logs in as a different account.
//  2. RevokeSessionsForAccount("acct-victim") removes both rows
//     for the suspended account.
//  3. The unrelated account's session row survives.
//
// Governing: SPEC-0005 REQ "Admin Account Management".
func TestBindAndRevokeSessionsForAccount(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	insertAccountForSession(t, st, "acct-victim")
	insertAccountForSession(t, st, "acct-bystander")

	mgr, cleanup, err := session.New(st.DB.DB, session.Options{Insecure: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		acct := r.URL.Query().Get("account")
		userID := "user-" + acct
		id := session.Identity{Subject: "sub-" + acct, UserID: userID, AccountID: acct}
		if err := session.PutIdentity(r.Context(), mgr, id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Force SCS to commit synchronously so the bind helpers have a
		// row to write/UPDATE -- production callers in #23 follow the
		// same pattern.
		if _, _, err := mgr.Commit(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Per ADR-0010, the user-bind is the primary write; the
		// account-bind narrows the scope. BindSessionToAccount errors
		// if no user-bound row exists, so the order matters.
		if err := session.BindSessionToUser(r.Context(), mgr, st.DB.DB, userID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := session.BindSessionToAccount(r.Context(), mgr, st.DB.DB, acct); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		if !session.IsAuthenticated(r.Context(), mgr) {
			http.Error(w, "unauth", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mgr.LoadAndSave(mux))
	defer srv.Close()

	browserA := newBrowser(t)
	loginAs(t, browserA, srv.URL, "acct-victim")
	browserB := newBrowser(t)
	loginAs(t, browserB, srv.URL, "acct-victim")
	browserC := newBrowser(t)
	loginAs(t, browserC, srv.URL, "acct-bystander")

	// Pre-revoke: every browser is authenticated.
	for _, b := range []*http.Client{browserA, browserB, browserC} {
		resp, err := b.Get(srv.URL + "/me")
		if err != nil {
			t.Fatalf("/me: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("pre-revoke /me status = %d, want 200", resp.StatusCode)
		}
	}

	// Suspend acct-victim → RevokeSessionsForAccount drops both
	// browserA + browserB sessions.
	n, err := session.RevokeSessionsForAccount(t.Context(), st.DB.DB, "acct-victim")
	if err != nil {
		t.Fatalf("RevokeSessionsForAccount: %v", err)
	}
	if n != 2 {
		t.Fatalf("RevokeSessionsForAccount = %d, want 2", n)
	}

	// Post-revoke: browserA + browserB are 401, browserC still OK.
	for label, b := range map[string]*http.Client{"A": browserA, "B": browserB} {
		resp, err := b.Get(srv.URL + "/me")
		if err != nil {
			t.Fatalf("post-revoke /me %s: %v", label, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("post-revoke %s status = %d, want 401", label, resp.StatusCode)
		}
	}
	resp, err := browserC.Get(srv.URL + "/me")
	if err != nil {
		t.Fatalf("post-revoke /me C: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("bystander session dropped — status %d", resp.StatusCode)
	}
}

// TestRevokeSessionsForAccount_NoLiveSessions covers the idempotent
// "no rows" case.
func TestRevokeSessionsForAccount_NoLiveSessions(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	n, err := session.RevokeSessionsForAccount(t.Context(), st.DB.DB, "no-such")
	if err != nil {
		t.Fatalf("RevokeSessionsForAccount: %v", err)
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
}

// TestRevokeSessionsForAccount_GuardsBadInput covers the nil/empty
// argument guards.
func TestRevokeSessionsForAccount_GuardsBadInput(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	if _, err := session.RevokeSessionsForAccount(t.Context(), nil, "x"); err == nil {
		t.Error("nil db: expected error, got nil")
	}
	if _, err := session.RevokeSessionsForAccount(t.Context(), st.DB.DB, ""); err == nil {
		t.Error("empty account: expected error, got nil")
	}
}

// TestRevokeSessionsForUser_DropsAllUserSessions exercises the
// per-user revocation primitive ADR-0010 introduces. A user with two
// sessions across two browsers (each scoped to a different one of
// their accounts) loses both when their users row is removed; an
// unrelated user's session survives.
//
// Governing: ADR-0010, SPEC-0001 REQ "User Lifecycle".
func TestRevokeSessionsForUser_DropsAllUserSessions(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()

	// User A owns two accounts; user B owns one. The "user owns N
	// accounts" shape is the whole point of ADR-0010 -- this test
	// pins the matching revocation scope.
	insertUserWithAccounts(t, st, "user-A", "sub-A", []string{"acct-A1", "acct-A2"})
	insertUserWithAccounts(t, st, "user-B", "sub-B", []string{"acct-B1"})

	mgr, cleanup, err := session.New(st.DB.DB, session.Options{Insecure: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("user")
		acct := r.URL.Query().Get("account")
		id := session.Identity{Subject: "sub-" + userID, UserID: userID, AccountID: acct}
		if err := session.PutIdentity(r.Context(), mgr, id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, _, err := mgr.Commit(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := session.BindSessionToUser(r.Context(), mgr, st.DB.DB, userID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if acct != "" {
			if err := session.BindSessionToAccount(r.Context(), mgr, st.DB.DB, acct); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		if !session.IsAuthenticated(r.Context(), mgr) {
			http.Error(w, "unauth", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mgr.LoadAndSave(mux))
	defer srv.Close()

	loginUser := func(c *http.Client, userID, accountID string) {
		t.Helper()
		u := srv.URL + "/login?user=" + userID + "&account=" + accountID
		resp, err := c.Get(u)
		if err != nil {
			t.Fatalf("login (%s/%s): %v", userID, accountID, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("login (%s/%s) status = %d", userID, accountID, resp.StatusCode)
		}
	}

	browserA1 := newBrowser(t)
	loginUser(browserA1, "user-A", "acct-A1")
	browserA2 := newBrowser(t)
	loginUser(browserA2, "user-A", "acct-A2")
	browserB := newBrowser(t)
	loginUser(browserB, "user-B", "acct-B1")

	// Sanity: every browser is authenticated.
	for label, b := range map[string]*http.Client{"A1": browserA1, "A2": browserA2, "B": browserB} {
		resp, err := b.Get(srv.URL + "/me")
		if err != nil {
			t.Fatalf("/me %s: %v", label, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("pre-revoke /me %s status = %d, want 200", label, resp.StatusCode)
		}
	}

	// Revoke user-A's sessions. Both A1 and A2 must drop; B must survive.
	n, err := session.RevokeSessionsForUser(t.Context(), st.DB.DB, "user-A")
	if err != nil {
		t.Fatalf("RevokeSessionsForUser: %v", err)
	}
	if n != 2 {
		t.Fatalf("RevokeSessionsForUser = %d, want 2", n)
	}

	for label, b := range map[string]*http.Client{"A1": browserA1, "A2": browserA2} {
		resp, err := b.Get(srv.URL + "/me")
		if err != nil {
			t.Fatalf("post-revoke /me %s: %v", label, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("revoked browser %s still authenticated -- status %d", label, resp.StatusCode)
		}
	}
	resp, err := browserB.Get(srv.URL + "/me")
	if err != nil {
		t.Fatalf("post-revoke /me B: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("unrelated user-B session dropped -- status %d", resp.StatusCode)
	}
}

// TestRevokeSessionsForUser_NoLiveSessions covers the idempotent
// "no rows" case.
func TestRevokeSessionsForUser_NoLiveSessions(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	n, err := session.RevokeSessionsForUser(t.Context(), st.DB.DB, "no-such-user")
	if err != nil {
		t.Fatalf("RevokeSessionsForUser: %v", err)
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
}

// TestRevokeSessionsForUser_GuardsBadInput covers the nil/empty
// argument guards.
func TestRevokeSessionsForUser_GuardsBadInput(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	if _, err := session.RevokeSessionsForUser(t.Context(), nil, "x"); err == nil {
		t.Error("nil db: expected error, got nil")
	}
	if _, err := session.RevokeSessionsForUser(t.Context(), st.DB.DB, ""); err == nil {
		t.Error("empty user: expected error, got nil")
	}
}

// TestBindSessionToAccount_RequiresUserBindFirst pins the
// "BindSessionToAccount errors when no user-bound row exists"
// invariant. The schema enforces user_id NOT NULL; the error path
// here turns the storage failure into a clear caller-facing message
// rather than a wrapped SQL constraint violation.
func TestBindSessionToAccount_RequiresUserBindFirst(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	insertAccountForSession(t, st, "acct-orphan")

	mgr, cleanup, err := session.New(st.DB.DB, session.Options{Insecure: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer cleanup()

	var bindErr error
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if err := session.PutIdentity(r.Context(), mgr, session.Identity{Subject: "sub-orphan"}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, _, err := mgr.Commit(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Skip BindSessionToUser deliberately. BindSessionToAccount
		// should refuse rather than silently insert a row that
		// violates user_id NOT NULL.
		bindErr = session.BindSessionToAccount(r.Context(), mgr, st.DB.DB, "acct-orphan")
		_, _ = w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mgr.LoadAndSave(mux))
	defer srv.Close()

	resp, err := newBrowser(t).Get(srv.URL + "/login")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()

	if bindErr == nil {
		t.Fatal("BindSessionToAccount succeeded without a prior user bind")
	}
}

// insertUserWithAccounts inserts one users row and N accounts owned
// by that user, all in state=active. Used by RevokeSessionsForUser
// tests that need a user with multiple accounts to assert the
// fan-out scope.
func insertUserWithAccounts(t *testing.T, st *store.Store, userID, sub string, accountIDs []string) {
	t.Helper()
	if _, err := st.DB.ExecContext(t.Context(),
		`INSERT INTO users (id, oidc_subject) VALUES (?, ?)`,
		userID, sub,
	); err != nil {
		t.Fatalf("insert user %s: %v", userID, err)
	}
	for _, aid := range accountIDs {
		if _, err := st.DB.ExecContext(t.Context(),
			`INSERT INTO accounts (id, user_id, state, key_envelope) VALUES (?, ?, 'active', X'00')`,
			aid, userID,
		); err != nil {
			t.Fatalf("insert account %s: %v", aid, err)
		}
	}
}

func newBrowser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{Jar: jar}
}

func loginAs(t *testing.T, c *http.Client, baseURL, accountID string) {
	t.Helper()
	resp, err := c.Get(baseURL + "/login?account=" + accountID)
	if err != nil {
		t.Fatalf("login (%s): %v", accountID, err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login (%s) status = %d", accountID, resp.StatusCode)
	}
}

// Per ADR-0010, accounts.user_id FK requires a users row first --
// insertAccountForSession mints both inline so each call is
// self-contained.
func insertAccountForSession(t *testing.T, st *store.Store, id string) {
	t.Helper()
	if _, err := st.DB.ExecContext(t.Context(),
		`INSERT INTO users (id, oidc_subject) VALUES (?, ?)`,
		"user-"+id, "sub-"+id,
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	const q = `
		INSERT INTO accounts (id, user_id, state, key_envelope)
		VALUES (?, ?, 'active', X'00')
	`
	if _, err := st.DB.ExecContext(t.Context(), q, id, "user-"+id); err != nil {
		t.Fatalf("insert account: %v", err)
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
