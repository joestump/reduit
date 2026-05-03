// Tests for BindFromOIDC, the OIDC-callback session-bind orchestration.
//
// Governing: ADR-0010, SPEC-0005 REQ "OIDC Login Flow", SPEC-0005
// REQ "Session admin tag is computed at bind time", SPEC-0001 REQ
// "User Identity".

package auth_test

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/joestump/reduit/internal/auth"
	"github.com/joestump/reduit/internal/auth/session"
	"github.com/joestump/reduit/internal/store"
	"github.com/joestump/reduit/internal/users"
)

// runBindThroughHandler wires a one-shot HTTP handler that runs
// BindFromOIDC inside the SCS LoadAndSave middleware and returns
// BindFromOIDC's returned Identity, the persisted Identity (read back
// via GetIdentity on a follow-up request), and the bind error. Tests
// use this rather than calling BindFromOIDC directly because
// BindFromOIDC depends on an active SCS request scope (mgr.Token,
// mgr.Commit) -- driving it through a real httptest server is the
// simplest way to satisfy that.
//
// Returning both the in-handler value and the post-roundtrip read
// catches a class of bug where BindFromOIDC's return diverges from
// what actually got persisted (e.g., a future refactor that moves
// fields around in the Identity struct without updating PutIdentity).
func runBindThroughHandler(t *testing.T, st *store.Store, usrSvc users.Service, claims auth.OIDCClaims, adminSubs []string) (returned, persisted session.Identity, err error) {
	t.Helper()
	mgr, cleanup, mgrErr := session.New(st.DB.DB, session.Options{Insecure: true})
	if mgrErr != nil {
		t.Fatalf("session.New: %v", mgrErr)
	}
	t.Cleanup(cleanup)

	var bindErr error
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		returned, bindErr = auth.BindFromOIDC(r.Context(), mgr, st.DB.DB, usrSvc, claims, adminSubs)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		persisted = session.GetIdentity(r.Context(), mgr)
		_, _ = w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mgr.LoadAndSave(mux))
	t.Cleanup(srv.Close)

	jar, jarErr := cookiejar.New(nil)
	if jarErr != nil {
		t.Fatalf("cookiejar: %v", jarErr)
	}
	c := &http.Client{Jar: jar}
	if resp, e := c.Get(srv.URL + "/callback"); e != nil {
		t.Fatalf("GET /callback: %v", e)
	} else {
		resp.Body.Close()
	}
	// Probe a follow-up request so the session is queryable post-bind.
	if resp, e := c.Get(srv.URL + "/me"); e != nil {
		t.Fatalf("GET /me: %v", e)
	} else {
		resp.Body.Close()
	}
	return returned, persisted, bindErr
}

func TestBindFromOIDC_FirstLoginCreatesUserAndBindsSession(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	usrSvc := users.New(st)

	claims := auth.OIDCClaims{
		Subject:     "sub-first-login",
		Email:       "joe@example.com",
		DisplayName: "Joe",
	}
	id, persisted, err := runBindThroughHandler(t, st, usrSvc, claims, nil)
	if err != nil {
		t.Fatalf("BindFromOIDC: %v", err)
	}
	if id.Subject != "sub-first-login" {
		t.Errorf("Identity.Subject = %q, want sub-first-login", id.Subject)
	}
	if id.UserID == "" {
		t.Error("Identity.UserID is empty; expected a freshly-minted users.id")
	}
	if id.Email != "joe@example.com" {
		t.Errorf("Identity.Email = %q, want joe@example.com", id.Email)
	}
	if id.IsAdmin {
		t.Error("Identity.IsAdmin should be false when adminSubs is nil")
	}

	// BindFromOIDC's returned Identity MUST match what GetIdentity
	// reads back from the persisted session. A divergence here would
	// mean a future refactor wrote a different value to the session
	// than it returned to the caller -- silent data drift that the
	// per-field assertions above can't catch on their own.
	if persisted != id {
		t.Errorf("persisted Identity diverged from returned: persisted=%+v returned=%+v", persisted, id)
	}

	// Confirm the users row exists with the expected shape.
	u, err := usrSvc.GetByOIDCSubject(t.Context(), "sub-first-login")
	if err != nil {
		t.Fatalf("GetByOIDCSubject: %v", err)
	}
	if u.ID != id.UserID {
		t.Errorf("user.ID = %q, want %q", u.ID, id.UserID)
	}
}

func TestBindFromOIDC_SubsequentLoginReusesUserRow(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	usrSvc := users.New(st)

	first, _, err := runBindThroughHandler(t, st, usrSvc, auth.OIDCClaims{Subject: "sub-reuse"}, nil)
	if err != nil {
		t.Fatalf("first bind: %v", err)
	}
	second, _, err := runBindThroughHandler(t, st, usrSvc, auth.OIDCClaims{Subject: "sub-reuse"}, nil)
	if err != nil {
		t.Fatalf("second bind: %v", err)
	}
	if first.UserID != second.UserID {
		t.Errorf("UserID drifted across logins: first=%q second=%q", first.UserID, second.UserID)
	}
}

func TestBindFromOIDC_ComputesAdminFromAllowlist(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	usrSvc := users.New(st)
	adminSubs := []string{"sub-admin", "sub-other-admin"}

	admin, _, err := runBindThroughHandler(t, st, usrSvc, auth.OIDCClaims{Subject: "sub-admin"}, adminSubs)
	if err != nil {
		t.Fatalf("admin bind: %v", err)
	}
	if !admin.IsAdmin {
		t.Error("Identity.IsAdmin should be true for an allowlisted subject")
	}

	user, _, err := runBindThroughHandler(t, st, usrSvc, auth.OIDCClaims{Subject: "sub-regular"}, adminSubs)
	if err != nil {
		t.Fatalf("user bind: %v", err)
	}
	if user.IsAdmin {
		t.Error("Identity.IsAdmin should be false for a non-allowlisted subject")
	}
}

func TestBindFromOIDC_EmptyAllowlistEntryDoesNotPromoteEmptySubject(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	usrSvc := users.New(st)

	// A misconfigured OIDC_ADMIN_SUBS like "OIDC_ADMIN_SUBS=,sub-foo"
	// would parse into ["", "sub-foo"]. BindFromOIDC must NOT promote
	// a session whose subject happens to be empty, even if "" is in
	// the allowlist. The empty-subject case is also rejected by the
	// upstream guard (we won't get past Upsert), so this assertion is
	// belt-and-suspenders -- but the guard belongs in both places.
	if _, _, err := runBindThroughHandler(t, st, usrSvc, auth.OIDCClaims{Subject: ""}, []string{"", "sub-foo"}); err == nil {
		t.Fatal("BindFromOIDC accepted an empty subject")
	}
}

func TestBindFromOIDC_PreservesEmailWhenSubsequentClaimDrops(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	usrSvc := users.New(st)

	if _, _, err := runBindThroughHandler(t, st, usrSvc, auth.OIDCClaims{
		Subject: "sub-email-preserve",
		Email:   "first@example.com",
	}, nil); err != nil {
		t.Fatalf("first bind: %v", err)
	}

	// Second login drops the email claim. The Identity should still
	// see the preserved value (users.Service.Upsert is COALESCE-NULLIF).
	id, _, err := runBindThroughHandler(t, st, usrSvc, auth.OIDCClaims{Subject: "sub-email-preserve"}, nil)
	if err != nil {
		t.Fatalf("second bind: %v", err)
	}
	if id.Email != "first@example.com" {
		t.Errorf("Identity.Email = %q, want preserved first@example.com", id.Email)
	}
}

func TestBindFromOIDC_GuardsBadInput(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	usrSvc := users.New(st)

	if _, _, err := runBindThroughHandler(t, st, usrSvc, auth.OIDCClaims{}, nil); err == nil {
		t.Error("empty subject: expected error, got nil")
	}
	// nil session manager / db / users service guards are exercised
	// directly rather than through the handler, since the handler
	// can't supply a nil mgr (the LoadAndSave wrap would panic first).
	if _, err := auth.BindFromOIDC(t.Context(), nil, st.DB.DB, usrSvc, auth.OIDCClaims{Subject: "x"}, nil); err == nil {
		t.Error("nil mgr: expected error, got nil")
	}
}
