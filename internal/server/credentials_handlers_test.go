// Tests for the credentials view and rotation handlers.
//
// Covers SPEC-0005 REQ "Per-User IMAP/SMTP Credentials":
//
//   - GET /accounts/{id}/credentials: owner → 200 with IMAP/SMTP details
//   - GET /accounts/{id}/credentials: unauthenticated → 302 to /auth/login
//   - GET /accounts/{id}/credentials: non-owner non-admin → 403
//   - POST /accounts/{id}/credentials/rotate: generates password, returns fragment
//   - POST /accounts/{id}/credentials/rotate: non-owner → 403
//   - POST /accounts/{id}/credentials/rotate: suspended account → 409
//   - POST /accounts/{id}/credentials/rotate: soft-deleted account → 409
//   - POST /accounts/{id}/credentials/rotate: SMTP sessions dropped on success
//
// The fixture reuses newWizardFixture from wizard_handlers_test.go.
//
// Governing: SPEC-0005 REQ "Per-User IMAP/SMTP Credentials".

package server_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/joestump/reduit/internal/account"
	authoidc "github.com/joestump/reduit/internal/auth/oidc"
	"github.com/joestump/reduit/internal/auth/session"
	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/server"
	"github.com/joestump/reduit/internal/users"

	"log/slog"
	"net/http/httptest"
)

func TestCredentials_OwnerGetsPage(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-cred-owner", "joe@example.com", "Joe")
	id := f.seedActive(t, userID)

	resp, err := c.Get(f.url + "/accounts/" + id + "/credentials")
	if err != nil {
		t.Fatalf("GET /accounts/{id}/credentials: %v", err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	// Must show IMAP/SMTP section headings.
	if !strings.Contains(body, "IMAP") {
		t.Errorf("expected IMAP in credentials page; body excerpt=%s", body[:min(len(body), 600)])
	}
	if !strings.Contains(body, "SMTP") {
		t.Errorf("expected SMTP in credentials page; body excerpt=%s", body[:min(len(body), 600)])
	}
	// Password must NOT appear — only a rotate button.
	if strings.Contains(body, "data-imap-password") {
		t.Errorf("plaintext password leaked into credentials view; body excerpt=%s", body[:min(len(body), 600)])
	}
}

func TestCredentials_Unauthenticated_Redirects(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	_, userID := f.makeUser(t, "sub-cred-unauth", "joe@example.com", "Joe")
	id := f.seedActive(t, userID)

	// Bare client with no session cookie.
	bare := noRedirectClient(t)
	resp, err := bare.Get(f.url + "/accounts/" + id + "/credentials")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/auth/login") {
		t.Errorf("redirect location = %q, want /auth/login", loc)
	}
}

func TestCredentials_NonOwner_Forbidden(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	cA, _ := f.makeUser(t, "sub-cred-A", "a@example.com", "A")
	_, userB := f.makeUser(t, "sub-cred-B", "b@example.com", "B")
	idB := f.seedActive(t, userB)

	resp, err := cA.Get(f.url + "/accounts/" + idB + "/credentials")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestCredentials_RotateViaCanonicalURL(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-cred-rot", "joe@example.com", "Joe")
	id := f.seedActive(t, userID)

	resp := post(t, c, f.url+"/accounts/"+id+"/credentials/rotate", url.Values{})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "data-imap-password") {
		t.Errorf("expected password block in modal; body excerpt=%s", body[:min(len(body), 600)])
	}
	if !strings.Contains(body, "imap-rotate-dialog") {
		t.Errorf("expected modal dialog; body excerpt=%s", body[:min(len(body), 600)])
	}
	// Must be a fragment, not a full page.
	if strings.Contains(body, "<html") {
		t.Errorf("expected fragment, not full page; body excerpt=%s", body[:min(len(body), 600)])
	}
	// Password must now be set.
	got, _ := f.accSvc.GetByID(t.Context(), id)
	if !got.HasIMAPPassword {
		t.Errorf("HasIMAPPassword = false, want true after rotate")
	}
}

func TestCredentials_Rotate_NonOwner_Forbidden(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	cA, _ := f.makeUser(t, "sub-cred-rot-A", "a@example.com", "A")
	_, userB := f.makeUser(t, "sub-cred-rot-B", "b@example.com", "B")
	idB := f.seedActive(t, userB)

	resp := post(t, cA, f.url+"/accounts/"+idB+"/credentials/rotate", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	// Verify the rotation did NOT happen.
	got, _ := f.accSvc.GetByID(t.Context(), idB)
	if got.HasIMAPPassword {
		t.Errorf("password rotated by non-owner — ownership check broken")
	}
}

// TestCredentials_Rotate_SuspendedAccount_Conflict asserts that
// POST /accounts/{id}/credentials/rotate returns 409 when the account
// is in the suspended state. Issuing new credentials on a suspended
// account is incoherent because SASL auth is already halted.
//
// Governing: SPEC-0005 REQ "Per-User IMAP/SMTP Credentials".
func TestCredentials_Rotate_SuspendedAccount_Conflict(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-rot-susp", "susp@example.com", "Susp")
	id := f.seedActive(t, userID)
	// Transition to suspended before attempting rotation.
	if _, err := f.accSvc.Transition(t.Context(), id, account.StateSuspended); err != nil {
		t.Fatalf("transition suspended: %v", err)
	}

	resp := post(t, c, f.url+"/accounts/"+id+"/credentials/rotate", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409 for suspended account rotation", resp.StatusCode)
	}
	// The account must still have no password (rotation did not proceed).
	got, _ := f.accSvc.GetByID(t.Context(), id)
	if got.HasIMAPPassword {
		t.Errorf("password rotated for suspended account — state guard broken")
	}
}

// TestCredentials_Rotate_SoftDeletedAccount_Conflict asserts that
// POST /accounts/{id}/credentials/rotate returns 409 when the account
// is soft-deleted.
//
// Governing: SPEC-0005 REQ "Per-User IMAP/SMTP Credentials".
func TestCredentials_Rotate_SoftDeletedAccount_Conflict(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-rot-sdel", "sdel@example.com", "SDel")
	id := f.seedActive(t, userID)
	if _, err := f.accSvc.Delete(t.Context(), id); err != nil {
		t.Fatalf("delete account: %v", err)
	}

	resp := post(t, c, f.url+"/accounts/"+id+"/credentials/rotate", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409 for soft-deleted account rotation", resp.StatusCode)
	}
}

// fakeSessionDropper records DropForAccount calls so tests can assert
// that both IMAP and SMTP session registries are notified on rotation.
type fakeSessionDropper struct {
	mu    sync.Mutex
	drops []string // accountIDs passed to DropForAccount
}

func (f *fakeSessionDropper) DropForAccount(accountID, _ string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.drops = append(f.drops, accountID)
	return 0
}

func (f *fakeSessionDropper) dropped() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.drops))
	copy(out, f.drops)
	return out
}

// TestCredentials_Rotate_DropsIMAPAndSMTPSessions asserts that a
// successful rotation calls DropForAccount on both the IMAP and SMTP
// session registries so old credentials cannot be replayed on either
// protocol within 1s.
//
// Governing: SPEC-0005 REQ "Per-User IMAP/SMTP Credentials" — both
// IMAP and SMTP sessions dropped within 1s on rotation.
func TestCredentials_Rotate_DropsIMAPAndSMTPSessions(t *testing.T) {
	t.Parallel()

	// Build a standalone fixture with IMAPSessions + SMTPSessions wired.
	st := openTempStore(t)
	master, err := cryptenv.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	accSvc := account.New(st, master)
	usrSvc := users.New(st)
	idp := newFakeIdP(t, "reduit-test-client-sess")
	wizardSessions := server.NewWizardSessionStore(0)
	t.Cleanup(wizardSessions.Stop)

	mgr, cleanup, err := session.New(st.DB.DB, session.Options{Insecure: true})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	t.Cleanup(cleanup)

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	oidcClient, err := authoidc.New(ctx, authoidc.Config{
		IssuerURL:    idp.URL(),
		ClientID:     "reduit-test-client-sess",
		ClientSecret: "test-secret",
		RedirectURL:  srv.URL + "/auth/callback",
		Scopes:       []string{"openid", "profile", "email"},
	})
	if err != nil {
		t.Fatalf("authoidc.New: %v", err)
	}
	preSessions := authoidc.NewPreSessionStore(0)

	imapDropper := &fakeSessionDropper{}
	smtpDropper := &fakeSessionDropper{}

	deps := server.Deps{
		Store:           st,
		Logger:          slog.Default(),
		Version:         "test",
		SessionManager:  mgr,
		OIDC:            oidcClient,
		PreSessions:     preSessions,
		UsersService:    usrSvc,
		AccountService:  accSvc,
		WizardSessions:  wizardSessions,
		InsecureCookies: true,
		IMAPSessions:    imapDropper,
		SMTPSessions:    smtpDropper,
	}
	_, handler := server.NewForTest(deps)
	mux.Handle("/", handler)

	// Create and authenticate a user.
	c := loginAndFollow(t, srv.URL, idp, "sub-sess-drop", "drop@example.com", "Drop")
	u, err := usrSvc.GetByOIDCSubject(t.Context(), "sub-sess-drop")
	if err != nil {
		t.Fatalf("GetByOIDCSubject: %v", err)
	}

	a, err := accSvc.Create(t.Context(), account.CreateParams{
		UserID:       u.ID,
		ProtonUserID: "proton-drop",
		Email:        "drop@proton.me",
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	if _, err := accSvc.Transition(t.Context(), a.ID, account.StateActive); err != nil {
		t.Fatalf("transition active: %v", err)
	}

	resp := post(t, c, srv.URL+"/accounts/"+a.ID+"/credentials/rotate", url.Values{})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}

	// Both IMAP and SMTP registries must have received a drop call for
	// the rotated account.
	imapDrops := imapDropper.dropped()
	smtpDrops := smtpDropper.dropped()

	found := func(drops []string, id string) bool {
		for _, d := range drops {
			if d == id {
				return true
			}
		}
		return false
	}
	if !found(imapDrops, a.ID) {
		t.Errorf("IMAP DropForAccount not called for account %s; drops=%v", a.ID, imapDrops)
	}
	if !found(smtpDrops, a.ID) {
		t.Errorf("SMTP DropForAccount not called for account %s; drops=%v", a.ID, smtpDrops)
	}
}

// noRedirectClient returns a cookie-jarred client that does NOT
// auto-follow redirects, so we can assert 302 responses directly.
func noRedirectClient(t *testing.T) *http.Client {
	t.Helper()
	c := newClient(t)
	// newClient already disables redirect following per its
	// CheckRedirect implementation.
	return c
}
