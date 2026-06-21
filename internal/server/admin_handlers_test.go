// Tests for the admin account management handlers.
//
// Covers SPEC-0005 REQ "Admin Account Management":
//
//   - GET /admin/accounts: admin → 200 with all accounts
//   - GET /admin/accounts: non-admin → 403
//   - POST /admin/accounts/{id}/suspend: admin → state suspended
//   - POST /admin/accounts/{id}/suspend: non-admin → 403
//   - POST /admin/accounts/{id}/unsuspend: admin → state active
//   - POST /admin/accounts/{id}/unsuspend: non-admin → 403
//   - POST /admin/accounts/{id}/delete: admin → state soft_deleted
//   - POST /admin/accounts/{id}/delete: non-admin → 403
//
// Governing: SPEC-0005 REQ "Admin Account Management".

package server_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/notify"
	"github.com/joestump/reduit/internal/store"
	"github.com/joestump/reduit/internal/users"
)

// adminFixture wires a test server with a named admin subject and
// two users: an admin and a regular user. The admin's cookie-jarred
// client is pre-authenticated.
type adminFixture struct {
	baseURL    string
	idp        *fakeIdP
	accSvc     account.Service
	usrSvc     users.Service
	notifySvc  notify.Service
	st         *store.Store
	adminSub   string
	adminEmail string
}

// newAdminFixture creates a test server with "sub-siteadmin" as the
// admin OIDC subject. It builds the server stack inline (rather than
// via dashboardTestServer) so the fixture can hold the *store.Store and
// a notify.Service for seeding admin notifications -- the server's own
// notify.Service is built against the SAME store, so a row seeded via
// the fixture's service is visible to the admin page.
func newAdminFixture(t *testing.T) *adminFixture {
	t.Helper()
	const adminSub = "sub-siteadmin"
	const adminEmail = "admin@example.com"

	st := openTempStore(t)
	master, err := cryptenv.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	accSvc := account.New(st, master)
	usrSvc := users.New(st)

	idp := newFakeIdP(t, "reduit-test-client")
	baseURL := mountTestServer(t, st, idp, []string{adminSub}, accSvc, usrSvc)
	return &adminFixture{
		baseURL:    baseURL,
		idp:        idp,
		accSvc:     accSvc,
		usrSvc:     usrSvc,
		notifySvc:  notify.New(st),
		st:         st,
		adminSub:   adminSub,
		adminEmail: adminEmail,
	}
}

// adminClient returns a cookie-jarred client authenticated as the
// admin subject.
func (f *adminFixture) adminClient(t *testing.T) *http.Client {
	t.Helper()
	return loginAndFollow(t, f.baseURL, f.idp, f.adminSub, f.adminEmail, "Admin")
}

// userClient returns a cookie-jarred client authenticated as a non-
// admin user with the given subject/email.
func (f *adminFixture) userClient(t *testing.T, sub, email string) *http.Client {
	t.Helper()
	return loginAndFollow(t, f.baseURL, f.idp, sub, email, "User")
}

// seedActiveForSubject upserts a users row for the given OIDC subject
// and creates an active account for it. Returns the account ID.
func (f *adminFixture) seedActiveForSubject(t *testing.T, sub, email string) string {
	t.Helper()
	ctx := context.Background()
	u, err := f.usrSvc.Upsert(ctx, users.UpsertParams{OIDCSubject: sub, Email: email})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	a, err := f.accSvc.Create(ctx, account.CreateParams{
		UserID:       u.ID,
		ProtonUserID: "proton-" + sub[:8],
		Email:        email,
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	if _, err := f.accSvc.Transition(ctx, a.ID, account.StateActive); err != nil {
		t.Fatalf("transition active: %v", err)
	}
	return a.ID
}

// --- GET /admin/accounts -----------------------------------------

func TestAdminAccounts_AdminGetsPage(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(t)
	f.seedActiveForSubject(t, "sub-user1", "user1@example.com")
	f.seedActiveForSubject(t, f.adminSub, f.adminEmail)

	c := f.adminClient(t)
	status, body := fetch(t, c, f.baseURL+"/admin/accounts")
	if status != http.StatusOK {
		t.Fatalf("status = %d, body=%s", status, body[:min(len(body), 600)])
	}
	// Admin management page title.
	if !strings.Contains(body, "All accounts") {
		t.Errorf("admin accounts page missing 'All accounts' heading; body excerpt=%s", body[:min(len(body), 600)])
	}
}

func TestAdminAccounts_NonAdminForbidden(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(t)

	c := f.userClient(t, "sub-nonadmin", "nonadmin@example.com")
	resp, err := c.Get(f.baseURL + "/admin/accounts")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

// --- POST /admin/accounts/{id}/suspend ---------------------------

func TestAdminSuspend_AdminSuspendsAccount(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(t)
	id := f.seedActiveForSubject(t, "sub-victim-susp", "victim@example.com")

	c := f.adminClient(t)
	resp := post(t, c, f.baseURL+"/admin/accounts/"+id+"/suspend", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	got, err := f.accSvc.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.State != account.StateSuspended {
		t.Errorf("state = %s, want suspended", got.State)
	}
}

func TestAdminSuspend_NonAdminForbidden(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(t)
	id := f.seedActiveForSubject(t, "sub-victim-susp2", "victim2@example.com")

	c := f.userClient(t, "sub-attacker", "attacker@example.com")
	resp := post(t, c, f.baseURL+"/admin/accounts/"+id+"/suspend", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	// State must be unchanged.
	got, _ := f.accSvc.GetByID(context.Background(), id)
	if got.State != account.StateActive {
		t.Errorf("state = %s after non-admin suspend attempt, want active", got.State)
	}
}

// --- POST /admin/accounts/{id}/unsuspend -------------------------

func TestAdminUnsuspend_AdminUnsuspendsAccount(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(t)
	id := f.seedActiveForSubject(t, "sub-victim-unsup", "victim3@example.com")
	if _, err := f.accSvc.Transition(context.Background(), id, account.StateSuspended); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	c := f.adminClient(t)
	resp := post(t, c, f.baseURL+"/admin/accounts/"+id+"/unsuspend", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	got, err := f.accSvc.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.State != account.StateActive {
		t.Errorf("state = %s, want active", got.State)
	}
}

func TestAdminUnsuspend_NonAdminForbidden(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(t)
	id := f.seedActiveForSubject(t, "sub-victim-unsup2", "victim4@example.com")
	if _, err := f.accSvc.Transition(context.Background(), id, account.StateSuspended); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	c := f.userClient(t, "sub-attacker2", "attacker2@example.com")
	resp := post(t, c, f.baseURL+"/admin/accounts/"+id+"/unsuspend", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

// --- POST /admin/accounts/{id}/delete ----------------------------

func TestAdminDelete_AdminSoftDeletesAccount(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(t)
	id := f.seedActiveForSubject(t, "sub-victim-del", "victim5@example.com")

	c := f.adminClient(t)
	resp := post(t, c, f.baseURL+"/admin/accounts/"+id+"/delete", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	got, err := f.accSvc.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.State != account.StateSoftDeleted {
		t.Errorf("state = %s, want soft_deleted", got.State)
	}
}

func TestAdminDelete_NonAdminForbidden(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(t)
	id := f.seedActiveForSubject(t, "sub-victim-del2", "victim6@example.com")

	c := f.userClient(t, "sub-attacker3", "attacker3@example.com")
	resp := post(t, c, f.baseURL+"/admin/accounts/"+id+"/delete", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	got, _ := f.accSvc.GetByID(context.Background(), id)
	if got.State != account.StateActive {
		t.Errorf("state = %s after non-admin delete attempt, want active", got.State)
	}
}

// TestAdminSuspend_MissingAccount_404 ensures the admin endpoint
// returns 404 for an unknown account ID, not 403.
func TestAdminSuspend_MissingAccount_404(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(t)

	c := f.adminClient(t)
	resp := post(t, c, f.baseURL+"/admin/accounts/does-not-exist/suspend", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// TestAdminSuspend_AlreadySuspended_409 ensures the endpoint returns
// 409 on an invalid transition attempt.
func TestAdminSuspend_AlreadySuspended_409(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(t)
	id := f.seedActiveForSubject(t, "sub-already-susp", "alreadysusp@example.com")
	if _, err := f.accSvc.Transition(context.Background(), id, account.StateSuspended); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	c := f.adminClient(t)
	resp := post(t, c, f.baseURL+"/admin/accounts/"+id+"/suspend", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
}

// --- Admin notifications -----------------------------------------

// TestAdminNotifications_BannerRendersUnacknowledged pins that a
// recorded admin notification surfaces on the admin accounts page.
//
// Governing: SPEC-0002 REQ "Panic Isolation" (worker crash surfaces to
// the operator), SPEC-0002 REQ "Backoff on Failure" (auto-revert).
func TestAdminNotifications_BannerRendersUnacknowledged(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(t)
	id := f.seedActiveForSubject(t, "sub-notif-user", "notif@example.com")

	if _, err := f.notifySvc.Record(context.Background(), id,
		notify.KindWorkerCrashed,
		"Sync worker crashed and was stopped; clear the crashed flag to retry.",
		"panic: boom"); err != nil {
		t.Fatalf("Record: %v", err)
	}

	c := f.adminClient(t)
	status, body := fetch(t, c, f.baseURL+"/admin/accounts")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if !strings.Contains(body, "Attention required") {
		t.Errorf("notification banner heading missing; body excerpt=%s", body[:min(len(body), 800)])
	}
	if !strings.Contains(body, "Worker crashed") {
		t.Errorf("notification kind label missing from banner")
	}
	if !strings.Contains(body, "clear the crashed flag to retry") {
		t.Errorf("notification message missing from banner")
	}
}

// TestAdminNotifications_DismissAcknowledges pins the dismiss flow: a
// POST to the ack route acknowledges the notification (303) and it no
// longer renders on the page.
func TestAdminNotifications_DismissAcknowledges(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(t)
	id := f.seedActiveForSubject(t, "sub-notif-dismiss", "dismiss@example.com")

	n, err := f.notifySvc.Record(context.Background(), id,
		notify.KindAutoReverted, "reverted to setup", "401")
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	c := f.adminClient(t)
	resp := post(t, c, f.baseURL+"/admin/notifications/"+n.ID+"/ack", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("ack status = %d, want 303", resp.StatusCode)
	}

	// Acknowledged: gone from the unacknowledged set.
	count, err := f.notifySvc.CountUnacknowledged(context.Background())
	if err != nil {
		t.Fatalf("CountUnacknowledged: %v", err)
	}
	if count != 0 {
		t.Errorf("CountUnacknowledged = %d after ack, want 0", count)
	}

	// And no longer on the page.
	status, body := fetch(t, c, f.baseURL+"/admin/accounts")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if strings.Contains(body, "Attention required") {
		t.Errorf("notification banner still present after dismiss")
	}
}

// TestAdminNotifications_DismissNonAdminForbidden pins that a non-admin
// cannot acknowledge a notification (the ack route is RequireAdmin).
func TestAdminNotifications_DismissNonAdminForbidden(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(t)
	id := f.seedActiveForSubject(t, "sub-notif-victim", "nvictim@example.com")
	n, err := f.notifySvc.Record(context.Background(), id,
		notify.KindWorkerCrashed, "crashed", "")
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	c := f.userClient(t, "sub-notif-attacker", "nattacker@example.com")
	resp := post(t, c, f.baseURL+"/admin/notifications/"+n.ID+"/ack", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	// Still unacknowledged.
	count, _ := f.notifySvc.CountUnacknowledged(context.Background())
	if count != 1 {
		t.Errorf("CountUnacknowledged = %d after forbidden ack, want 1", count)
	}
}

// --- Password rotation (unit-level) ------------------------------

// TestRotateIMAPPassword_HashStoredAndPlaintextReturned verifies the
// service-level behaviour: rotate returns a non-empty base32 plaintext,
// subsequent verification against the stored hash succeeds.
func TestRotateIMAPPassword_HashStoredAndPlaintextReturned(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	master, err := cryptenv.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	svc := account.New(st, master)
	ctx := context.Background()

	usersSvc := users.New(st)
	u, err := usersSvc.Upsert(ctx, users.UpsertParams{OIDCSubject: "sub-rot-unit"})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	a, err := svc.Create(ctx, account.CreateParams{
		UserID:       u.ID,
		ProtonUserID: "p-rot",
		Email:        "rot@proton.me",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	plaintext, err := svc.RotateIMAPPassword(ctx, a.ID)
	if err != nil {
		t.Fatalf("RotateIMAPPassword: %v", err)
	}
	if len(plaintext) == 0 {
		t.Fatal("RotateIMAPPassword returned empty plaintext")
	}
	// base32 alphabet only (A-Z, 2-7 for NoPadding, 32 chars from 20 bytes).
	const expectedLen = 32
	if len(plaintext) != expectedLen {
		t.Errorf("plaintext length = %d, want %d", len(plaintext), expectedLen)
	}

	// Verify the stored hash matches the returned plaintext.
	if err := svc.VerifyIMAPPassword(ctx, a.ID, []byte(plaintext)); err != nil {
		t.Errorf("VerifyIMAPPassword: %v", err)
	}

	// Rotate a second time — the ciphertext must change (the new
	// plaintext is different from the first).
	plaintext2, err := svc.RotateIMAPPassword(ctx, a.ID)
	if err != nil {
		t.Fatalf("RotateIMAPPassword (2nd): %v", err)
	}
	if plaintext2 == plaintext {
		t.Error("second rotation returned same plaintext as first — entropy source may be broken")
	}
	// First password must no longer verify.
	if err := svc.VerifyIMAPPassword(ctx, a.ID, []byte(plaintext)); err == nil {
		t.Error("old password still verifies after rotation")
	}
}
