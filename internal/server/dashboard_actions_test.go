// Tests for the dashboard's per-account action handlers.
//
// Covers SPEC-0005 REQ "Account Dashboard" Scenario "User manages
// account state":
//
//   - Discard (soft-delete) on active and suspended cards.
//   - Suspend on active cards (active -> suspended).
//   - Reactivate on suspended cards (suspended -> active).
//   - Rotate IMAP password returns the plaintext fragment for one-
//     time display.
//   - Cross-user isolation: a session bound to user A cannot Discard /
//     Suspend / Reactivate / Rotate user B's accounts (403).
//
// The fixture reuses newWizardFixture from wizard_handlers_test.go --
// it already wires the full middleware chain + AccountService and
// gives us a per-test httptest server.
//
// Governing: SPEC-0005 REQ "Account Dashboard"; issues #102, #103.

package server_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/joestump/reduit/internal/account"
)

// seedActive provisions a fresh active account for the bound user.
// Returns the account ID. Used by every action test that needs an
// existing target.
func (f *wizardFixture) seedActive(t *testing.T, userID string) string {
	t.Helper()
	a, err := f.accSvc.Create(t.Context(), account.CreateParams{
		UserID:       userID,
		ProtonUserID: "proton-user-" + userID[:8],
		Email:        "joe@protonmail.com",
	})
	if err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if _, err := f.accSvc.Transition(t.Context(), a.ID, account.StateActive); err != nil {
		t.Fatalf("transition active: %v", err)
	}
	return a.ID
}

func TestDashboardAction_Delete_SoftDeletes(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-act-del", "joe@example.com", "Joe")
	id := f.seedActive(t, userID)

	resp := post(t, c, f.url+"/accounts/"+id+"/delete", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/accounts" {
		t.Errorf("redirect = %q, want /accounts", got)
	}
	got, err := f.accSvc.GetByID(t.Context(), id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.State != account.StateSoftDeleted {
		t.Errorf("state = %s, want soft_deleted", got.State)
	}
}

func TestDashboardAction_Suspend_TransitionsActiveToSuspended(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-act-susp", "joe@example.com", "Joe")
	id := f.seedActive(t, userID)

	resp := post(t, c, f.url+"/accounts/"+id+"/suspend", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	got, _ := f.accSvc.GetByID(t.Context(), id)
	if got.State != account.StateSuspended {
		t.Errorf("state = %s, want suspended", got.State)
	}
}

func TestDashboardAction_Reactivate_TransitionsSuspendedToActive(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-act-react", "joe@example.com", "Joe")
	id := f.seedActive(t, userID)
	if _, err := f.accSvc.Transition(t.Context(), id, account.StateSuspended); err != nil {
		t.Fatalf("transition suspend: %v", err)
	}

	resp := post(t, c, f.url+"/accounts/"+id+"/reactivate", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	got, _ := f.accSvc.GetByID(t.Context(), id)
	if got.State != account.StateActive {
		t.Errorf("state = %s, want active", got.State)
	}
}

func TestDashboardAction_RotateIMAP_ReturnsPlaintextFragment(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-act-rot", "joe@example.com", "Joe")
	id := f.seedActive(t, userID)

	resp := post(t, c, f.url+"/accounts/"+id+"/imap-password/rotate", url.Values{})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "data-imap-password") {
		t.Errorf("expected password block; body excerpt=%s", body[:min(len(body), 600)])
	}
	if !strings.Contains(body, "imap-rotate-dialog") {
		t.Errorf("expected modal dialog id; body excerpt=%s", body[:min(len(body), 600)])
	}
	if !strings.Contains(body, "modal-host") {
		t.Errorf("expected modal-host wrapper for HTMX swap; body excerpt=%s", body[:min(len(body), 600)])
	}

	// The returned fragment should NOT carry the chrome (no <html>,
	// no left rail) -- it is a partial swap target.
	if strings.Contains(body, "<html") {
		t.Errorf("expected fragment, not full page; body excerpt=%s", body[:min(len(body), 600)])
	}

	// And the persisted hash actually rotated.
	got, _ := f.accSvc.GetByID(t.Context(), id)
	if !got.HasIMAPPassword {
		t.Errorf("HasIMAPPassword = false, want true")
	}
}

func TestDashboardAction_CrossUser_Forbidden(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	cA, userA := f.makeUser(t, "sub-cross-A", "a@example.com", "A")
	_, userB := f.makeUser(t, "sub-cross-B", "b@example.com", "B")
	idB := f.seedActive(t, userB)

	// userA hits userB's account on every action route. All four
	// must 403 (or 404 if the handler chooses to obscure existence;
	// our implementation returns 403).
	for _, path := range []string{"/delete", "/suspend", "/reactivate", "/imap-password/rotate"} {
		resp := post(t, cA, f.url+"/accounts/"+idB+path, url.Values{})
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s cross-user status = %d, want 403", path, resp.StatusCode)
		}
	}

	// userA's lack of authority must NOT have changed userB's state.
	gotB, _ := f.accSvc.GetByID(t.Context(), idB)
	if gotB.State != account.StateActive {
		t.Errorf("userB account state = %s after cross-user attempts, want active", gotB.State)
	}
	if gotB.HasIMAPPassword {
		t.Errorf("userB IMAP password rotated by userA -- ownership check broken")
	}
	_ = userA
}

func TestDashboardAction_MissingAccount_404(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, _ := f.makeUser(t, "sub-act-404", "joe@example.com", "Joe")

	resp := post(t, c, f.url+"/accounts/does-not-exist/suspend", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestDashboardAction_Suspend_AlreadySuspended_409(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-act-409", "joe@example.com", "Joe")
	id := f.seedActive(t, userID)
	if _, err := f.accSvc.Transition(t.Context(), id, account.StateSuspended); err != nil {
		t.Fatalf("transition: %v", err)
	}

	resp := post(t, c, f.url+"/accounts/"+id+"/suspend", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
}
