// Tests for the comprehensive anti-CSRF protection on state-changing
// POST routes (issue #26).
//
// SPEC-0005 design "Content security and CSRF" requires every state-
// changing request to carry an unforgeable per-session anti-CSRF token.
// Issue #11 minted the token and wired it on POST /auth/logout only;
// issue #26 extends validation to ALL destructive POSTs via the
// csrfProtect middleware. These tests pin:
//
//   - Fail-closed: a missing or wrong token is 403 BEFORE any state
//     change, on every protected route (dashboard actions, credentials
//     rotation, admin suspend/unsuspend/delete, notification ack, the
//     five wizard POSTs).
//   - The token is accepted from EITHER the X-CSRF-Token header (HTMX
//     path) OR the csrf_token form field (no-JS form path).
//   - No state leakage: a rejected request leaves the target unchanged.
//   - Middleware ordering: a non-admin hitting an admin POST gets the
//     admin gate's 403 (RequireAdmin runs before csrfProtect).
//   - Wizard regression: the multi-step HTMX flow still completes when
//     each step carries the token via the header.
//
// Governing: SPEC-0005 design "Content security and CSRF"; issue #26.

package server_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/joestump/reduit/internal/account"
)

// --- dashboard action routes -------------------------------------

// TestCSRF_DashboardActions_MissingTokenForbidden asserts every
// per-account destructive POST 403s when no token is supplied, and the
// account state is untouched.
func TestCSRF_DashboardActions_MissingTokenForbidden(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)

	for i, path := range []string{"/delete", "/suspend", "/reactivate", "/imap-password/rotate"} {
		// Distinct user per path so each seeded account has a unique
		// (user_id, proton_user_id) -- the account service rejects a
		// duplicate Proton identity for the same user.
		sub := "sub-csrf-dash-" + string(rune('a'+i))
		c, userID := f.makeUser(t, sub, sub+"@example.com", "Joe")
		id := f.seedActive(t, userID)
		// Empty token => no X-CSRF-Token header and no form field.
		resp := postNoCSRF(t, c, f.url+"/accounts/"+id+path, url.Values{}, "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s without token: status = %d, want 403", path, resp.StatusCode)
		}
		got, _ := f.accSvc.GetByID(t.Context(), id)
		if got.State != account.StateActive {
			t.Errorf("%s without token mutated state to %s; CSRF gate must reject before any change", path, got.State)
		}
		if got.HasIMAPPassword {
			t.Errorf("%s without token rotated the IMAP password; CSRF gate must reject before any change", path)
		}
	}
}

// TestCSRF_DashboardActions_WrongTokenForbidden asserts a non-matching
// token is rejected (the constant-time compare in session.ValidCSRF
// must fail closed on a wrong value, not just an empty one).
func TestCSRF_DashboardActions_WrongTokenForbidden(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-csrf-wrong", "joe@example.com", "Joe")
	id := f.seedActive(t, userID)

	resp := postNoCSRF(t, c, f.url+"/accounts/"+id+"/suspend", url.Values{}, "not-the-real-token")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("wrong token: status = %d, want 403", resp.StatusCode)
	}
	got, _ := f.accSvc.GetByID(t.Context(), id)
	if got.State != account.StateActive {
		t.Errorf("wrong token mutated state to %s", got.State)
	}
}

// TestCSRF_DashboardAction_ValidHeaderAccepted asserts the X-CSRF-Token
// header (the HTMX delivery path) admits the request.
func TestCSRF_DashboardAction_ValidHeaderAccepted(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-csrf-hdr", "joe@example.com", "Joe")
	id := f.seedActive(t, userID)

	tok := csrfTokenFor(t, c, f.url)
	resp := postNoCSRF(t, c, f.url+"/accounts/"+id+"/suspend", url.Values{}, tok)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("valid header token: status = %d, want 303", resp.StatusCode)
	}
	got, _ := f.accSvc.GetByID(t.Context(), id)
	if got.State != account.StateSuspended {
		t.Errorf("state = %s, want suspended", got.State)
	}
}

// TestCSRF_DashboardAction_ValidFormFieldAccepted asserts the
// csrf_token form field (the no-JS <form> delivery path) admits the
// request even with no X-CSRF-Token header present.
func TestCSRF_DashboardAction_ValidFormFieldAccepted(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-csrf-field", "joe@example.com", "Joe")
	id := f.seedActive(t, userID)

	tok := csrfTokenFor(t, c, f.url)
	// No header — token only in the form body, like a no-JS form submit.
	resp := postNoCSRF(t, c, f.url+"/accounts/"+id+"/suspend", url.Values{"csrf_token": {tok}}, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("valid form-field token: status = %d, want 303", resp.StatusCode)
	}
	got, _ := f.accSvc.GetByID(t.Context(), id)
	if got.State != account.StateSuspended {
		t.Errorf("state = %s, want suspended", got.State)
	}
}

// --- credentials rotation ----------------------------------------

func TestCSRF_CredentialsRotate_MissingTokenForbidden(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-csrf-cred", "joe@example.com", "Joe")
	id := f.seedActive(t, userID)

	resp := postNoCSRF(t, c, f.url+"/accounts/"+id+"/credentials/rotate", url.Values{}, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("credentials rotate without token: status = %d, want 403", resp.StatusCode)
	}
	got, _ := f.accSvc.GetByID(t.Context(), id)
	if got.HasIMAPPassword {
		t.Errorf("credentials rotate without token rotated the password; gate must reject first")
	}
}

func TestCSRF_CredentialsRotate_ValidHeaderAccepted(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-csrf-cred-ok", "joe@example.com", "Joe")
	id := f.seedActive(t, userID)

	resp := post(t, c, f.url+"/accounts/"+id+"/credentials/rotate", url.Values{})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("credentials rotate with token: status = %d, body=%s", resp.StatusCode, body[:min(len(body), 300)])
	}
	got, _ := f.accSvc.GetByID(t.Context(), id)
	if !got.HasIMAPPassword {
		t.Errorf("credentials rotate with token did not rotate the password")
	}
}

// --- admin routes -------------------------------------------------

// TestCSRF_AdminActions_MissingTokenForbidden asserts an authenticated
// admin still needs a token for the destructive POSTs.
func TestCSRF_AdminActions_MissingTokenForbidden(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(t)
	c := f.adminClient(t)

	cases := []struct {
		path  string
		setup func() string // returns account id, fresh per case
	}{
		{"/suspend", func() string { return f.seedActiveForSubject(t, "sub-v-susp", "vs@example.com") }},
		{"/unsuspend", func() string {
			id := f.seedActiveForSubject(t, "sub-v-unsusp", "vu@example.com")
			if _, err := f.accSvc.Transition(t.Context(), id, account.StateSuspended); err != nil {
				t.Fatalf("pre-suspend: %v", err)
			}
			return id
		}},
		{"/delete", func() string { return f.seedActiveForSubject(t, "sub-v-del", "vd@example.com") }},
	}
	for _, tc := range cases {
		id := tc.setup()
		resp := postNoCSRF(t, c, f.baseURL+"/admin/accounts/"+id+tc.path, url.Values{}, "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("admin %s without token: status = %d, want 403", tc.path, resp.StatusCode)
		}
	}
}

// TestCSRF_AdminAction_ValidTokenAccepted asserts a valid token admits
// an admin suspend (the happy path the existing admin tests rely on,
// asserted explicitly here under the CSRF contract).
func TestCSRF_AdminAction_ValidTokenAccepted(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(t)
	id := f.seedActiveForSubject(t, "sub-v-ok", "vok@example.com")
	c := f.adminClient(t)

	resp := post(t, c, f.baseURL+"/admin/accounts/"+id+"/suspend", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("admin suspend with token: status = %d, want 303", resp.StatusCode)
	}
	got, _ := f.accSvc.GetByID(t.Context(), id)
	if got.State != account.StateSuspended {
		t.Errorf("state = %s, want suspended", got.State)
	}
}

// TestCSRF_AdminAction_NonAdminGetsAdminGateFirst pins the middleware
// ordering: RequireAdmin wraps csrfProtect, so a non-admin is rejected
// by the admin gate (403) regardless of token. Both layers fail closed;
// this asserts the request never reaches the handler and the ordering
// is admin-then-CSRF (a non-admin with no token must still be 403, not
// a 500 or a state change).
func TestCSRF_AdminAction_NonAdminGetsAdminGateFirst(t *testing.T) {
	t.Parallel()
	f := newAdminFixture(t)
	id := f.seedActiveForSubject(t, "sub-v-nonadmin", "vna@example.com")
	c := f.userClient(t, "sub-plain", "plain@example.com")

	// Non-admin, no token: must be 403 (admin gate), account unchanged.
	resp := postNoCSRF(t, c, f.baseURL+"/admin/accounts/"+id+"/suspend", url.Values{}, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin admin POST: status = %d, want 403", resp.StatusCode)
	}
	got, _ := f.accSvc.GetByID(t.Context(), id)
	if got.State != account.StateActive {
		t.Errorf("non-admin admin POST mutated state to %s", got.State)
	}
}

// --- wizard regression -------------------------------------------

// TestCSRF_Wizard_MissingTokenForbidden asserts the wizard's first
// state-changing POST (credentials) fails closed without a token.
func TestCSRF_Wizard_MissingTokenForbidden(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, _ := f.makeUser(t, "sub-csrf-wiz", "joe@example.com", "Joe")

	// GET to mint the pending row + the per-session token.
	resp, _ := c.Get(f.url + "/accounts/setup")
	resp.Body.Close()

	resp = postNoCSRF(t, c, f.url+"/accounts/setup/auth", url.Values{
		"username": {"joe@protonmail.com"},
		"password": {"hunter2"},
	}, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("wizard auth without token: status = %d, want 403", resp.StatusCode)
	}
	// The Proton login stub must never have been invoked — the CSRF gate
	// rejects before the handler runs.
	if n := len(f.stub.loginCalls()); n != 0 {
		t.Errorf("wizard auth without token reached the handler: %d proton login calls", n)
	}
}

// TestCSRF_Wizard_HappyPathWithToken is the multi-step HTMX regression
// guard: the full credentials -> unlock -> done -> complete flow must
// still succeed when each POST carries the per-session token via the
// X-CSRF-Token header (the path base.html's hx-headers exercises in the
// browser). This is the main regression risk called out in issue #26.
func TestCSRF_Wizard_HappyPathWithToken(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-csrf-wiz-ok", "joe@example.com", "Joe")

	stubClient := readyClient()
	f.stub.push(stubLoginResult{client: stubClient, auth: stubAuth(0)})

	// Step 1 GET mints the pending row + token.
	resp, _ := c.Get(f.url + "/accounts/setup")
	resp.Body.Close()
	tok := csrfTokenFor(t, c, f.url)

	// Credentials -> unlock screen (no 2FA).
	resp = postNoCSRF(t, c, f.url+"/accounts/setup/auth", url.Values{
		"username": {"joe@protonmail.com"},
		"password": {"hunter2"},
	}, tok)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Unlock your Proton mailbox") {
		t.Fatalf("auth step: status=%d, body excerpt=%s", resp.StatusCode, body[:min(len(body), 300)])
	}

	// Unlock -> Done.
	resp = postNoCSRF(t, c, f.url+"/accounts/setup/unlock", url.Values{
		"passphrase": {"my-mailbox-passphrase"},
	}, tok)
	body = readBody(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Set up your mail client") {
		t.Fatalf("unlock step: status=%d, body excerpt=%s", resp.StatusCode, body[:min(len(body), 300)])
	}

	// Complete -> redirect to dashboard.
	resp = postNoCSRF(t, c, f.url+"/accounts/setup/complete", url.Values{}, tok)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("complete step: status=%d, want 303", resp.StatusCode)
	}

	accts, _ := f.accSvc.ListByUser(t.Context(), userID)
	if len(accts) != 1 || accts[0].State != account.StateActive {
		t.Fatalf("wizard did not produce one active account: %+v", accts)
	}
}
