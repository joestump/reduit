// Tests for the credentials view and rotation handlers.
//
// Covers SPEC-0005 REQ "Per-User IMAP/SMTP Credentials":
//
//   - GET /accounts/{id}/credentials: owner → 200 with IMAP/SMTP details
//   - GET /accounts/{id}/credentials: unauthenticated → 302 to /auth/login
//   - GET /accounts/{id}/credentials: non-owner non-admin → 403
//   - POST /accounts/{id}/credentials/rotate: generates password, returns fragment
//   - POST /accounts/{id}/credentials/rotate: non-owner → 403
//
// The fixture reuses newWizardFixture from wizard_handlers_test.go.
//
// Governing: SPEC-0005 REQ "Per-User IMAP/SMTP Credentials".

package server_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
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

// noRedirectClient returns a cookie-jarred client that does NOT
// auto-follow redirects, so we can assert 302 responses directly.
func noRedirectClient(t *testing.T) *http.Client {
	t.Helper()
	c := newClient(t)
	// newClient already disables redirect following per its
	// CheckRedirect implementation.
	return c
}
