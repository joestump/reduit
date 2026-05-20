// Snapshot tests for the OIDC login flow and accounts dashboard.
//
// "Snapshot" here means structural string assertions against rendered
// HTTP responses rather than golden-file diffing. The assertions are
// intentionally coarse — they pin the response shape so a future
// refactor that accidentally changes the structure (e.g., leaks IdP
// error detail in a 401 body, drops the title element, or swaps the
// redirect target) fails immediately with a clear assertion message.
//
// Golden-file diffing (testdata/snapshots/) is deferred until the UI
// stabilises post-alpha. The markers chosen here survive minor HTML
// whitespace / attribute-order churn while still catching regressions.
//
// Governing: SPEC-0005 REQ "OIDC Login Flow", SPEC-0005 REQ
// "Authentication Gating".

package server_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestSnapshotLoginRedirect pins the /auth/login response shape:
//   - HTTP 302 (not a rendered page — login is a redirect-only handler)
//   - Location points at the IdP's /authorize endpoint
//   - __Host-Reduit-Bind cookie is set (PKCE bind)
//
// The test does NOT follow the redirect; it treats the 302 itself as
// the snapshot surface so a regression that turns login into a rendered
// HTML page (wrong) is immediately visible.
//
// Governing: SPEC-0005 REQ "OIDC Login Flow".
func TestSnapshotLoginRedirect(t *testing.T) {
	t.Parallel()
	baseURL, idp, _ := newTestServer(t, nil)
	c := newClient(t)

	resp, err := c.Get(baseURL + "/auth/login")
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	defer resp.Body.Close()

	// Snapshot: must be a redirect, not a rendered page.
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 302; body=%s", resp.StatusCode, body)
	}

	// Snapshot: Location must target the fake IdP's /authorize endpoint.
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, idp.URL()+"/authorize") {
		t.Errorf("Location = %q, want IdP /authorize prefix (%s/authorize)", loc, idp.URL())
	}

	// Snapshot: the PKCE bind cookie must be present.
	// TestAuthLogin_RedirectsToIdPWithBindCookie covers this in depth;
	// here we assert its existence as part of the snapshot contract so
	// this test stands alone as a full response-shape check.
	var hasBind bool
	for _, ck := range resp.Cookies() {
		if ck.Name == "__Host-Reduit-Bind" {
			hasBind = true
			break
		}
	}
	if !hasBind {
		t.Error("snapshot: __Host-Reduit-Bind cookie absent from /auth/login response")
	}

	// Snapshot: the authorization URL must carry the PKCE + state params.
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	q := u.Query()
	for _, k := range []string{"state", "code_challenge", "nonce"} {
		if q.Get(k) == "" {
			t.Errorf("snapshot: authorization URL missing %q param (Location=%q)", k, loc)
		}
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("snapshot: code_challenge_method = %q, want S256", got)
	}
}

// TestSnapshotOIDCErrorPage pins the OIDC error response shape:
//   - HTTP 401 (uniform; not 400, not 500)
//   - Body contains "unauthorized" (the callbackUnauthorized sentinel)
//   - Body does NOT reflect any IdP-supplied error_description
//
// The snapshot is intentionally minimal so it survives body-text
// rewording. What matters is the status code and the absence of
// oracle-leaking IdP detail — those two properties protect against the
// security-relevant regression of exposing error_description to callers.
//
// Note: TestOIDCError_CallbackWithIdPError in oidc_login_flow_test.go
// covers the same scenario end-to-end. This test duplicates the
// assertions here under the "snapshot" namespace so a future
// snapshot-infra migration (golden-file vs. string) has a single clear
// anchor point.
//
// Governing: SPEC-0005 REQ "OIDC Login Flow".
func TestSnapshotOIDCErrorPage(t *testing.T) {
	t.Parallel()
	baseURL, _, _ := newTestServer(t, nil)
	c := newClient(t)

	// IdP returns ?error=access_denied with a human-readable description.
	// The callback receives no code or state, so it rejects the request
	// at the "missing state or code" check.
	resp, err := c.Get(baseURL + "/auth/callback?error=access_denied&error_description=User+denied+consent")
	if err != nil {
		t.Fatalf("GET /auth/callback: %v", err)
	}
	defer resp.Body.Close()

	// Snapshot: status must be 401 — not 400, not 500, not a redirect.
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("snapshot: status = %d, want 401", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := strings.TrimSpace(string(body))

	// Snapshot: body must contain the opaque sentinel.
	if !strings.Contains(bodyStr, "unauthorized") {
		t.Errorf("snapshot: body = %q, want \"unauthorized\" sentinel", bodyStr)
	}

	// Snapshot: body must NOT reflect the IdP's error_description.
	// If this assertion fires, the handler is leaking IdP detail to callers,
	// which violates the "uniform 401" contract in SPEC-0005.
	for _, leak := range []string{"access_denied", "denied consent", "error_description"} {
		if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(leak)) {
			t.Errorf("snapshot: body leaks IdP error detail %q: body=%q", leak, bodyStr)
		}
	}
}

// TestSnapshotAccountsDashboard pins the /accounts page HTML structure
// for an authenticated user with zero accounts. Assertions check that:
//   - The response is 200 OK
//   - The <title> element follows the "Page — Reduit" pattern
//   - The page contains a CTA linking to /accounts/setup
//
// These markers are stable across minor styling changes and survive
// Tailwind class churn. They catch regressions where the template is
// accidentally replaced, the title format drifts, or the wizard entry
// point is removed from the empty-state card.
//
// Governing: SPEC-0005 REQ "Account Dashboard".
func TestSnapshotAccountsDashboard(t *testing.T) {
	t.Parallel()
	baseURL, idp, _, _ := dashboardTestServer(t, nil)
	idp.setSubject("sub-snapshot", "snapshot@example.com", "Snap")
	c := loginAndFollow(t, baseURL, idp, "sub-snapshot", "snapshot@example.com", "Snap")

	status, body := fetch(t, c, baseURL+"/accounts")
	if status != http.StatusOK {
		t.Fatalf("snapshot: status = %d, want 200; body=%s", status, body[:min(len(body), 400)])
	}

	// Snapshot: title follows the "Page — Reduit" convention from base.html.
	// The em-dash separator and "Reduit" brand name are structural — a
	// stray template rename that drops the brand or changes the separator
	// would break this.
	if !strings.Contains(body, "— Reduit") {
		t.Errorf("snapshot: page title missing '— Reduit' brand suffix (first 400 chars: %s)", body[:min(len(body), 400)])
	}

	// Snapshot: the wizard CTA must appear so users can add their first
	// Proton account. Empty-state page links to /accounts/setup.
	if !strings.Contains(body, "/accounts/setup") {
		t.Error("snapshot: /accounts/setup link absent from empty-state dashboard")
	}
}
