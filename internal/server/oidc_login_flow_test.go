// Tests for OIDC login flow template rendering and auth gating.
//
// This file is the companion test story for issue #23 (OIDC login
// handlers). It covers:
//
//   - Template render: GET /auth/login?return_to=<path> issues a redirect
//     that preserves the return_to through the full OIDC round-trip so the
//     browser lands back on the originally-requested page post-login.
//
//   - OIDC error rendering: when the IdP redirects back with ?error=, the
//     callback returns a uniform 401 (no oracle-leaking detail). Snapshot
//     assertions pin the response body so a future refactor that accidentally
//     exposes IdP error detail is caught immediately.
//
//   - Auth gating: unauthenticated GET requests to protected routes (the
//     accounts dashboard, the wizard entry point, and the wizard step
//     handlers) all 302 to /auth/login?return_to=<original-path>. Authenticated
//     requests (browser holding a valid session cookie) pass through to the
//     handler. POST to a protected route without a session returns 401 (not a
//     redirect, so HTMX snippets surface the error rather than following a
//     browser redirect).
//
// Governing: SPEC-0005 REQ "Authentication Gating", SPEC-0005 REQ "OIDC Login Flow".

package server_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestOIDCLoginFlow_ReturnToPreservedThroughCallbackRedirect verifies
// that GET /auth/login?return_to=<path> causes /auth/callback to
// redirect to <path> after a successful IdP round-trip. This pins the
// full-stack wiring: login handler → PreSession → callback → redirect.
//
// Governing: SPEC-0005 REQ "OIDC Login Flow".
func TestOIDCLoginFlow_ReturnToPreservedThroughCallbackRedirect(t *testing.T) {
	t.Parallel()
	baseURL, idp, _ := newTestServer(t, nil)
	idp.setSubject("sub-return-to", "rto@example.com", "RTO")
	c := newClient(t)

	// Log in with a specific return_to. loginThroughIdP follows the
	// /auth/login → IdP → /auth/callback chain and returns the final
	// (302) response from /auth/callback.
	resp := loginThroughIdP(t, c, baseURL, "/accounts/setup")
	defer resp.Body.Close()

	// The callback MUST 302 to the return_to path, not to the
	// defaultPostLoginPath ("/accounts"). This confirms the PreSession
	// preserved the return_to through the PKCE round-trip.
	//
	// Governing: SPEC-0005 REQ "OIDC Login Flow".
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/auth/callback status = %d, want 302; body=%s", resp.StatusCode, body)
	}
	got := resp.Header.Get("Location")
	if got != "/accounts/setup" {
		t.Errorf("callback Location = %q, want /accounts/setup", got)
	}
}

// TestOIDCLoginFlow_DefaultRedirectWhenNoReturnTo verifies that
// GET /auth/login (without return_to) ultimately lands at the
// defaultPostLoginPath ("/accounts") after a successful login.
//
// Governing: SPEC-0005 REQ "OIDC Login Flow".
func TestOIDCLoginFlow_DefaultRedirectWhenNoReturnTo(t *testing.T) {
	t.Parallel()
	baseURL, idp, _ := newTestServer(t, nil)
	idp.setSubject("sub-default-redir", "dr@example.com", "DR")
	c := newClient(t)

	resp := loginThroughIdP(t, c, baseURL, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/auth/callback status = %d, want 302; body=%s", resp.StatusCode, body)
	}
	got := resp.Header.Get("Location")
	if got != "/accounts" {
		t.Errorf("callback Location = %q, want /accounts (defaultPostLoginPath)", got)
	}
}

// TestOIDCError_CallbackWithIdPError verifies the OIDC error snapshot:
// when the IdP redirects to /auth/callback with ?error=access_denied
// (and no valid state or code), the handler returns 401 with an opaque
// "unauthorized" body. The body is intentionally uniform so an attacker
// cannot use it to distinguish "no pre-session" from "PKCE mismatch"
// from "IdP returned access_denied".
//
// This is the snapshot test mandated by SPEC-0005 REQ "OIDC Login Flow"
// — it pins the response shape so a future refactor that accidentally
// leaks IdP error detail (e.g. echoing ?error_description back to the
// browser) is caught immediately.
//
// Governing: SPEC-0005 REQ "OIDC Login Flow".
func TestOIDCError_CallbackWithIdPError(t *testing.T) {
	t.Parallel()
	baseURL, _, _ := newTestServer(t, nil)
	c := newClient(t)

	// The IdP returns ?error=access_denied with no code or state.
	// This hits the "missing state or code" 401 branch.
	resp, err := c.Get(baseURL + "/auth/callback?error=access_denied&error_description=User+denied+consent")
	if err != nil {
		t.Fatalf("GET /auth/callback: %v", err)
	}
	defer resp.Body.Close()

	// SPEC-0005 mandates a uniform 401 — the error detail MUST NOT
	// reach the response body. A future caller that forwards the IdP's
	// error_description would fail this assertion.
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	bodyStr := strings.TrimSpace(string(body))
	// Snapshot: the response body must contain the expected opaque
	// text and must NOT reflect the IdP's error_description.
	if !strings.Contains(bodyStr, "unauthorized") {
		t.Errorf("body = %q, want to contain \"unauthorized\"", bodyStr)
	}
	if strings.Contains(bodyStr, "access_denied") || strings.Contains(bodyStr, "denied consent") {
		t.Errorf("body leaks IdP error detail: %q", bodyStr)
	}
}

// TestOIDCError_CallbackWithErrorButValidState verifies that even if
// the IdP includes ?error= alongside a valid-looking state, the callback
// still returns 401 (not 500). The state+code check fires first; a
// missing code surfaces as the "missing state or code" branch.
//
// Governing: SPEC-0005 REQ "OIDC Login Flow".
func TestOIDCError_CallbackWithErrorButValidState(t *testing.T) {
	t.Parallel()
	baseURL, _, _ := newTestServer(t, nil)
	c := newClient(t)

	// Drive /auth/login to capture a real state value.
	resp, err := c.Get(baseURL + "/auth/login")
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("/auth/login Location has no state param")
	}

	// IdP returns error with the real state but no code — simulates
	// a user-denied-consent flow.
	cbURL := baseURL + "/auth/callback?error=access_denied&state=" + url.QueryEscape(state)
	resp, err = c.Get(cbURL)
	if err != nil {
		t.Fatalf("GET /auth/callback: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestAuthGating_UnauthenticatedGetRedirectsToLogin verifies SPEC-0005
// REQ "Authentication Gating" for three protected GET routes: the
// accounts dashboard (/accounts), the wizard entry (/accounts/setup),
// and the root (/). All must redirect to /auth/login with a return_to
// param equal to the originally-requested path.
//
// These three routes span the two handler groups registered in
// server.routes (dashboard + wizard) plus the root-redirect handler,
// giving a broad coverage baseline without duplicating the
// TestDashboard_UnauthRedirectsToLogin assertion from
// dashboard_handlers_test.go.
//
// Governing: SPEC-0005 REQ "Authentication Gating".
func TestAuthGating_UnauthenticatedGetRedirectsToLogin(t *testing.T) {
	t.Parallel()
	baseURL, _, _, _ := dashboardTestServer(t, nil)

	// Disable redirect-following so we can inspect the gate's 302.
	c := newClient(t)
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	for _, tc := range []struct {
		path      string
		wantRetTo string
	}{
		// Dashboard — the canonical protected path.
		{"/accounts", "/accounts"},
		// Wizard entry point — tests a second handler group.
		{"/accounts/setup", "/accounts/setup"},
		// Root redirect — passes through RequireSession because "/" is
		// not allowlisted; the gate fires before the redirect handler.
		{"/", "/"},
	} {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			resp, err := c.Get(baseURL + tc.path)
			if err != nil {
				t.Fatalf("GET %s: %v", tc.path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusFound {
				t.Errorf("%s status = %d, want 302", tc.path, resp.StatusCode)
				return
			}
			loc := resp.Header.Get("Location")
			u, err := url.Parse(loc)
			if err != nil {
				t.Fatalf("Location %q parse: %v", loc, err)
			}
			if u.Path != "/auth/login" {
				t.Errorf("%s Location.Path = %q, want /auth/login (full: %q)", tc.path, u.Path, loc)
			}
			retTo := u.Query().Get("return_to")
			if retTo != tc.wantRetTo {
				t.Errorf("%s return_to = %q, want %q", tc.path, retTo, tc.wantRetTo)
			}
		})
	}
}

// TestAuthGating_UnauthenticatedPostReturns401 verifies that a POST
// to a protected route from a session-less browser returns 401 (not
// a redirect). HTMX uses the 401 status to trigger a custom
// out-of-band response rather than a full-page redirect loop.
//
// Governing: SPEC-0005 REQ "Authentication Gating".
func TestAuthGating_UnauthenticatedPostReturns401(t *testing.T) {
	t.Parallel()
	baseURL, _, _, _ := dashboardTestServer(t, nil)

	c := newClient(t)
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	for _, path := range []string{
		"/accounts/setup/auth",
		"/accounts/setup/cancel",
		"/auth/logout",
	} {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			resp, err := c.Post(baseURL+path, "application/x-www-form-urlencoded", strings.NewReader(""))
			if err != nil {
				t.Fatalf("POST %s: %v", path, err)
			}
			defer resp.Body.Close()

			// /auth/logout is allowlisted, so it should NOT 401 — it always
			// redirects. All other POST targets are gated.
			if path == "/auth/logout" {
				if resp.StatusCode != http.StatusFound {
					t.Errorf("POST %s status = %d, want 302 (logout always redirects)", path, resp.StatusCode)
				}
				return
			}
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("POST %s status = %d, want 401", path, resp.StatusCode)
			}
		})
	}
}

// TestAuthGating_AuthenticatedRequestProceeds verifies that an
// authenticated session (established through the full OIDC round-trip)
// gains access to the accounts dashboard. This covers the "Authenticated
// request proceeds" scenario from SPEC-0005 for the primary protected route.
//
// The wizard routes (/accounts/setup and its POST steps) require
// ProtonManager + WizardSessions to be wired; when those are nil the
// handlers return 500. Those handler-level configs are validated in
// wizard_handlers_test.go; this test pins the auth-gate layer only.
//
// Governing: SPEC-0005 REQ "Authentication Gating".
func TestAuthGating_AuthenticatedRequestProceeds(t *testing.T) {
	t.Parallel()
	baseURL, idp, _, _ := dashboardTestServer(t, nil)

	// Log in with a known subject so the session cookie is present.
	idp.setSubject("sub-auth-gating", "ag@example.com", "AG")
	c := loginAndFollow(t, baseURL, idp, "sub-auth-gating", "ag@example.com", "AG")

	// The accounts dashboard must be reachable (200) once logged in.
	// An inadvertent auth-gate regression would return 302 here;
	// a missing dependency would return 500 — both fail the test.
	resp, err := c.Get(baseURL + "/accounts")
	if err != nil {
		t.Fatalf("GET /accounts: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("/accounts status = %d, want 200; body excerpt=%s", resp.StatusCode, body[:min(len(body), 200)])
	}

	// /healthz (allowlisted) must also remain reachable — a sanity
	// check that the middleware is not double-gating allowlisted paths
	// for authenticated users.
	resp2, err := c.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("/healthz status = %d, want 200", resp2.StatusCode)
	}
}
