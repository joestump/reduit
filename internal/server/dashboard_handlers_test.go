// Tests for the /accounts dashboard handler.
//
// Covers the SPEC-0005 REQ "Account Dashboard" scenarios:
//
//   - Unauthenticated request redirects to /auth/login (gate; covered
//     elsewhere but exercised here too via a smoke test).
//   - User with zero accounts gets the empty-state hero card.
//   - Non-admin user sees only their own accounts; sibling-user
//     accounts are filtered out.
//   - Admin sees every account, grouped by owner.
//
// Templates render real HTML; assertions inspect the response body
// for marker strings rather than parse the DOM.
//
// Governing: ADR-0010, SPEC-0005 REQ "Account Dashboard".

package server_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/users"
)

// dashboardTestServer is the dashboard-specific fixture: wires
// AccountService alongside the OIDC stack so /accounts has data to
// render. Mirrors newTestServer's shape but accepts the services as
// inputs so each test can seed before the server starts.
func dashboardTestServer(t *testing.T, adminSubs []string) (baseURL string, idp *fakeIdP, accSvc account.Service, usrSvc users.Service) {
	t.Helper()
	st := openTempStore(t)
	master, err := cryptenv.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	accSvc = account.New(st, master)
	usrSvc = users.New(st)

	idp = newFakeIdP(t, "reduit-test-client")
	baseURL = mountTestServer(t, st, idp, adminSubs, accSvc, usrSvc)
	return baseURL, idp, accSvc, usrSvc
}

// loginAndFollow runs the OIDC round-trip for the configured IdP
// subject and returns the cookie-jarred client + the
// final-redirect target. Tests can then GET further pages with the
// same client to inherit the session cookie.
func loginAndFollow(t *testing.T, baseURL string, idp *fakeIdP, sub, email, name string) *http.Client {
	t.Helper()
	idp.setSubject(sub, email, name)
	c := newClient(t)
	resp := loginThroughIdP(t, c, baseURL, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login round-trip status = %d, want 302", resp.StatusCode)
	}
	return c
}

// fetch executes a GET via the supplied client and returns the
// status code + body string. Tests use the body string for
// substring assertions against template output.
func fetch(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestDashboard_UnauthRedirectsToLogin(t *testing.T) {
	t.Parallel()
	baseURL, _, _, _ := dashboardTestServer(t, nil)
	c := newClient(t)

	// Disable redirect following so we can inspect the gate's 302
	// response directly. The default client (newClient) follows
	// redirects, which would consume the Location header and report
	// the IdP's response shape instead of the dashboard gate's.
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := c.Get(baseURL + "/accounts")
	if err != nil {
		t.Fatalf("GET /accounts: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
	}

	// SPEC-0005 REQ "Authentication Gating" Scenario "Unauthenticated
	// request redirects to login" mandates the redirect points at
	// /auth/login with a return_to query param echoing the original
	// request URI. Asserting on the Location header pins the gate-to-
	// dashboard wiring -- the broader auth_test suite exercises the
	// same gate generically, but a dashboard-specific assertion catches
	// a regression that only affects the /accounts route (e.g., a
	// future caller that mounts /accounts outside the gate, or a
	// return_to encoder that drops the path).
	//
	// Governing: SPEC-0005 REQ "Authentication Gating"; PR #72 review (N2).
	loc := resp.Header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("Location %q parse: %v", loc, err)
	}
	if u.Path != "/auth/login" {
		t.Errorf("Location.Path = %q, want /auth/login (full Location: %q)", u.Path, loc)
	}
	if got := u.Query().Get("return_to"); got != "/accounts" {
		t.Errorf("return_to = %q, want /accounts (full Location: %q)", got, loc)
	}
}

func TestDashboard_EmptyStateForUserWithZeroAccounts(t *testing.T) {
	t.Parallel()
	baseURL, idp, _, _ := dashboardTestServer(t, nil)
	c := loginAndFollow(t, baseURL, idp, "sub-zero", "zero@example.com", "Zero")

	status, body := fetch(t, c, baseURL+"/accounts")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", status, body)
	}
	if !strings.Contains(body, "Add your first Proton account") {
		t.Errorf("empty-state hero copy missing; body=%s", body[:min(len(body), 500)])
	}
	if !strings.Contains(body, "/accounts/setup") {
		t.Error("empty-state CTA link missing")
	}
}

func TestDashboard_NonAdminSeesOnlyOwnAccounts(t *testing.T) {
	t.Parallel()
	baseURL, idp, accSvc, usrSvc := dashboardTestServer(t, nil)
	ctx := context.Background()

	// Seed: user A owns 2 accounts; user B owns 1.
	uA, err := usrSvc.Upsert(ctx, users.UpsertParams{OIDCSubject: "sub-A", Email: "a@example.com"})
	if err != nil {
		t.Fatalf("upsert A: %v", err)
	}
	uB, err := usrSvc.Upsert(ctx, users.UpsertParams{OIDCSubject: "sub-B", Email: "b@example.com"})
	if err != nil {
		t.Fatalf("upsert B: %v", err)
	}
	for _, params := range []account.CreateParams{
		{UserID: uA.ID, ProtonUserID: "proton-A1", Email: "a1@proton.me"},
		{UserID: uA.ID, ProtonUserID: "proton-A2", Email: "a2@proton.me"},
		{UserID: uB.ID, ProtonUserID: "proton-B1", Email: "b1@proton.me"},
	} {
		if _, err := accSvc.Create(ctx, params); err != nil {
			t.Fatalf("create account: %v", err)
		}
	}

	// User A logs in. Dashboard should show A's two accounts but
	// NOT B's account.
	c := loginAndFollow(t, baseURL, idp, "sub-A", "a@example.com", "A")
	status, body := fetch(t, c, baseURL+"/accounts")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if !strings.Contains(body, "a1@proton.me") {
		t.Error("body missing user-A's first account")
	}
	if !strings.Contains(body, "a2@proton.me") {
		t.Error("body missing user-A's second account")
	}
	if strings.Contains(body, "b1@proton.me") {
		t.Error("non-admin saw sibling user's account (b1@proton.me)")
	}
	// Subtitle reflects 2 accounts.
	if !strings.Contains(body, "2 accounts") {
		t.Errorf("subtitle missing '2 accounts'; body excerpt=%s", body[:min(len(body), 800)])
	}
}

func TestDashboard_AdminSeesAllAccountsGroupedByOwner(t *testing.T) {
	t.Parallel()
	baseURL, idp, accSvc, usrSvc := dashboardTestServer(t, []string{"sub-admin"})
	ctx := context.Background()

	// Seed: admin owns 1 account; another user owns 1 account.
	uAdmin, err := usrSvc.Upsert(ctx, users.UpsertParams{OIDCSubject: "sub-admin", Email: "admin@example.com"})
	if err != nil {
		t.Fatalf("upsert admin: %v", err)
	}
	uOther, err := usrSvc.Upsert(ctx, users.UpsertParams{OIDCSubject: "sub-other", Email: "other@example.com"})
	if err != nil {
		t.Fatalf("upsert other: %v", err)
	}
	if _, err := accSvc.Create(ctx, account.CreateParams{UserID: uAdmin.ID, ProtonUserID: "p-admin", Email: "admin@proton.me"}); err != nil {
		t.Fatalf("admin acct: %v", err)
	}
	if _, err := accSvc.Create(ctx, account.CreateParams{UserID: uOther.ID, ProtonUserID: "p-other", Email: "other@proton.me"}); err != nil {
		t.Fatalf("other acct: %v", err)
	}

	// Admin logs in.
	c := loginAndFollow(t, baseURL, idp, "sub-admin", "admin@example.com", "Admin")
	status, body := fetch(t, c, baseURL+"/accounts")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	// Admin sees both accounts.
	if !strings.Contains(body, "admin@proton.me") {
		t.Error("admin missing own account")
	}
	if !strings.Contains(body, "other@proton.me") {
		t.Error("admin missing other user's account")
	}
	// Owner labels render as group headers (uses email per the spec).
	if !strings.Contains(body, "admin@example.com") {
		t.Error("admin view missing admin's owner-group header")
	}
	if !strings.Contains(body, "other@example.com") {
		t.Error("admin view missing other user's owner-group header")
	}
	// Subtitle reflects 2 accounts across 2 users.
	if !strings.Contains(body, "2 accounts across 2 users") {
		t.Errorf("admin subtitle wrong; body excerpt=%s", body[:min(len(body), 800)])
	}
}

// TestDashboard_AdminViewPaginatesWhenOverThreshold seeds enough
// accounts to span multiple admin pages and exercises the prev/next
// strip + the "subtitle stays at the unpaginated total" contract.
//
// Governing: SPEC-0005 REQ "Account Dashboard"; PR #72 review (N3).
func TestDashboard_AdminViewPaginatesWhenOverThreshold(t *testing.T) {
	t.Parallel()
	baseURL, idp, accSvc, usrSvc := dashboardTestServer(t, []string{"sub-admin"})
	ctx := context.Background()

	uAdmin, err := usrSvc.Upsert(ctx, users.UpsertParams{OIDCSubject: "sub-admin", Email: "admin@example.com"})
	if err != nil {
		t.Fatalf("upsert admin: %v", err)
	}
	// Seed 25 accounts under one user -- comfortably above the 20-per-
	// page threshold so page 1 has 20 cards and page 2 has 5.
	const total = 25
	for i := 0; i < total; i++ {
		params := account.CreateParams{
			UserID:       uAdmin.ID,
			ProtonUserID: fmtSeedID("p-admin-", i),
			Email:        fmtSeedID("seed-", i) + "@proton.me",
		}
		if _, err := accSvc.Create(ctx, params); err != nil {
			t.Fatalf("create account %d: %v", i, err)
		}
	}

	c := loginAndFollow(t, baseURL, idp, "sub-admin", "admin@example.com", "Admin")

	// Page 1: subtitle reflects unpaginated total (25), Next is
	// present, Previous is absent.
	status, body := fetch(t, c, baseURL+"/accounts")
	if status != http.StatusOK {
		t.Fatalf("page 1 status = %d, want 200", status)
	}
	if !strings.Contains(body, "25 accounts across 1 user") {
		t.Errorf("page 1 subtitle should reflect unpaginated total; body excerpt=%s", body[:min(len(body), 1200)])
	}
	if !strings.Contains(body, ">Next<") {
		t.Error("page 1 missing Next control")
	}
	if strings.Contains(body, ">Previous<") {
		t.Error("page 1 should not have Previous control")
	}
	// Page-1 spot-check: the FIRST seeded account is on the page; the
	// 21st (which lives on page 2) is NOT.
	if !strings.Contains(body, "seed-00@proton.me") {
		t.Error("page 1 missing first seeded account")
	}
	if strings.Contains(body, "seed-20@proton.me") {
		t.Error("page 1 should not contain 21st account (lives on page 2)")
	}

	// Page 2: Previous is present, Next is absent (5 of 25 shown).
	status, body = fetch(t, c, baseURL+"/accounts?page=2")
	if status != http.StatusOK {
		t.Fatalf("page 2 status = %d, want 200", status)
	}
	if !strings.Contains(body, ">Previous<") {
		t.Error("page 2 missing Previous control")
	}
	if strings.Contains(body, ">Next<") {
		t.Error("page 2 should not have Next control (last page)")
	}
	if !strings.Contains(body, "seed-20@proton.me") {
		t.Error("page 2 missing 21st seeded account")
	}
	if strings.Contains(body, "seed-00@proton.me") {
		t.Error("page 2 should not contain first account (lives on page 1)")
	}

	// Out-of-range page (page=99) snaps to the last populated page
	// rather than 404 -- a stale browser tab pointed at a now-trimmed
	// fleet should still render usefully.
	status, body = fetch(t, c, baseURL+"/accounts?page=99")
	if status != http.StatusOK {
		t.Fatalf("page 99 status = %d, want 200", status)
	}
	if !strings.Contains(body, "seed-20@proton.me") {
		t.Error("page 99 (snapped to last) missing expected page-2 account")
	}

	// Bad page param falls back to page 1 silently (no 400).
	status, body = fetch(t, c, baseURL+"/accounts?page=junk")
	if status != http.StatusOK {
		t.Fatalf("page=junk status = %d, want 200", status)
	}
	if !strings.Contains(body, "seed-00@proton.me") {
		t.Error("page=junk should fall back to page 1 (first account missing)")
	}
}

// fmtSeedID is a small zero-padding helper local to the pagination
// test so seed-00..seed-24 sort lexicographically (which matches
// the accounts.List ordering by created_at and stable card order).
func fmtSeedID(prefix string, i int) string {
	return prefix + string(rune('0'+i/10)) + string(rune('0'+i%10))
}
