// Tests for the MCP token issuance + revocation admin UI.
//
// Covers SPEC-0006 REQ "Token Issuance and Revocation" + the SPEC-0005
// security considerations the issue mandates for new HTTP endpoints
// (auth gate + CSRF):
//
//   - GET  /accounts/{id}/mcp-tokens: owner → 200 list + issue form
//   - GET  /accounts/{id}/mcp-tokens: non-owner → 403
//   - GET  /accounts/{id}/mcp-tokens: unauthenticated → 302 /auth/login
//   - POST /accounts/{id}/mcp-tokens: owner → one-time plaintext modal
//   - POST /accounts/{id}/mcp-tokens: missing CSRF → 403, no token issued
//   - POST /accounts/{id}/mcp-tokens: non-owner → 403, no token issued
//   - POST .../{tokenID}/revoke: owner → token inactive afterwards
//   - POST .../{tokenID}/revoke: missing CSRF → 403, token still active
//   - POST .../{tokenID}/revoke: token of another account → 404, untouched
//   - indistinguishability: non-existent vs existing-not-owned account
//     return byte-identical responses on GET / issue / revoke
//
// Governing: SPEC-0006 REQ "Token Issuance and Revocation"; SPEC-0005
// design "Content security and CSRF"; issue #19.

package server_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/joestump/reduit/internal/auth/mcptoken"
)

func TestMCPTokens_OwnerGetsPage(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-mcp-owner", "joe@example.com", "Joe")
	id := f.seedActive(t, userID)

	resp, err := c.Get(f.url + "/accounts/" + id + "/mcp-tokens")
	if err != nil {
		t.Fatalf("GET mcp-tokens: %v", err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "Issue a new token") {
		t.Errorf("expected issue form; body excerpt=%s", body[:min(len(body), 600)])
	}
	// No plaintext anywhere on the list page.
	if strings.Contains(body, "data-mcp-token") {
		t.Errorf("plaintext token block leaked onto list page")
	}
}

func TestMCPTokens_Unauthenticated_Redirects(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	_, userID := f.makeUser(t, "sub-mcp-unauth", "joe@example.com", "Joe")
	id := f.seedActive(t, userID)

	bare := noRedirectClient(t)
	resp, err := bare.Get(f.url + "/accounts/" + id + "/mcp-tokens")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "/auth/login") {
		t.Errorf("redirect = %q, want /auth/login", loc)
	}
}

func TestMCPTokens_NonOwner_Forbidden(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	cA, _ := f.makeUser(t, "sub-mcp-A", "a@example.com", "A")
	_, userB := f.makeUser(t, "sub-mcp-B", "b@example.com", "B")
	idB := f.seedActive(t, userB)

	resp, err := cA.Get(f.url + "/accounts/" + idB + "/mcp-tokens")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestMCPTokens_Issue_OneTimeDisplay(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-mcp-issue", "joe@example.com", "Joe")
	id := f.seedActive(t, userID)

	resp := post(t, c, f.url+"/accounts/"+id+"/mcp-tokens", url.Values{"label": {"laptop agent"}})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	// The fragment shows the plaintext once, with the Reduit prefix.
	if !strings.Contains(body, "data-mcp-token") {
		t.Fatalf("expected one-time token block; body excerpt=%s", body[:min(len(body), 600)])
	}
	if !strings.Contains(body, "rdmcp_") {
		t.Errorf("expected plaintext token (rdmcp_ prefix) in modal")
	}
	// Fragment, not a full page.
	if strings.Contains(body, "<html") {
		t.Errorf("expected HTMX fragment, got full page")
	}
	// The token now exists in the repo for this account.
	toks, err := mcptoken.NewRepository(f.store.DB).ListForAccount(t.Context(), id)
	if err != nil {
		t.Fatalf("ListForAccount: %v", err)
	}
	if len(toks) != 1 || toks[0].Label != "laptop agent" {
		t.Fatalf("repo state after issue = %+v, want 1 labeled token", toks)
	}
}

func TestMCPTokens_Issue_MissingCSRF_Forbidden(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-mcp-issue-csrf", "joe@example.com", "Joe")
	id := f.seedActive(t, userID)

	// Empty token => no X-CSRF-Token header => csrfProtect 403.
	resp := postNoCSRF(t, c, f.url+"/accounts/"+id+"/mcp-tokens", url.Values{}, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for missing CSRF", resp.StatusCode)
	}
	// No token must have been issued.
	toks, _ := mcptoken.NewRepository(f.store.DB).ListForAccount(t.Context(), id)
	if len(toks) != 0 {
		t.Errorf("token issued despite missing CSRF — gate broken: %+v", toks)
	}
}

func TestMCPTokens_Issue_NonOwner_Forbidden(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	cA, _ := f.makeUser(t, "sub-mcp-issue-A", "a@example.com", "A")
	_, userB := f.makeUser(t, "sub-mcp-issue-B", "b@example.com", "B")
	idB := f.seedActive(t, userB)

	resp := post(t, cA, f.url+"/accounts/"+idB+"/mcp-tokens", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for non-owner", resp.StatusCode)
	}
	toks, _ := mcptoken.NewRepository(f.store.DB).ListForAccount(t.Context(), idB)
	if len(toks) != 0 {
		t.Errorf("non-owner issued a token — ownership check broken: %+v", toks)
	}
}

func TestMCPTokens_Revoke_OwnerSucceeds(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-mcp-revoke", "joe@example.com", "Joe")
	id := f.seedActive(t, userID)

	repo := mcptoken.NewRepository(f.store.DB)
	tok, err := repo.Issue(t.Context(), mcptoken.IssueParams{AccountID: id})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	resp := post(t, c, f.url+"/accounts/"+id+"/mcp-tokens/"+tok.ID+"/revoke", url.Values{})
	resp.Body.Close()
	// SeeOther redirect back to the list page on success.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303/200", resp.StatusCode)
	}
	got, err := repo.FindByPlaintext(t.Context(), tok.Plaintext)
	if err != nil {
		t.Fatalf("FindByPlaintext: %v", err)
	}
	if got.IsActive(time.Now()) {
		t.Error("token still active after owner revoke")
	}
}

func TestMCPTokens_Revoke_MissingCSRF_Forbidden(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-mcp-revoke-csrf", "joe@example.com", "Joe")
	id := f.seedActive(t, userID)

	repo := mcptoken.NewRepository(f.store.DB)
	tok, _ := repo.Issue(t.Context(), mcptoken.IssueParams{AccountID: id})

	resp := postNoCSRF(t, c, f.url+"/accounts/"+id+"/mcp-tokens/"+tok.ID+"/revoke", url.Values{}, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for missing CSRF", resp.StatusCode)
	}
	got, _ := repo.FindByPlaintext(t.Context(), tok.Plaintext)
	if !got.IsActive(time.Now()) {
		t.Error("token revoked despite missing CSRF — gate broken")
	}
}

func TestMCPTokens_Revoke_OtherAccountsToken_NotFound(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	cA, userA := f.makeUser(t, "sub-mcp-rev-A", "a@example.com", "A")
	idA := f.seedActive(t, userA)
	_, userB := f.makeUser(t, "sub-mcp-rev-B", "b@example.com", "B")
	idB := f.seedActive(t, userB)

	repo := mcptoken.NewRepository(f.store.DB)
	// A token bound to account B.
	tokB, _ := repo.Issue(t.Context(), mcptoken.IssueParams{AccountID: idB})

	// User A (owner of A) tries to revoke B's token via A's path. The
	// handler confirms the token belongs to the path account before
	// revoking, so this is a 404 and B's token stays active.
	resp := post(t, cA, f.url+"/accounts/"+idA+"/mcp-tokens/"+tokB.ID+"/revoke", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for cross-account token revoke", resp.StatusCode)
	}
	got, _ := repo.FindByPlaintext(t.Context(), tokB.Plaintext)
	if !got.IsActive(time.Now()) {
		t.Error("cross-account revoke succeeded — token confinement broken")
	}
}

// statusAndBody reads a response's status code + full body and closes it.
func statusAndBody(t *testing.T, resp *http.Response) (int, string) {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(b)
}

// TestMCPTokens_Indistinguishable_NotExistVsNotOwned asserts the
// SPEC-0006 indistinguishability discipline on the token routes: a
// NON-EXISTENT account UUID and an EXISTING-BUT-NOT-OWNED account UUID
// produce byte-identical (status + body) responses on GET, issue, and
// revoke. Otherwise a non-admin iterating UUIDs against
// /accounts/{id}/mcp-tokens could enumerate which accounts exist (and
// UUIDv7 leaks creation time).
//
// Governing: SPEC-0006 REQ "Token Issuance and Revocation"
// (indistinguishability discipline); SPEC-0006 design.md.
func TestMCPTokens_Indistinguishable_NotExistVsNotOwned(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	// Caller A owns nothing relevant.
	cA, _ := f.makeUser(t, "sub-mcp-indist-A", "a@example.com", "A")
	// Account owned by a DIFFERENT user B (exists-but-not-owned by A).
	_, userB := f.makeUser(t, "sub-mcp-indist-B", "b@example.com", "B")
	idOwnedByB := f.seedActive(t, userB)
	// A well-formed UUID that does not correspond to any account row.
	idNonExistent := uuid.NewString()

	// GET: non-existent vs existing-not-owned must be byte-identical.
	st1, b1 := statusAndBody(t, mustGet(t, cA, f.url+"/accounts/"+idNonExistent+"/mcp-tokens"))
	st2, b2 := statusAndBody(t, mustGet(t, cA, f.url+"/accounts/"+idOwnedByB+"/mcp-tokens"))
	if st1 != http.StatusForbidden || st2 != http.StatusForbidden {
		t.Fatalf("GET statuses = %d / %d, want 403 / 403", st1, st2)
	}
	if st1 != st2 || b1 != b2 {
		t.Errorf("GET responses distinguishable: (%d,%q) vs (%d,%q)", st1, b1, st2, b2)
	}

	// Issue (POST): same discipline.
	st3, b3 := statusAndBody(t, post(t, cA, f.url+"/accounts/"+idNonExistent+"/mcp-tokens", url.Values{}))
	st4, b4 := statusAndBody(t, post(t, cA, f.url+"/accounts/"+idOwnedByB+"/mcp-tokens", url.Values{}))
	if st3 != http.StatusForbidden || st4 != http.StatusForbidden {
		t.Fatalf("issue statuses = %d / %d, want 403 / 403", st3, st4)
	}
	if st3 != st4 || b3 != b4 {
		t.Errorf("issue responses distinguishable: (%d,%q) vs (%d,%q)", st3, b3, st4, b4)
	}

	// Revoke (POST): the account gate runs before the token lookup, so a
	// non-existent and a not-owned account must be byte-identical here too
	// (a dummy token id is fine — the gate rejects before the lookup).
	tokenPath := "/mcp-tokens/" + uuid.NewString() + "/revoke"
	st5, b5 := statusAndBody(t, post(t, cA, f.url+"/accounts/"+idNonExistent+tokenPath, url.Values{}))
	st6, b6 := statusAndBody(t, post(t, cA, f.url+"/accounts/"+idOwnedByB+tokenPath, url.Values{}))
	if st5 != http.StatusForbidden || st6 != http.StatusForbidden {
		t.Fatalf("revoke statuses = %d / %d, want 403 / 403", st5, st6)
	}
	if st5 != st6 || b5 != b6 {
		t.Errorf("revoke responses distinguishable: (%d,%q) vs (%d,%q)", st5, b5, st6, b6)
	}
}

// mustGet issues a GET and fails the test on a transport error.
func mustGet(t *testing.T, c *http.Client, target string) *http.Response {
	t.Helper()
	resp, err := c.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	return resp
}
