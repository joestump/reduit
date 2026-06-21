// MCP token issuance + revocation admin UI.
//
// Per-account MCP bearer tokens (SPEC-0006 REQ "Token Issuance and
// Revocation") are issued and revoked from here:
//
//   GET  /accounts/{id}/mcp-tokens                    — list + issue form
//   POST /accounts/{id}/mcp-tokens                    — issue (one-time display)
//   POST /accounts/{id}/mcp-tokens/{tokenID}/revoke   — revoke
//
// Authority is "owner of the target account, OR an admin" — enforced by
// requireOwnedAccount (account.user_id == session.user_id || is_admin),
// the same gate the dashboard action handlers use. Every state-changing
// POST is CSRF-protected (csrfProtect, issue #26): the issue form carries
// the hidden csrf_token field and each revoke <form> carries it too.
//
// The plaintext token is shown EXACTLY ONCE, in an HTMX modal fragment
// returned by the issue POST — mirroring the IMAP-password rotation
// one-time-display flow (dashboard_actions.go). It is never logged and
// never rendered again; only the SHA-256 hash is persisted by the
// mcptoken repository.
//
// Governing: SPEC-0006 REQ "Token Issuance and Revocation",
// SPEC-0005 design "Content security and CSRF" (auth gate + CSRF on every
// new HTTP endpoint), ADR-0008 (embedded MCP).

package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/auth/mcptoken"
	"github.com/joestump/reduit/internal/auth/session"
)

// MCPTokenStore is the slice of the mcptoken.Repository the admin UI
// needs. Declared here as an interface (rather than taking the concrete
// *mcptoken.Repository) so handler tests can inject a stub without a
// database. *mcptoken.Repository satisfies it.
//
// Governing: SPEC-0006 REQ "Token Issuance and Revocation".
type MCPTokenStore interface {
	Issue(ctx context.Context, p mcptoken.IssueParams) (*mcptoken.Token, error)
	Revoke(ctx context.Context, id string) error
	ListForAccount(ctx context.Context, accountID string) ([]*mcptoken.Token, error)
	GetByID(ctx context.Context, id string) (*mcptoken.Token, error)
}

// mcpTokensReady gates the handlers on the token store + account service
// being wired (symmetric to dashboardActionsReady). A nil store is a
// startup wiring bug, not a request-time condition.
func (s *Server) mcpTokensReady(w http.ResponseWriter) bool {
	if s.deps.SessionManager == nil || s.deps.AccountService == nil || s.deps.MCPTokens == nil {
		s.deps.Logger.Error("mcp-token handler called without required deps")
		http.Error(w, "mcp tokens not configured", http.StatusInternalServerError)
		return false
	}
	return true
}

// tokenForbidden writes the single byte-identical authorization-failure
// response the token routes use for BOTH "account does not exist" AND
// "account exists but is not owned by the caller". Status, headers, and
// body are identical so a non-admin iterating UUIDs against
// /accounts/{id}/mcp-tokens cannot tell which accounts exist (UUIDv7
// leaks creation time, so an existence oracle is a real leak).
//
// http.Error sets Content-Type: text/plain; charset=utf-8 and writes the
// message + "\n"; calling it with the same string from every branch is
// what makes the responses byte-for-byte identical.
//
// Governing: SPEC-0006 REQ "Token Issuance and Revocation"
// (indistinguishability discipline — "a non-admin user must not learn
// whether a given account UUID exists just because they probed
// /accounts/{id}/mcp-tokens"); SPEC-0006 design.md "Authz failures on
// issuance/revocation paths follow the same indistinguishability
// discipline".
func tokenForbidden(w http.ResponseWriter) {
	http.Error(w, "forbidden", http.StatusForbidden)
}

// requireTokenAccount resolves the {id} path value to an account the
// caller may operate token routes on (owner OR admin), applying the
// indistinguishability discipline: a NON-EXISTENT account and an
// EXISTING-BUT-NOT-OWNED account produce the SAME 403 (tokenForbidden),
// so the response cannot be used to enumerate which account UUIDs exist.
//
// This is deliberately stricter than requireOwnedAccount (which returns
// 404 for a missing row and 403 for not-owned) because SPEC-0006 names
// the token routes for the indistinguishability discipline, whereas the
// dashboard-action routes requireOwnedAccount governs are not subject to
// it. Returns the resolved account + identity on success; writes the
// identical 403 (or a 500 on a genuine lookup error) and returns ok=false
// otherwise.
//
// Governing: SPEC-0006 REQ "Token Issuance and Revocation"
// (indistinguishability discipline).
func (s *Server) requireTokenAccount(w http.ResponseWriter, r *http.Request) (*account.Account, session.Identity, bool) {
	id := session.GetIdentity(r.Context(), s.deps.SessionManager)
	if id.UserID == "" {
		// A session with no user binding can own nothing; fail closed with
		// the same 403 so this path is indistinguishable from not-owned.
		s.deps.Logger.Warn("mcp tokens: authenticated session has empty UserID",
			slog.String("subject", id.Subject))
		tokenForbidden(w)
		return nil, session.Identity{}, false
	}
	accountID := r.PathValue("id")
	if accountID == "" {
		http.Error(w, "missing account id", http.StatusBadRequest)
		return nil, session.Identity{}, false
	}
	acct, err := s.deps.AccountService.GetByID(r.Context(), accountID)
	if err != nil {
		if errors.Is(err, account.ErrAccountNotFound) {
			// Account does not exist -> identical 403 to the not-owned case
			// below. This is the indistinguishability the spec mandates.
			tokenForbidden(w)
			return nil, session.Identity{}, false
		}
		s.deps.Logger.Error("mcp tokens: get account",
			slog.String("account_id", accountID),
			slog.String("error", err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, session.Identity{}, false
	}
	if acct.UserID != id.UserID && !id.IsAdmin {
		// Account exists but is not owned -> identical 403 to the
		// not-exist case above.
		s.deps.Logger.Warn("mcp tokens: ownership check failed",
			slog.String("account_id", accountID),
			slog.String("session_user", id.UserID),
			slog.String("account_owner", acct.UserID))
		tokenForbidden(w)
		return nil, session.Identity{}, false
	}
	return acct, id, true
}

// mcpTokenView is one token row in the list template. The plaintext is
// NEVER part of this view — only the issue-response fragment carries it.
type mcpTokenView struct {
	ID       string
	Label    string
	Created  string
	Expires  string
	LastUsed string
	Revoked  bool
	Expired  bool
	Active   bool
}

// mcpTokensPageData backs the token-management page template.
type mcpTokensPageData struct {
	pageData
	AccountID    string
	AccountLabel string
	Tokens       []mcpTokenView
}

// handleMCPTokens renders GET /accounts/{id}/mcp-tokens: the list of the
// account's tokens plus the issue form. Gated by requireTokenAccount
// (owner or admin, with the indistinguishability discipline so a missing
// account is byte-identical to a not-owned one).
//
// Governing: SPEC-0006 REQ "Token Issuance and Revocation".
func (s *Server) handleMCPTokens(w http.ResponseWriter, r *http.Request) {
	if !s.mcpTokensReady(w) {
		return
	}
	acct, id, ok := s.requireTokenAccount(w, r)
	if !ok {
		return
	}

	tokens, err := s.deps.MCPTokens.ListForAccount(r.Context(), acct.ID)
	if err != nil {
		s.deps.Logger.Error("mcp tokens: list",
			slog.String("account_id", acct.ID),
			slog.String("error", err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	label := acct.Email
	if label == "" {
		label = "Account " + acct.ID[:min(8, len(acct.ID))]
	}
	data := mcpTokensPageData{
		pageData: pageData{
			Title:    "MCP Tokens",
			Identity: newIdentityView(id),
			IsAdmin:  id.IsAdmin,
		},
		AccountID:    acct.ID,
		AccountLabel: label,
		Tokens:       tokenViews(tokens),
	}
	s.renderPage(w, r, "mcp_tokens", &data)
}

// mcpTokenIssuedModalData backs the one-time-display fragment. The
// plaintext lives only on the value rendered into the response body — it
// is never written to the session, never logged, and dropped from the
// handler stack on return (mirrors imapRotateModalData).
type mcpTokenIssuedModalData struct {
	AccountID    string
	AccountLabel string
	Label        string
	Plaintext    string
	Expires      string
}

// handleMCPTokenIssue handles POST /accounts/{id}/mcp-tokens. Generates a
// new per-account token and returns the plaintext in an HTMX modal
// fragment for one-time display. CSRF-protected (route wraps this in
// csrfProtect); ownership-gated by requireTokenAccount (with the
// indistinguishability discipline applied to a non-existent account).
//
// Governing: SPEC-0006 REQ "Token Issuance and Revocation" — "the
// plaintext token SHALL be returned exactly once via the admin UI"; the
// 403 for a non-owned account is byte-identical to the 403 for a
// non-existent account (indistinguishability discipline).
func (s *Server) handleMCPTokenIssue(w http.ResponseWriter, r *http.Request) {
	if !s.mcpTokensReady(w) {
		return
	}
	acct, _, ok := s.requireTokenAccount(w, r)
	if !ok {
		return
	}

	label := strings.TrimSpace(r.PostFormValue("label"))
	if len(label) > 100 {
		label = label[:100]
	}

	var expiresAt *time.Time
	// Optional expiry in days. Empty / 0 means no expiry. A malformed or
	// negative value is treated as "no expiry" rather than erroring — the
	// field is a convenience, not a gate.
	if days := strings.TrimSpace(r.PostFormValue("expires_days")); days != "" {
		if n := parsePositiveInt(days); n > 0 {
			t := time.Now().UTC().Add(time.Duration(n) * 24 * time.Hour)
			expiresAt = &t
		}
	}

	tok, err := s.deps.MCPTokens.Issue(r.Context(), mcptoken.IssueParams{
		AccountID: acct.ID,
		Label:     label,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		s.deps.Logger.Error("mcp tokens: issue",
			slog.String("account_id", acct.ID),
			slog.String("error", err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.deps.Logger.Info("mcp tokens: issued",
		slog.String("account_id", acct.ID),
		slog.String("token_id", tok.ID))

	accLabel := acct.Email
	if accLabel == "" {
		accLabel = "Account " + acct.ID[:min(8, len(acct.ID))]
	}
	data := mcpTokenIssuedModalData{
		AccountID:    acct.ID,
		AccountLabel: accLabel,
		Label:        tok.Label,
		Plaintext:    tok.Plaintext,
		Expires:      formatExpiry(tok.ExpiresAt),
	}
	if s.tmpl == nil {
		http.Error(w, "templates not loaded", http.StatusInternalServerError)
		return
	}
	frag, ok := s.tmpl.getFragment("mcp_token_issued_modal")
	if !ok {
		s.deps.Logger.Error("mcp tokens: mcp_token_issued_modal fragment not found")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := frag.ExecuteTemplate(w, "mcp_token_issued_modal", data); err != nil {
		s.deps.Logger.Error("mcp tokens: render issued modal: " + err.Error())
	}
}

// handleMCPTokenRevoke handles POST
// /accounts/{id}/mcp-tokens/{tokenID}/revoke. Marks the token revoked so
// subsequent MCP requests carrying it fail with 401. CSRF-protected;
// ownership-gated.
//
// Ownership of the path account is gated by requireTokenAccount (with
// the account-existence indistinguishability discipline). The token is
// then confirmed to belong to {id} BEFORE revoking: a token ID bound to
// a different account surfaces as 404 (indistinguishable from a genuinely
// missing token), so a caller who owns account A cannot revoke a token
// bound to account B by guessing its ID. This token-level 404 only fires
// AFTER the account gate passes (the caller owns the path account), so it
// leaks nothing about which account UUIDs exist.
//
// Governing: SPEC-0006 REQ "Token Issuance and Revocation" — "On success
// the token SHALL be marked revoked and subsequent MCP requests carrying
// it SHALL fail"; indistinguishability discipline on the account gate.
func (s *Server) handleMCPTokenRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.mcpTokensReady(w) {
		return
	}
	acct, _, ok := s.requireTokenAccount(w, r)
	if !ok {
		return
	}
	tokenID := r.PathValue("tokenID")
	if tokenID == "" {
		http.Error(w, "missing token id", http.StatusBadRequest)
		return
	}

	// Confirm the token belongs to this account before revoking. A token
	// bound to another account (or no token at all) is a 404 — the same
	// response, so account membership is not leaked via the revoke path.
	tok, err := s.deps.MCPTokens.GetByID(r.Context(), tokenID)
	if err != nil || tok.AccountID != acct.ID {
		if err != nil && !errors.Is(err, mcptoken.ErrTokenNotFound) {
			s.deps.Logger.Error("mcp tokens: get for revoke",
				slog.String("account_id", acct.ID),
				slog.String("token_id", tokenID),
				slog.String("error", err.Error()))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if err := s.deps.MCPTokens.Revoke(r.Context(), tokenID); err != nil {
		if errors.Is(err, mcptoken.ErrTokenNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.deps.Logger.Error("mcp tokens: revoke",
			slog.String("account_id", acct.ID),
			slog.String("token_id", tokenID),
			slog.String("error", err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.deps.Logger.Info("mcp tokens: revoked",
		slog.String("account_id", acct.ID),
		slog.String("token_id", tokenID))

	// Redirect back to the token page so the no-JS <form> submit lands on
	// the refreshed list (the revoked token now shows its revoked state).
	http.Redirect(w, r, "/accounts/"+acct.ID+"/mcp-tokens", http.StatusSeeOther)
}

// ----- view helpers -----

// tokenViews projects repository tokens into the display rows, computing
// the active/revoked/expired state at render time.
func tokenViews(tokens []*mcptoken.Token) []mcpTokenView {
	now := time.Now().UTC()
	out := make([]mcpTokenView, 0, len(tokens))
	for _, t := range tokens {
		expired := t.ExpiresAt != nil && !t.ExpiresAt.After(now)
		out = append(out, mcpTokenView{
			ID:       t.ID,
			Label:    t.Label,
			Created:  t.CreatedAt.Format("2006-01-02 15:04 UTC"),
			Expires:  formatExpiry(t.ExpiresAt),
			LastUsed: formatLastUsed(t.LastUsedAt),
			Revoked:  t.RevokedAt != nil,
			Expired:  expired,
			Active:   t.IsActive(now),
		})
	}
	return out
}

func formatExpiry(t *time.Time) string {
	if t == nil {
		return "Never"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

func formatLastUsed(t *time.Time) string {
	if t == nil {
		return "Never"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// parsePositiveInt parses a small positive integer, returning 0 for any
// non-positive or unparseable input. Used for the optional expiry-days
// field where a bad value is benign (treated as "no expiry").
func parsePositiveInt(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
		if n > 100000 { // clamp absurd values
			return 100000
		}
	}
	return n
}
