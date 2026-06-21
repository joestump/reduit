// Admin account management handlers.
//
// Routes (all gated by RequireAdmin middleware):
//
//   GET  /admin/accounts                    — list all accounts grouped by user
//   POST /admin/accounts/{id}/suspend       — state → suspended, log admin action
//   POST /admin/accounts/{id}/unsuspend     — state → active, log admin action
//   POST /admin/accounts/{id}/delete        — state → soft_deleted, log admin action
//
// Every handler reads the acting admin's OIDC sub from the session and
// records it in a structured log line so suspension / deletion decisions
// are auditable. Sessions for affected accounts are dropped via
// RevokeSessionsForAccount.
//
// Governing: SPEC-0005 REQ "Admin Account Management".

package server

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/auth/session"
)

// adminActionsReady gates every admin handler on its required deps
// (symmetric to dashboardActionsReady). Returns false and writes a
// 500 when deps are not wired.
func (s *Server) adminActionsReady(w http.ResponseWriter) bool {
	if s.deps.SessionManager == nil || s.deps.AccountService == nil {
		s.deps.Logger.Error("admin handler called without required deps")
		http.Error(w, "admin actions not configured", http.StatusInternalServerError)
		return false
	}
	return true
}

// requireAdminAndAccount resolves the {id} path parameter to an account
// (any account — admin is not restricted by ownership) and returns the
// acting admin's identity. Writes 404/500 and returns nil on error.
func (s *Server) requireAdminAndAccount(w http.ResponseWriter, r *http.Request) (*account.Account, session.Identity, bool) {
	id := session.GetIdentity(r.Context(), s.deps.SessionManager)
	accountID := r.PathValue("id")
	if accountID == "" {
		http.Error(w, "missing account id", http.StatusBadRequest)
		return nil, session.Identity{}, false
	}
	acct, err := s.deps.AccountService.GetByID(r.Context(), accountID)
	if err != nil {
		if errors.Is(err, account.ErrAccountNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return nil, session.Identity{}, false
		}
		s.deps.Logger.Error("admin action: get account",
			slog.String("account_id", accountID),
			slog.String("error", err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, session.Identity{}, false
	}
	return acct, id, true
}

// revokeAccountSessions drops HTTP sessions bound to the account.
// Errors are logged but do not fail the action — the state transition
// has already committed; leaking a session on a DB hiccup is less bad
// than rolling back a successful suspend.
func (s *Server) revokeAccountSessions(r *http.Request, accountID string) {
	if s.deps.Store == nil {
		return
	}
	if n, err := session.RevokeSessionsForAccount(r.Context(), s.deps.Store.DB.DB, accountID); err != nil {
		s.deps.Logger.Error("admin action: revoke sessions",
			slog.String("account_id", accountID),
			slog.String("error", err.Error()))
	} else if n > 0 {
		s.deps.Logger.Info("admin action: revoked sessions",
			slog.String("account_id", accountID),
			slog.Int64("sessions_revoked", n))
	}
}

// handleAdminAccountSuspend transitions the account to suspended.
// Drops HTTP sessions and logs the admin action with the OIDC sub.
//
// Governing: SPEC-0005 REQ "Admin Account Management".
func (s *Server) handleAdminAccountSuspend(w http.ResponseWriter, r *http.Request) {
	if !s.adminActionsReady(w) {
		return
	}
	acct, id, ok := s.requireAdminAndAccount(w, r)
	if !ok {
		return
	}
	if _, err := s.deps.AccountService.Transition(r.Context(), acct.ID, account.StateSuspended); err != nil {
		if errors.Is(err, account.ErrInvalidTransition) {
			s.deps.Logger.Warn("admin action: invalid transition (suspend)",
				slog.String("admin_subject", id.Subject),
				slog.String("account_id", acct.ID),
				slog.String("error", err.Error()))
			http.Error(w, "account cannot be suspended from its current state", http.StatusConflict)
			return
		}
		s.deps.Logger.Error("admin action: suspend",
			slog.String("admin_subject", id.Subject),
			slog.String("account_id", acct.ID),
			slog.String("error", err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Governing: SPEC-0005 REQ "Admin Account Management" — drop live sessions.
	s.revokeAccountSessions(r, acct.ID)
	if s.deps.IMAPSessions != nil {
		s.deps.IMAPSessions.DropForAccount(acct.ID, "account suspended by admin")
	}
	if s.deps.SMTPSessions != nil {
		s.deps.SMTPSessions.DropForAccount(acct.ID, "account suspended by admin")
	}
	s.deps.Logger.Info("admin action: suspended account",
		slog.String("account_id", acct.ID),
		slog.String("account_owner", acct.UserID),
		slog.String("admin_subject", id.Subject),
		slog.String("admin_user_id", id.UserID))
	http.Redirect(w, r, "/admin/accounts", http.StatusSeeOther)
}

// handleAdminAccountUnsuspend transitions suspended → active and
// logs the admin action with the OIDC sub.
//
// Governing: SPEC-0005 REQ "Admin Account Management".
func (s *Server) handleAdminAccountUnsuspend(w http.ResponseWriter, r *http.Request) {
	if !s.adminActionsReady(w) {
		return
	}
	acct, id, ok := s.requireAdminAndAccount(w, r)
	if !ok {
		return
	}
	if _, err := s.deps.AccountService.Transition(r.Context(), acct.ID, account.StateActive); err != nil {
		if errors.Is(err, account.ErrInvalidTransition) {
			s.deps.Logger.Warn("admin action: invalid transition (unsuspend)",
				slog.String("admin_subject", id.Subject),
				slog.String("account_id", acct.ID),
				slog.String("error", err.Error()))
			http.Error(w, "account cannot be unsuspended from its current state", http.StatusConflict)
			return
		}
		s.deps.Logger.Error("admin action: unsuspend",
			slog.String("admin_subject", id.Subject),
			slog.String("account_id", acct.ID),
			slog.String("error", err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.deps.Logger.Info("admin action: unsuspended account",
		slog.String("account_id", acct.ID),
		slog.String("account_owner", acct.UserID),
		slog.String("admin_subject", id.Subject),
		slog.String("admin_user_id", id.UserID))
	http.Redirect(w, r, "/admin/accounts", http.StatusSeeOther)
}

// handleAdminAccountDelete soft-deletes the account and logs the
// admin action with the OIDC sub.
//
// Governing: SPEC-0005 REQ "Admin Account Management".
func (s *Server) handleAdminAccountDelete(w http.ResponseWriter, r *http.Request) {
	if !s.adminActionsReady(w) {
		return
	}
	acct, id, ok := s.requireAdminAndAccount(w, r)
	if !ok {
		return
	}
	if _, err := s.deps.AccountService.Delete(r.Context(), acct.ID); err != nil {
		if errors.Is(err, account.ErrInvalidTransition) {
			s.deps.Logger.Warn("admin action: invalid transition (delete)",
				slog.String("admin_subject", id.Subject),
				slog.String("account_id", acct.ID),
				slog.String("error", err.Error()))
			http.Error(w, "account is already removed", http.StatusConflict)
			return
		}
		s.deps.Logger.Error("admin action: delete",
			slog.String("admin_subject", id.Subject),
			slog.String("account_id", acct.ID),
			slog.String("error", err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Governing: SPEC-0005 REQ "Admin Account Management" — drop live sessions.
	s.revokeAccountSessions(r, acct.ID)
	if s.deps.IMAPSessions != nil {
		s.deps.IMAPSessions.DropForAccount(acct.ID, "account deleted by admin")
	}
	if s.deps.SMTPSessions != nil {
		s.deps.SMTPSessions.DropForAccount(acct.ID, "account deleted by admin")
	}
	s.deps.Logger.Info("admin action: soft-deleted account",
		slog.String("account_id", acct.ID),
		slog.String("account_owner", acct.UserID),
		slog.String("admin_subject", id.Subject),
		slog.String("admin_user_id", id.UserID))
	http.Redirect(w, r, "/admin/accounts", http.StatusSeeOther)
}

// handleAdminAccounts renders GET /admin/accounts. This is the admin-
// only account listing page — it shows every account in the system
// grouped by user, with suspend / unsuspend / delete action buttons.
// The underlying data comes from adminAllAccountsGrouped (same as the
// /accounts handler's admin path) but lives at a distinct URL so it
// can be gated exclusively by RequireAdmin without affecting the user
// dashboard.
//
// Governing: SPEC-0005 REQ "Admin Account Management".
func (s *Server) handleAdminAccounts(w http.ResponseWriter, r *http.Request) {
	if s.deps.SessionManager == nil || s.deps.AccountService == nil {
		http.Error(w, "admin not configured", http.StatusInternalServerError)
		return
	}
	id := session.GetIdentity(r.Context(), s.deps.SessionManager)
	groups, err := s.adminAllAccountsGrouped(r)
	if err != nil {
		s.deps.Logger.Error("admin accounts: list: " + err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	page := parsePage(r.URL.Query().Get("page"))
	var pageGroups []accountGroup
	var pg paginationState
	if len(groups) == 0 || allEmpty(groups) {
		pageGroups = nil
	} else {
		pageGroups, pg = paginateAdminGroups(groups, page, adminPageSize)
	}

	data := adminAccountsPageData{
		pageData: pageData{
			Title:    "Admin — All Accounts",
			Identity: newIdentityView(id),
			IsAdmin:  id.IsAdmin,
		},
		Groups:  pageGroups,
		Empty:   len(pageGroups) == 0,
		Page:    pg.page,
		HasPrev: pg.hasPrev,
		HasNext: pg.hasNext,
	}
	if pg.hasPrev {
		data.PrevURL = "/admin/accounts?page=" + itoa(pg.page-1)
	}
	if pg.hasNext {
		data.NextURL = "/admin/accounts?page=" + itoa(pg.page+1)
	}
	s.renderPage(w, r, "admin_accounts", &data)
}

// adminAccountsPageData backs the admin accounts page template.
type adminAccountsPageData struct {
	pageData
	Empty   bool
	Groups  []accountGroup
	Page    int
	HasPrev bool
	HasNext bool
	PrevURL string
	NextURL string
}

// itoa converts an int to its decimal string representation without
// importing strconv in this file.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
