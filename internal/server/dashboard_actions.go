// Action handlers for managing existing accounts from the dashboard.
//
// Three POST routes per SPEC-0005 "Account Dashboard" Scenario "User
// manages account state":
//
//   POST /accounts/{id}/delete                  -- soft-delete
//   POST /accounts/{id}/suspend                 -- active -> suspended
//   POST /accounts/{id}/reactivate              -- suspended -> active
//   POST /accounts/{id}/imap-password/rotate    -- generate fresh IMAP pw
//
// Every handler verifies the SCS-bound user owns the target account
// (or that the session is admin) before any state change. The
// rotation endpoint returns the freshly generated plaintext password
// in an HTMX modal fragment for one-time display per SPEC-0001 REQ
// "Per-Account IMAP Password" -- it is never logged and never
// rendered again.
//
// Governing: ADR-0010 (multi-Proton-account per user); SPEC-0001 REQ
// "Per-Account IMAP Password"; SPEC-0005 REQ "Account Dashboard"
// (Scenario "User manages account state"); issues #102, #103.

package server

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/auth/session"
)

// dashboardActionsReady gates every action handler on its
// dependencies. Symmetric to wizardReady -- a missing service is a
// fixture / startup wiring bug, not a request-time misconfiguration.
func (s *Server) dashboardActionsReady(w http.ResponseWriter) bool {
	if s.deps.SessionManager == nil || s.deps.AccountService == nil {
		s.deps.Logger.Error("dashboard actions handler called without required deps")
		http.Error(w, "dashboard actions not configured", http.StatusInternalServerError)
		return false
	}
	return true
}

// requireOwnedAccount resolves the {id} path value to an account
// owned by the bound session user (or any account when the session
// is admin). Returns the resolved account on success and writes a
// 404/403 + nil on failure. Use as the first thing in every
// per-account action handler.
//
// Governing: SPEC-0005 REQ "Account Dashboard" -- "users see only the
// accounts they own" (admins see all).
func (s *Server) requireOwnedAccount(w http.ResponseWriter, r *http.Request) (*account.Account, session.Identity, bool) {
	id := session.GetIdentity(r.Context(), s.deps.SessionManager)
	if id.UserID == "" {
		s.deps.Logger.Warn("dashboard action: authenticated session has empty UserID",
			slog.String("subject", id.Subject))
		http.Error(w, "session missing user binding", http.StatusInternalServerError)
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
			http.Error(w, "not found", http.StatusNotFound)
			return nil, session.Identity{}, false
		}
		s.deps.Logger.Error("dashboard action: get account",
			slog.String("account_id", accountID),
			slog.String("error", err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, session.Identity{}, false
	}
	if acct.UserID != id.UserID && !id.IsAdmin {
		s.deps.Logger.Warn("dashboard action: ownership check failed",
			slog.String("account_id", accountID),
			slog.String("session_user", id.UserID),
			slog.String("account_owner", acct.UserID))
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, session.Identity{}, false
	}
	return acct, id, true
}

// handleAccountDelete soft-deletes the account. Idempotent on
// already-soft-deleted rows: the underlying transition rejects
// terminal -> terminal, so a double-submit returns 409 (Conflict)
// rather than a confusing redirect-then-404. Issue #102.
func (s *Server) handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	if !s.dashboardActionsReady(w) {
		return
	}
	acct, _, ok := s.requireOwnedAccount(w, r)
	if !ok {
		return
	}
	if _, err := s.deps.AccountService.Delete(r.Context(), acct.ID); err != nil {
		if errors.Is(err, account.ErrInvalidTransition) {
			http.Error(w, "account is already removed", http.StatusConflict)
			return
		}
		s.deps.Logger.Error("dashboard action: delete",
			slog.String("account_id", acct.ID),
			slog.String("error", err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.deps.Logger.Info("dashboard action: soft-deleted account",
		slog.String("account_id", acct.ID),
		slog.String("user_id", acct.UserID))
	http.Redirect(w, r, "/accounts", http.StatusSeeOther)
}

// handleAccountSuspend transitions active -> suspended. Drops any
// IMAP/SMTP sessions per SPEC-0005 "Admin Account Management";
// re-enabling requires a Reactivate action below. Issue #102.
func (s *Server) handleAccountSuspend(w http.ResponseWriter, r *http.Request) {
	if !s.dashboardActionsReady(w) {
		return
	}
	acct, _, ok := s.requireOwnedAccount(w, r)
	if !ok {
		return
	}
	if _, err := s.deps.AccountService.Transition(r.Context(), acct.ID, account.StateSuspended); err != nil {
		if errors.Is(err, account.ErrInvalidTransition) {
			http.Error(w, "account cannot be suspended from its current state", http.StatusConflict)
			return
		}
		s.deps.Logger.Error("dashboard action: suspend",
			slog.String("account_id", acct.ID),
			slog.String("error", err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.deps.Logger.Info("dashboard action: suspended account",
		slog.String("account_id", acct.ID),
		slog.String("user_id", acct.UserID))
	http.Redirect(w, r, "/accounts", http.StatusSeeOther)
}

// handleAccountReactivate transitions suspended -> active. Used by
// the suspended-card action so the operator can recover from a
// suspend without going through the wizard again. Issue #102.
func (s *Server) handleAccountReactivate(w http.ResponseWriter, r *http.Request) {
	if !s.dashboardActionsReady(w) {
		return
	}
	acct, _, ok := s.requireOwnedAccount(w, r)
	if !ok {
		return
	}
	if _, err := s.deps.AccountService.Transition(r.Context(), acct.ID, account.StateActive); err != nil {
		if errors.Is(err, account.ErrInvalidTransition) {
			http.Error(w, "account cannot be reactivated from its current state", http.StatusConflict)
			return
		}
		s.deps.Logger.Error("dashboard action: reactivate",
			slog.String("account_id", acct.ID),
			slog.String("error", err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.deps.Logger.Info("dashboard action: reactivated account",
		slog.String("account_id", acct.ID),
		slog.String("user_id", acct.UserID))
	http.Redirect(w, r, "/accounts", http.StatusSeeOther)
}

// imapRotateModalData backs the rotate-success template fragment.
// The plaintext password lives only on the value rendered into the
// response body; it is never written to the SCS session, never
// logged, and is dropped from the handler's stack on return.
type imapRotateModalData struct {
	AccountID    string
	AccountLabel string
	Plaintext    string
	IMAPHost     string
	IMAPPort     int
	SMTPPort     int
	Username     string
}

// handleAccountIMAPRotate generates a fresh IMAP password for the
// account and renders an HTMX modal fragment with the plaintext for
// one-time display. The dashboard's rotate button targets this
// route via hx-post + hx-target so the response replaces the modal
// container without a full-page reload.
//
// The previously-stored bcrypt hash and sealed ciphertext are
// overwritten inside RotateIMAPPassword; the plaintext returned here
// is the only path the operator has to recover it. The fragment
// includes a copy-to-clipboard control + an "I've saved this" button
// that closes the modal.
//
// Governing: SPEC-0001 REQ "Per-Account IMAP Password" (rotation
// returns the plaintext for one-time admin-UI display); SPEC-0005
// REQ "Account Dashboard"; issues #102, #103.
func (s *Server) handleAccountIMAPRotate(w http.ResponseWriter, r *http.Request) {
	if !s.dashboardActionsReady(w) {
		return
	}
	acct, _, ok := s.requireOwnedAccount(w, r)
	if !ok {
		return
	}
	plaintext, err := s.deps.AccountService.RotateIMAPPassword(r.Context(), acct.ID)
	if err != nil {
		s.deps.Logger.Error("dashboard action: rotate imap password",
			slog.String("account_id", acct.ID),
			slog.String("error", err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.deps.Logger.Info("dashboard action: rotated imap password",
		slog.String("account_id", acct.ID),
		slog.String("user_id", acct.UserID))

	host := mailHostFromRequest(r)
	username := acct.PrimaryAlias
	if username == "" {
		// Fall back to a sensible label when the alias was never
		// pinned (e.g., a row created before SPEC-0003 landed). The
		// operator can still copy the plaintext; the IMAP server
		// will resolve the SASL identity from whatever they paste.
		username = acct.Email
	}
	label := acct.Email
	if label == "" {
		label = "Account " + acct.ID[:min(8, len(acct.ID))]
	}
	data := imapRotateModalData{
		AccountID:    acct.ID,
		AccountLabel: label,
		Plaintext:    plaintext,
		IMAPHost:     host,
		IMAPPort:     993,
		SMTPPort:     465,
		Username:     username,
	}
	if s.tmpl == nil {
		http.Error(w, "templates not loaded", http.StatusInternalServerError)
		return
	}
	t, ok := s.tmpl.getFragment("imap_rotate_modal")
	if !ok {
		s.deps.Logger.Error("dashboard action: imap_rotate_modal fragment not found")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "imap_rotate_modal", data); err != nil {
		s.deps.Logger.Error("dashboard action: render imap_rotate_modal: " + err.Error())
		// Headers may already be flushed; nothing more we can do.
	}
}
