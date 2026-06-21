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
	"time"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/auth/session"
	"github.com/joestump/reduit/internal/notify"
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
		Groups:        pageGroups,
		Empty:         len(pageGroups) == 0,
		Page:          pg.page,
		HasPrev:       pg.hasPrev,
		HasNext:       pg.hasNext,
		Notifications: s.loadAdminNotifications(r),
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
	// Notifications is the unacknowledged admin-notification list
	// rendered as a dismissable banner above the account grid. Empty
	// when the surface is unwired or there are no pending notifications.
	//
	// Governing: SPEC-0002 REQ "Panic Isolation", REQ "Backoff on
	// Failure".
	Notifications []adminNotificationView
}

// adminNotificationView is the per-notification view-model the admin
// template consumes. The conversion lives in the handler so the
// template stays logic-light (no time formatting, no kind→label map).
type adminNotificationView struct {
	ID       string
	Kind     string // raw kind, for any kind-specific styling
	Label    string // human-readable kind ("Worker crashed", ...)
	Message  string
	Detail   string
	Age      string // "X min ago"
	AlertCSS string // DaisyUI alert color class
}

// notificationKindLabel maps a notify.Kind to a short human label and
// the DaisyUI alert color class the banner uses. A worker crash is an
// error (rose); an auto-revert is a warning (the account needs operator
// action but nothing is broken).
func notificationKindLabel(k notify.Kind) (label, alertCSS string) {
	switch k {
	case notify.KindWorkerCrashed:
		return "Worker crashed", "alert-error"
	case notify.KindAutoReverted:
		return "Account reverted to setup", "alert-warning"
	default:
		return string(k), "alert-info"
	}
}

// loadAdminNotifications fetches the unacknowledged notification list
// for the admin banner. A nil Notifications dep (surface unwired) or a
// load error degrades to an empty banner: the account grid is the
// primary content and MUST render even if the notification store
// hiccups, so an error is logged but not surfaced as a 500.
//
// Governing: SPEC-0002 REQ "Panic Isolation".
func (s *Server) loadAdminNotifications(r *http.Request) []adminNotificationView {
	if s.deps.Notifications == nil {
		return nil
	}
	const bannerLimit = 20
	ns, err := s.deps.Notifications.ListUnacknowledged(r.Context(), bannerLimit)
	if err != nil {
		s.deps.Logger.Error("admin accounts: load notifications: " + err.Error())
		return nil
	}
	if len(ns) == 0 {
		return nil
	}
	out := make([]adminNotificationView, len(ns))
	for i, n := range ns {
		label, alertCSS := notificationKindLabel(n.Kind)
		out[i] = adminNotificationView{
			ID:       n.ID,
			Kind:     string(n.Kind),
			Label:    label,
			Message:  n.Message,
			Detail:   n.Detail,
			Age:      formatNotificationAge(n.CreatedAt),
			AlertCSS: alertCSS,
		}
	}
	return out
}

// formatNotificationAge renders a notification's CreatedAt as a coarse
// relative time, mirroring formatLastSync's vocabulary so the admin
// surface reads consistently.
func formatNotificationAge(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return itoa(int(d.Minutes())) + " min ago"
	case d < 24*time.Hour:
		return itoa(int(d.Hours())) + " hr ago"
	default:
		return itoa(int(d.Hours()/24)) + " days ago"
	}
}

// handleAdminNotificationAck dismisses a single admin notification.
// Returns to /admin/accounts so the banner re-renders without the
// acknowledged row. A missing notification is treated as already-gone
// (redirect, not 404) so a double-click is benign.
//
// Governing: SPEC-0002 REQ "Panic Isolation" (acknowledging clears the
// operator-facing notification once they've seen it).
func (s *Server) handleAdminNotificationAck(w http.ResponseWriter, r *http.Request) {
	if s.deps.Notifications == nil {
		http.Error(w, "notifications not configured", http.StatusInternalServerError)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing notification id", http.StatusBadRequest)
		return
	}
	if err := s.deps.Notifications.Acknowledge(r.Context(), id); err != nil {
		if errors.Is(err, notify.ErrNotFound) {
			// Already gone (acknowledged elsewhere, or hard-deleted with
			// its account). The operator's intent -- "make it go away" --
			// is already satisfied, so redirect rather than 404.
			http.Redirect(w, r, "/admin/accounts", http.StatusSeeOther)
			return
		}
		s.deps.Logger.Error("admin notification ack: " + err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/accounts", http.StatusSeeOther)
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
