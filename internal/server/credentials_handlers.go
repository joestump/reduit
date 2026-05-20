// Credentials view and rotation handlers.
//
// GET /accounts/{id}/credentials renders the IMAP/SMTP connection
// details for an account, with a rotate button. The password is
// NEVER shown on this page — only on the one-time-display modal
// returned by the rotate endpoint.
//
// POST /accounts/{id}/credentials/rotate is an alias for the
// existing /accounts/{id}/imap-password/rotate. It generates a fresh
// password, seals it, persists ciphertext + bcrypt hash, and renders
// the HTMX modal fragment for one-time-display.
//
// Governing: SPEC-0005 REQ "Per-User IMAP/SMTP Credentials".

package server

import (
	"net/http"
)

// credentialsPageData backs the credentials view template.
type credentialsPageData struct {
	pageData
	AccountID    string
	AccountLabel string
	Username     string
	IMAPHost     string
	IMAPPort     int
	SMTPHost     string
	SMTPPort     int
	HasPassword  bool
}

// handleAccountCredentials renders GET /accounts/{id}/credentials.
// Shows IMAP host, port 993, SMTP host, port 465, and per-account
// username. The password is NOT shown; only a rotate button is
// rendered. Gated: account.user_id == session.user_id || session.is_admin.
//
// Governing: SPEC-0005 REQ "Per-User IMAP/SMTP Credentials".
func (s *Server) handleAccountCredentials(w http.ResponseWriter, r *http.Request) {
	if !s.dashboardActionsReady(w) {
		return
	}
	acct, id, ok := s.requireOwnedAccount(w, r)
	if !ok {
		return
	}

	host := mailHostFromRequest(r)
	username := acct.PrimaryAlias
	if username == "" {
		username = acct.Email
	}
	label := acct.Email
	if label == "" {
		label = "Account " + acct.ID[:min(8, len(acct.ID))]
	}

	data := credentialsPageData{
		pageData: pageData{
			Title:    "IMAP/SMTP Credentials",
			Identity: newIdentityView(id),
			IsAdmin:  id.IsAdmin,
		},
		AccountID:    acct.ID,
		AccountLabel: label,
		Username:     username,
		IMAPHost:     host,
		IMAPPort:     993,
		SMTPHost:     host,
		SMTPPort:     465,
		HasPassword:  acct.HasIMAPPassword,
	}

	s.renderPage(w, r, "credentials", data)
}

// handleAccountCredentialsRotate is a route alias for the existing
// handleAccountIMAPRotate. It accepts POST /accounts/{id}/credentials/rotate
// and delegates to the same rotation logic so callers using the
// SPEC-0005 canonical URL get the same one-time-display modal.
//
// Governing: SPEC-0005 REQ "Per-User IMAP/SMTP Credentials".
func (s *Server) handleAccountCredentialsRotate(w http.ResponseWriter, r *http.Request) {
	s.handleAccountIMAPRotate(w, r)
}
