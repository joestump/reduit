// Add-Proton-account wizard handlers.
//
// Five HTTP entry points back the wizard the user clicks through
// from the dashboard's "Add account" button:
//
//   GET  /accounts/setup           -- render the appropriate step
//   POST /accounts/setup/auth      -- credentials -> Proton login
//   POST /accounts/setup/2fa       -- TOTP second factor
//   POST /accounts/setup/unlock    -- mailbox passphrase + commit
//   POST /accounts/setup/cancel    -- soft-delete + redirect home
//
// The wizard binds at GET time: a fresh accounts row is INSERTed in
// state pending_proton_setup so the rest of the flow has a stable
// account ID to thread through SCS + the in-memory wizard store.
// On success (POST /unlock), the row is updated with the Proton user
// id, the sealed refresh token, the sealed mailbox passphrase, and
// transitioned to active -- which fires the OnTransition callback the
// sync supervisor uses to spin up its worker.
//
// Out of scope for v0.3: FIDO2 (deferred -- the user hasn't enabled
// it on their accounts; passkey + TOTP cover the use case). When a
// Proton account requires FIDO2 we surface a clear error rather than
// silently proceeding.
//
// Governing: ADR-0001 (go-proton-api), ADR-0010 (multi-Proton-account
// per user), SPEC-0005 REQ "Add-Proton-Account Wizard".

package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/auth/session"
	"github.com/joestump/reduit/internal/proton"
)

// wizardSessionKey is the SCS key holding the in-flight wizard's
// pending account ID. Cleared on commit and on cancel.
const wizardSessionKey = "wizard.account_id"

// maxFormFieldBytes caps each form-field length so a runaway POST
// can't blow up server memory. The Proton login surface fields
// (email, password, TOTP code, passphrase) are all short.
const maxFormFieldBytes = 4096

// wizardPageData is the template view-model for every wizard step.
// `Step` is the 1-5 indicator value; the template branches on `Stage`
// to pick which body to render. `ErrorMessage` is non-empty when the
// previous attempt failed and we're re-rendering with the inline
// error banner.
type wizardPageData struct {
	pageData
	Step          int
	Stage         string // "credentials", "totp", "unlock", "aborted"
	Email         string
	ErrorMessage  string
	StateExpires  string
	StepIndicator []wizardStepIndicator
}

type wizardStepIndicator struct {
	Index int
	Label string
	State string // "done", "current", "pending"
}

// stepIndicatorFor renders the 5-step header given the current stage.
// We collapse the spec's "label sync" + "done" into a single visual
// step beyond unlock; the user lands on the dashboard immediately on
// success so the "Done" tick is implicit.
func stepIndicatorFor(stage WizardStage) []wizardStepIndicator {
	cur := 1
	switch stage {
	case WizardStageCredentials:
		cur = 1
	case WizardStageTOTP:
		cur = 2
	case WizardStageUnlock:
		cur = 3
	}
	labels := []string{"Credentials", "Two-factor", "Mailbox key", "Label sync", "Done"}
	out := make([]wizardStepIndicator, len(labels))
	for i, label := range labels {
		state := "pending"
		switch {
		case i+1 < cur:
			state = "done"
		case i+1 == cur:
			state = "current"
		}
		out[i] = wizardStepIndicator{Index: i + 1, Label: label, State: state}
	}
	return out
}

// wizardReady gates every wizard handler on its dependencies.
// Symmetric to authReady -- a missing service means a fixture or
// startup wiring bug, not a request-time misconfiguration. Logs
// loud, returns an opaque 500.
func (s *Server) wizardReady(w http.ResponseWriter) bool {
	missing := []string{}
	if s.deps.SessionManager == nil {
		missing = append(missing, "SessionManager")
	}
	if s.deps.AccountService == nil {
		missing = append(missing, "AccountService")
	}
	if s.deps.ProtonManager == nil {
		missing = append(missing, "ProtonManager")
	}
	if s.deps.WizardSessions == nil {
		missing = append(missing, "WizardSessions")
	}
	if len(missing) == 0 {
		return true
	}
	s.deps.Logger.Error("wizard handler called without required deps",
		slog.String("missing", strings.Join(missing, ",")))
	http.Error(w, "wizard subsystem not configured", http.StatusInternalServerError)
	return false
}

// requireUser pulls the bound user identity off the SCS session and
// fails closed if anything is missing. RequireSession middleware has
// already gated us, so we expect a non-empty UserID here.
func (s *Server) requireUser(w http.ResponseWriter, r *http.Request) (session.Identity, bool) {
	id := session.GetIdentity(r.Context(), s.deps.SessionManager)
	if id.UserID == "" {
		s.deps.Logger.Warn("wizard: authenticated session has empty UserID",
			slog.String("subject", id.Subject))
		http.Error(w, "session missing user binding", http.StatusInternalServerError)
		return session.Identity{}, false
	}
	return id, true
}

// trimField pulls form value `key`, length-caps it at maxFormFieldBytes,
// and trims surrounding whitespace.
func trimField(r *http.Request, key string) string {
	v := r.FormValue(key)
	if len(v) > maxFormFieldBytes {
		v = v[:maxFormFieldBytes]
	}
	return strings.TrimSpace(v)
}

// resolveWizardSession looks up the in-flight wizard for the bound
// user. Returns the (sessionID, *WizardSession, ok) triple. Failure
// modes:
//
//   - No session ID in the SCS session: ok = false, no error.
//   - Session ID present but expired in the wizard store: ok = false,
//     SCS key cleared in passing.
//   - Session ID present but bound to a different user (cross-user
//     hijack attempt): ok = false, the session is dropped + a Warn is
//     logged; we treat the request as starting from scratch.
//
// On every success we `s.deps.WizardSessions.Put(sess)` to refresh
// the IdleAt timestamp.
func (s *Server) resolveWizardSession(r *http.Request, userID string) (string, *WizardSession, bool) {
	accountID := s.deps.SessionManager.GetString(r.Context(), wizardSessionKey)
	if accountID == "" {
		return "", nil, false
	}
	sess, ok := s.deps.WizardSessions.Get(accountID)
	if !ok {
		s.deps.SessionManager.Remove(r.Context(), wizardSessionKey)
		return accountID, nil, false
	}
	if sess.UserID != userID {
		s.deps.Logger.Warn("wizard: session userID mismatch; dropping",
			slog.String("expected", userID),
			slog.String("got", sess.UserID),
			slog.String("account_id", accountID))
		s.deps.WizardSessions.Drop(accountID)
		s.deps.SessionManager.Remove(r.Context(), wizardSessionKey)
		return "", nil, false
	}
	return accountID, sess, true
}

// renderWizard dispatches to the right step template based on the
// session's stage.
func (s *Server) renderWizard(w http.ResponseWriter, r *http.Request, sess *WizardSession, errMsg string) {
	id, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	stage := WizardStageCredentials
	username := ""
	if sess != nil {
		stage = sess.Stage
		username = sess.Username
	}
	stageName := "credentials"
	switch stage {
	case WizardStageTOTP:
		stageName = "totp"
	case WizardStageUnlock:
		stageName = "unlock"
	}
	data := wizardPageData{
		pageData: pageData{
			Title:    "Add Proton account",
			Identity: newIdentityView(id),
			IsAdmin:  id.IsAdmin,
		},
		Step:          int(stage) + 1,
		Stage:         stageName,
		Email:         username,
		ErrorMessage:  errMsg,
		StateExpires:  "Session expires in 30 min",
		StepIndicator: stepIndicatorFor(stage),
	}
	s.renderPage(w, r, "wizard", data)
}

// renderWizardError renders a terminal error page (e.g. 3 TOTP
// failures, FIDO2-only account, server-side abort). The wizard
// session is already dropped by the caller; the page links back to
// /accounts/setup so the user can restart.
func (s *Server) renderWizardError(w http.ResponseWriter, r *http.Request, message string) {
	id, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	data := wizardPageData{
		pageData: pageData{
			Title:    "Add Proton account",
			Identity: newIdentityView(id),
			IsAdmin:  id.IsAdmin,
		},
		Stage:         "aborted",
		ErrorMessage:  message,
		StepIndicator: stepIndicatorFor(WizardStageCredentials),
	}
	s.renderPage(w, r, "wizard", data)
}

// handleWizardStart renders the wizard. If no in-flight session
// exists for the user, a fresh pending_proton_setup account row is
// created and bound to a new wizard session in stage Credentials.
// Otherwise we render whichever step the existing session is on.
func (s *Server) handleWizardStart(w http.ResponseWriter, r *http.Request) {
	if !s.wizardReady(w) {
		return
	}
	id, ok := s.requireUser(w, r)
	if !ok {
		return
	}

	if _, sess, ok := s.resolveWizardSession(r, id.UserID); ok {
		s.renderWizard(w, r, sess, "")
		return
	}

	// No live session -- mint a fresh pending account row + wizard
	// session entry in stage 1.
	acct, err := s.deps.AccountService.Create(r.Context(), account.CreateParams{UserID: id.UserID})
	if err != nil {
		s.deps.Logger.Error("wizard/start: create account: " + err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sess := &WizardSession{
		AccountID: acct.ID,
		UserID:    id.UserID,
		Stage:     WizardStageCredentials,
	}
	s.deps.WizardSessions.Put(sess)
	s.deps.SessionManager.Put(r.Context(), wizardSessionKey, acct.ID)

	s.renderWizard(w, r, sess, "")
}

// handleWizardAuth processes the credentials POST. Runs the SRP
// login flow against Proton; on success, captures the freshly minted
// session in the wizard store and renders either step 2 (TOTP) or
// jumps straight to step 3 (mailbox passphrase).
//
// FIDO2-only accounts are surfaced as a terminal error -- the wizard
// scope this PR ships covers TOTP only (FIDO2 is deferred per #24
// scope discussion; the user uses passkeys via Proton Pass + TOTP).
func (s *Server) handleWizardAuth(w http.ResponseWriter, r *http.Request) {
	if !s.wizardReady(w) {
		return
	}
	id, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	accountID, sess, ok := s.resolveWizardSession(r, id.UserID)
	if !ok {
		// Lost session -- bounce back to the start which mints a new one.
		http.Redirect(w, r, "/accounts/setup", http.StatusSeeOther)
		return
	}
	if sess.Stage != WizardStageCredentials {
		// Out-of-order POST. Render whichever step we are actually on.
		s.renderWizard(w, r, sess, "")
		return
	}

	username := trimField(r, "username")
	password := trimField(r, "password")
	if username == "" || password == "" {
		s.renderWizard(w, r, sess, "Please enter your Proton email and password.")
		return
	}

	client, auth, err := s.deps.ProtonManager.NewClientWithLogin(r.Context(), username, password)
	if err != nil {
		s.deps.Logger.Warn("wizard/auth: proton login failed",
			slog.String("account_id", accountID),
			slog.String("error", err.Error()))
		s.renderWizard(w, r, sess, "Proton rejected those credentials. Double-check the email and password.")
		return
	}

	sess.Username = username
	sess.Client = client
	sess.RefreshToken = auth.RefreshToken
	sess.ProtonUserID = auth.UserID

	// FIDO2-only accounts: the spec calls for FIDO2 support but this
	// PR's scope is TOTP only. Surface a clear "not yet supported"
	// message rather than letting the user enter a TOTP code that
	// will never validate.
	twoFA := auth.TwoFA.Enabled
	switch {
	case twoFA == 0:
		// No 2FA -- jump straight to mailbox unlock.
		sess.Stage = WizardStageUnlock
	case twoFA&proton.HasTOTP != 0:
		// TOTP path (covers HasTOTP and HasFIDO2AndTOTP).
		sess.Stage = WizardStageTOTP
	default:
		// FIDO2-only.
		_ = client.Logout(r.Context())
		s.deps.WizardSessions.Drop(accountID)
		s.deps.SessionManager.Remove(r.Context(), wizardSessionKey)
		_, _ = s.deps.AccountService.Delete(r.Context(), accountID)
		s.renderWizardError(w, r,
			"This Proton account requires a FIDO2 security key. Reduit's wizard supports TOTP-based 2FA in this release; FIDO2 support is on the roadmap.")
		return
	}

	s.deps.WizardSessions.Put(sess)
	s.renderWizard(w, r, sess, "")
}

// handleWizardTOTP processes the TOTP submit. Three failures abort
// the wizard.
func (s *Server) handleWizardTOTP(w http.ResponseWriter, r *http.Request) {
	if !s.wizardReady(w) {
		return
	}
	id, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	accountID, sess, ok := s.resolveWizardSession(r, id.UserID)
	if !ok {
		http.Redirect(w, r, "/accounts/setup", http.StatusSeeOther)
		return
	}
	if sess.Stage != WizardStageTOTP {
		s.renderWizard(w, r, sess, "")
		return
	}
	if sess.Client == nil {
		s.deps.Logger.Error("wizard/2fa: session has no client",
			slog.String("account_id", accountID))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	code := trimField(r, "code")
	if code == "" {
		s.renderWizard(w, r, sess, "Enter the 6-digit code from your authenticator app.")
		return
	}

	if err := sess.Client.AuthTOTP(r.Context(), code); err != nil {
		sess.TOTPAttempts++
		s.deps.Logger.Warn("wizard/2fa: totp rejected",
			slog.String("account_id", accountID),
			slog.Int("attempt", sess.TOTPAttempts),
			slog.String("error", err.Error()))
		if sess.TOTPAttempts >= MaxWizardTOTPAttempts {
			// Hard abort: tear down session, soft-delete the pending
			// account, render the dead-end page.
			_ = sess.Client.Logout(r.Context())
			s.deps.WizardSessions.Drop(accountID)
			s.deps.SessionManager.Remove(r.Context(), wizardSessionKey)
			if _, delErr := s.deps.AccountService.Delete(r.Context(), accountID); delErr != nil {
				s.deps.Logger.Warn("wizard/2fa: soft-delete after abort: " + delErr.Error())
			}
			s.renderWizardError(w, r,
				"Three failed two-factor attempts. The wizard has been reset for safety -- restart from the dashboard if you'd like to try again.")
			return
		}
		s.deps.WizardSessions.Put(sess)
		s.renderWizard(w, r, sess,
			fmt.Sprintf("Code rejected. %d attempt(s) remaining before the wizard resets.",
				MaxWizardTOTPAttempts-sess.TOTPAttempts))
		return
	}

	sess.Stage = WizardStageUnlock
	s.deps.WizardSessions.Put(sess)
	s.renderWizard(w, r, sess, "")
}

// handleWizardUnlock processes the mailbox-passphrase POST. On
// success: persists the refresh token, the sealed mailbox passphrase,
// the Proton user id + email; transitions the account to active;
// drops the wizard session; redirects to /accounts.
//
// On unlock failure (wrong passphrase) we keep the wizard alive and
// re-render step 3 with an inline error -- per ADR-0010 this is a
// "user mistype", not a security event.
func (s *Server) handleWizardUnlock(w http.ResponseWriter, r *http.Request) {
	if !s.wizardReady(w) {
		return
	}
	id, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	accountID, sess, ok := s.resolveWizardSession(r, id.UserID)
	if !ok {
		http.Redirect(w, r, "/accounts/setup", http.StatusSeeOther)
		return
	}
	if sess.Stage != WizardStageUnlock {
		s.renderWizard(w, r, sess, "")
		return
	}
	if sess.Client == nil {
		s.deps.Logger.Error("wizard/unlock: session has no client",
			slog.String("account_id", accountID))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	passphrase := trimField(r, "passphrase")
	if passphrase == "" {
		s.renderWizard(w, r, sess, "Enter your Proton mailbox passphrase.")
		return
	}

	if err := s.commitWizard(r, sess, passphrase); err != nil {
		// Three branches:
		//  1. errWizardUnlock: wrong passphrase. Re-render step 3
		//     with an inline error (the wizard stays alive).
		//  2. ErrAccountAlreadyExists: this Proton account is
		//     already bound to another row owned by the same user.
		//     Tear the wizard down (we can't pin a duplicate
		//     identity onto the pending row) and surface a clear
		//     message.
		//  3. anything else: 500.
		switch {
		case errors.Is(err, errWizardUnlock):
			s.renderWizard(w, r, sess,
				"Reduit could not unlock your mailbox with that passphrase. Use your Proton login password unless you've set a separate mailbox key.")
			return
		case errors.Is(err, account.ErrAccountAlreadyExists):
			_ = sess.Client.Logout(r.Context())
			s.deps.WizardSessions.Drop(accountID)
			s.deps.SessionManager.Remove(r.Context(), wizardSessionKey)
			if _, delErr := s.deps.AccountService.Delete(r.Context(), accountID); delErr != nil {
				s.deps.Logger.Warn("wizard/unlock: soft-delete after duplicate: " + delErr.Error())
			}
			s.renderWizardError(w, r,
				"This Proton account is already linked to one of your Reduit accounts. Open the dashboard to manage it.")
			return
		default:
			s.deps.Logger.Error("wizard/unlock: commit",
				slog.String("account_id", accountID),
				slog.String("error", err.Error()))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	// Commit success: the live proton session is no longer needed.
	// Drop wizard state, clear the SCS key, redirect home.
	s.deps.WizardSessions.Drop(accountID)
	s.deps.SessionManager.Remove(r.Context(), wizardSessionKey)

	s.deps.Logger.Info("wizard/unlock: account active",
		slog.String("account_id", accountID),
		slog.String("user_id", id.UserID))

	http.Redirect(w, r, "/accounts", http.StatusSeeOther)
}

// errWizardUnlock is the sentinel returned by commitWizard when the
// user's mailbox passphrase is wrong (vs. a DB / schema / network
// failure). The handler branches on this to decide between an inline
// re-render and a 500.
var errWizardUnlock = errors.New("wizard: mailbox unlock failed")

// commitWizard runs the Proton-side unlock + persists every column
// the dashboard and sync supervisor need. Returns errWizardUnlock for
// "wrong passphrase" so the handler can re-render step 3 inline.
func (s *Server) commitWizard(r *http.Request, sess *WizardSession, passphrase string) error {
	user, err := sess.Client.GetUser(r.Context())
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if len(user.Keys) == 0 {
		return fmt.Errorf("user has no keys")
	}
	salts, err := sess.Client.KeySalts(r.Context())
	if err != nil {
		return fmt.Errorf("key salts: %w", err)
	}
	saltedKey, err := salts.SaltForKey([]byte(passphrase), user.Keys.Primary().ID)
	if err != nil {
		return fmt.Errorf("%w: %v", errWizardUnlock, err)
	}
	addresses, err := sess.Client.GetAddresses(r.Context())
	if err != nil {
		return fmt.Errorf("get addresses: %w", err)
	}
	if _, _, err := sess.Client.Unlock(user, addresses, saltedKey); err != nil {
		return fmt.Errorf("%w: %v", errWizardUnlock, err)
	}

	// Unlock succeeded. Persist everything in this fixed order:
	//   1. Refresh token (most sensitive bit -- gets sealed first).
	//   2. Mailbox passphrase (also sealed under the per-account key).
	//   3. ProtonUserID + Email columns.
	//   4. Transition to active (fires the supervisor callback).
	//
	// Each step is its own DB write; a partial failure leaves the
	// row in pending_proton_setup which is fine for resume.
	if err := s.deps.AccountService.SealRefreshToken(r.Context(), sess.AccountID, []byte(sess.RefreshToken)); err != nil {
		return fmt.Errorf("seal refresh token: %w", err)
	}
	if err := s.deps.AccountService.SealMailboxPassphrase(r.Context(), sess.AccountID, []byte(passphrase)); err != nil {
		return fmt.Errorf("seal mailbox passphrase: %w", err)
	}
	if err := s.setAccountProtonIdentity(r, sess); err != nil {
		return err
	}
	if _, err := s.deps.AccountService.Transition(r.Context(), sess.AccountID, account.StateActive); err != nil {
		return fmt.Errorf("transition active: %w", err)
	}
	return nil
}

// setAccountProtonIdentity stamps the proton_user_id + email columns
// on the pending account row. The columns were left NULL by Create
// (ADR-0010 says Proton identity isn't known until the wizard runs),
// so this is the first write that pins the row to a Proton account.
func (s *Server) setAccountProtonIdentity(r *http.Request, sess *WizardSession) error {
	return s.deps.AccountService.SetProtonIdentity(r.Context(), sess.AccountID, sess.ProtonUserID, sess.Username)
}

// handleWizardCancel discards the in-flight wizard. Soft-deletes the
// pending account row so it doesn't pile up in the user's dashboard.
// Idempotent.
func (s *Server) handleWizardCancel(w http.ResponseWriter, r *http.Request) {
	if !s.wizardReady(w) {
		return
	}
	id, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	accountID, _, hasSession := s.resolveWizardSession(r, id.UserID)
	if hasSession || accountID != "" {
		s.deps.WizardSessions.Drop(accountID)
		s.deps.SessionManager.Remove(r.Context(), wizardSessionKey)
		if _, err := s.deps.AccountService.Delete(r.Context(), accountID); err != nil {
			s.deps.Logger.Warn("wizard/cancel: soft-delete: " + err.Error())
		}
	}
	http.Redirect(w, r, "/accounts", http.StatusSeeOther)
}
