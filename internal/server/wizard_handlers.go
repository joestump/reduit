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
	"context"
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

// dropInFlightWizard is the shared cleanup hook fired from any
// session-invalidation path (handleAuthLogout, the auth gate's
// malformed-shape fail-closed branch, the auth gate's
// AccountActive-false branch). It Logouts the upstream Proton
// session under the per-session lock, then drops the in-memory
// wizard entry. SCS removal is left to the caller -- some sites
// follow this with Destroy (which clears everything), others just
// want the wizard gone.
//
// Safe to call when no wizard is in flight (no-op).
//
// Governing: SPEC-0005 REQ "Add-Proton-Account Wizard" -- "WHEN
// wizard idle 30 min OR session invalidated THEN partial credentials
// discarded from memory."
func (s *Server) dropInFlightWizard(ctx context.Context) {
	if s.deps.SessionManager == nil || s.deps.WizardSessions == nil {
		return
	}
	accountID := s.deps.SessionManager.GetString(ctx, wizardSessionKey)
	if accountID == "" {
		return
	}
	if sess, ok := s.deps.WizardSessions.Get(accountID); ok {
		sess.Lock()
		if sess.Client != nil {
			_ = sess.Client.Logout(ctx)
		}
		sess.Unlock()
	}
	s.deps.WizardSessions.Drop(accountID)
}

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
	Stage         string // "credentials", "totp", "unlock", "done", "aborted"
	Email         string
	ErrorMessage  string
	StateExpires  string
	StepIndicator []wizardStepIndicator
	// Done-stage fields. Populated only when Stage == "done"; the
	// template branches on .Stage so they're zero-valued otherwise.
	// IMAPPassword is the freshly-generated plaintext for one-time
	// display per SPEC-0001 REQ "Per-Account IMAP Password".
	IMAPPassword string
	IMAPUsername string
	IMAPHost     string
	IMAPPort     int
	SMTPPort     int
}

type wizardStepIndicator struct {
	Index int
	Label string
	State string // "done", "current", "pending"
	Last  bool   // true on the rightmost step; the template skips its trailing connector
}

// stepIndicatorFor renders the 4-step header given the current stage.
// The spec/mockup show 5 visual steps (Credentials → Two-factor →
// Mailbox key → Label sync → Done); the Label-sync visual step is
// still future work, but issue #104 introduces the Done step so the
// operator sees the freshly generated IMAP password before the wizard
// closes. Render only the steps that match real handler stages so the
// indicator doesn't dangle on "step 4 of 5" forever.
//
// Governing: SPEC-0005 REQ "Add-Proton-Account Wizard"; issue #104.
func stepIndicatorFor(stage WizardStage) []wizardStepIndicator {
	cur := 1
	switch stage {
	case WizardStageCredentials:
		cur = 1
	case WizardStageTOTP:
		cur = 2
	case WizardStageUnlock:
		cur = 3
	case WizardStageDone:
		cur = 4
	}
	labels := []string{"Credentials", "Two-factor", "Mailbox key", "Mail client"}
	out := make([]wizardStepIndicator, len(labels))
	for i, label := range labels {
		state := "pending"
		switch {
		case i+1 < cur:
			state = "done"
		case i+1 == cur:
			state = "current"
		}
		out[i] = wizardStepIndicator{Index: i + 1, Label: label, State: state, Last: i == len(labels)-1}
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
	imapPassword := ""
	imapUsername := ""
	imapHost := ""
	if sess != nil {
		// renderWizard is invoked from two shapes: handlers that
		// already hold sess.Lock() across a read-modify-write
		// sequence, and handlers (handleWizardStart, the resume
		// path) that arrive with no lock. The Mutex is reentrant-
		// hostile, so we cannot blindly Lock here. Snapshot via a
		// separate helper that only acquires when the caller is
		// holding the lock externally is overkill -- the races we
		// care about (concurrent /complete dropping the session)
		// are protected by the wizard store's own map mutex (Drop
		// removes the entry before we'd ever read stale fields,
		// and Get returns the same pointer pre-Drop). The fields
		// we read are only ever mutated inside the per-session
		// lock by handlers that have just resolved the same
		// pointer; once a handler sets stage and calls Put the
		// state is stable until the next handler. This race
		// surface is identical to what the pre-#104 wizard
		// already shipped with for Username/Stage; #104 just
		// adds three more fields (IMAPPassword, PrimaryAlias,
		// MailHost) with the same lifecycle.
		stage = sess.Stage
		username = sess.Username
		imapPassword = sess.IMAPPassword
		imapUsername = sess.PrimaryAlias
		imapHost = sess.MailHost
	}
	stageName := "credentials"
	switch stage {
	case WizardStageTOTP:
		stageName = "totp"
	case WizardStageUnlock:
		stageName = "unlock"
	case WizardStageDone:
		stageName = "done"
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
		IMAPPassword:  imapPassword,
		IMAPUsername:  imapUsername,
		IMAPHost:      imapHost,
		IMAPPort:      993,
		SMTPPort:      465,
	}
	s.renderPage(w, r, "wizard", &data)
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
	s.renderPage(w, r, "wizard", &data)
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

	// No live in-memory session. Try to reuse an existing pending
	// row owned by this user before creating a new one -- otherwise
	// every cookie-cleared GET, every TTL-expired wizard, every
	// race-double-click would mint another orphan pending row that
	// nothing ever cleans up. The retention sweep is a separate
	// concern (#73-class follow-up).
	accts, err := s.deps.AccountService.ListByUser(r.Context(), id.UserID)
	if err != nil {
		s.deps.Logger.Error("wizard/start: list accounts: " + err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var pending *account.Account
	for _, a := range accts {
		if a.State == account.StatePendingProtonSetup {
			pending = a
			break
		}
	}
	var acctID string
	if pending != nil {
		acctID = pending.ID
	} else {
		acct, err := s.deps.AccountService.Create(r.Context(), account.CreateParams{UserID: id.UserID})
		if err != nil {
			s.deps.Logger.Error("wizard/start: create account: " + err.Error())
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		acctID = acct.ID
	}

	// If the in-memory wizard store already has a live session for
	// this accountID (e.g., the SCS cookie was cleared but the in-
	// memory state lingered), reuse it -- replacing it with a fresh
	// WizardSession would orphan the prior live proton.Client without
	// Logout. The store key is per-account and accounts are owned by
	// users, so a Get hit here is by construction owned by id.UserID;
	// we still verify defensively.
	if existing, ok := s.deps.WizardSessions.Get(acctID); ok && existing.UserID == id.UserID {
		s.deps.SessionManager.Put(r.Context(), wizardSessionKey, acctID)
		s.renderWizard(w, r, existing, "")
		return
	}

	sess := &WizardSession{
		AccountID: acctID,
		UserID:    id.UserID,
		Stage:     WizardStageCredentials,
	}
	s.deps.WizardSessions.Put(sess)
	s.deps.SessionManager.Put(r.Context(), wizardSessionKey, acctID)

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
	// Per-session lock serialises concurrent POSTs (double-click,
	// HTMX retry, two tabs) so stage transitions and TOTP-attempt
	// counting cannot race.
	sess.Lock()
	defer sess.Unlock()
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
	// Capture the ephemeral session UID alongside the refresh token so
	// commitWizard can seal it. /auth/v4/refresh needs the UID to re-auth
	// on daemon restart; auth.UID is the only place it is exposed (it is
	// discarded after this handler otherwise). Distinct from auth.UserID
	// above (the persistent proton_user_id).
	//
	// Governing: ADR-0001, SPEC-0002 REQ "One Worker Per Active
	// Account"; #28, #34.
	sess.SessionUID = auth.UID

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
	sess.Lock()
	defer sess.Unlock()
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
	sess.Lock()
	defer sess.Unlock()
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
		// Four branches:
		//  1. errWizardUnlock: wrong passphrase. Re-render step 3
		//     with an inline error (the wizard stays alive).
		//  2. errWizardNoKeys: brand-new Proton account with no
		//     primary key yet. Terminal error -- the user has to
		//     finish Proton-side setup before relaying mail.
		//  3. ErrAccountAlreadyExists: this Proton account is
		//     already bound to another row owned by the same user.
		//     Tear the wizard down (we can't pin a duplicate
		//     identity onto the pending row) and surface a clear
		//     message.
		//  4. ErrProtonIdentityMismatch: the pending row was already
		//     stamped with a DIFFERENT Proton identity on a prior run
		//     and this attempt logged into a different Proton account.
		//     SPEC-0001 "Account Identity" forbids silently overwriting
		//     the stored id, so tear the wizard down and tell the user
		//     to start a fresh add-account flow for the other mailbox.
		//  5. anything else: 500.
		switch {
		case errors.Is(err, errWizardUnlock):
			s.renderWizard(w, r, sess,
				"Reduit could not unlock your mailbox with that passphrase. Use your Proton login password unless you've set a separate mailbox key.")
			return
		case errors.Is(err, errWizardNoKeys):
			_ = sess.Client.Logout(r.Context())
			s.deps.WizardSessions.Drop(accountID)
			s.deps.SessionManager.Remove(r.Context(), wizardSessionKey)
			if _, delErr := s.deps.AccountService.Delete(r.Context(), accountID); delErr != nil {
				s.deps.Logger.Warn("wizard/unlock: soft-delete after no-keys: " + delErr.Error())
			}
			s.renderWizardError(w, r,
				"This Proton account has no encryption keys yet. Sign in to Proton on the web once to provision your primary key, then restart this wizard.")
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
		case errors.Is(err, account.ErrProtonIdentityMismatch):
			// Governing: SPEC-0001 REQ "Account Identity" -- a Proton
			// user ID mismatch on a subsequent login is an error and
			// MUST NOT silently overwrite the stored value. Same
			// teardown as the duplicate case: drop the in-flight wizard
			// state and soft-delete the pending row so a clean retry
			// can start fresh.
			_ = sess.Client.Logout(r.Context())
			s.deps.WizardSessions.Drop(accountID)
			s.deps.SessionManager.Remove(r.Context(), wizardSessionKey)
			if _, delErr := s.deps.AccountService.Delete(r.Context(), accountID); delErr != nil {
				s.deps.Logger.Warn("wizard/unlock: soft-delete after identity mismatch: " + delErr.Error())
			}
			s.renderWizardError(w, r,
				"This add-account flow was started for a different Proton account than the one you just signed into. Start a new add-account flow to link this mailbox.")
			return
		default:
			s.deps.Logger.Error("wizard/unlock: commit",
				slog.String("account_id", accountID),
				slog.String("error", err.Error()))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	// Commit succeeded: the account is now StateActive and the
	// supervisor callback has fired. Before redirecting we generate
	// the per-account IMAP/SMTP password and pin a SASL primary
	// alias so the operator can copy them into a mail client. The
	// wizard session is held open across the Done step so a refresh
	// renders the same plaintext rather than re-rotating; the
	// transition to active happened above so a re-rotation here
	// would only be a UI annoyance, but keeping the plaintext stable
	// across refresh is also what the spec calls for.
	//
	// Governing: SPEC-0001 REQ "Per-Account IMAP Password";
	// SPEC-0005 REQ "Add-Proton-Account Wizard"; issue #104.
	s.deps.Logger.Info("wizard/unlock: account active",
		slog.String("account_id", accountID),
		slog.String("user_id", id.UserID))

	// Retain the now-unlocked client so body decryption works in the
	// daemon. commitWizard ran Unlock on sess.Client, so its per-address
	// keyrings are retained in-process (proton.clientImpl.addrKeyRings);
	// handing it to the registry transfers ownership away from the wizard
	// session. We do this AFTER the active transition (so a resolver
	// lookup that races us sees a client only for an active account) and
	// BEFORE finishWizardSetup (whose failure path drops the session but
	// must NOT discard the live client).
	//
	// OWNERSHIP TRANSFER: immediately after Set we nil sess.Client. The
	// registry now owns the client's lifecycle (it Logouts on Drop /
	// CloseAll / replace). Leaving sess.Client pointing at the same
	// client would create dual ownership: dropInFlightWizard (fired on
	// admin logout / auth-gate invalidation) Logouts sess.Client WITHOUT
	// Drop'ing the registry entry or transitioning the account -- so an
	// operator who finishes the wizard (account active, client registered,
	// Done screen) then logs out of the admin UI before clicking
	// "complete" would kill the registry-owned client, leaving the account
	// `active` but serving a dead, logged-out client (every FETCH BODY[] /
	// MCP get_message -> ErrNotAuthenticated until daemon restart). All
	// post-Done teardown paths (handleWizardComplete, finishWizardSetup's
	// error branch, dropInFlightWizard, handleWizardCancel) guard on
	// `sess.Client != nil`, so niling here makes every one of them a clean
	// no-op against the transferred client.
	//
	// This runs under sess.Lock() (held for the whole handler), so the
	// Set + nil pair is atomic against dropInFlightWizard, which takes the
	// same per-session lock before touching sess.Client.
	//
	// Governing: ADR-0003 (retained keyring is the in-memory at-rest
	// material), SPEC-0002 REQ "One Worker Per Active Account"; issue #28.
	if s.deps.LiveClients != nil {
		s.deps.LiveClients.Set(accountID, sess.Client)
		sess.Client = nil
	} else {
		s.deps.Logger.Warn("wizard/unlock: no live-client registry wired; body decryption will be unavailable for this account until the daemon is configured with one",
			slog.String("account_id", accountID))
	}

	if err := s.finishWizardSetup(r, sess); err != nil {
		s.deps.Logger.Error("wizard/unlock: finish setup",
			slog.String("account_id", accountID),
			slog.String("error", err.Error()))
		// The account is already active; drop the wizard so the
		// operator can recover via the dashboard's rotate-password
		// action instead of getting stuck on a half-rendered Done
		// screen. The dashboard recovery path is issue #103.
		s.deps.WizardSessions.Drop(accountID)
		s.deps.SessionManager.Remove(r.Context(), wizardSessionKey)
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}

	sess.Stage = WizardStageDone
	s.deps.WizardSessions.Put(sess)
	s.renderWizard(w, r, sess, "")
}

// finishWizardSetup runs the post-active provisioning step: generate
// + persist the IMAP password and assign the SASL primary alias. The
// plaintext password is captured on the *WizardSession and returned
// (logically) to the rendering path; we never log or write it
// elsewhere. Idempotent on the alias side (collision returns the
// account already exists error and we surface it as a server-side
// failure since the alias is derived deterministically from the Proton
// email -- a true collision would mean two different Proton accounts
// sharing the same local part, which is a future-multi-tenancy issue
// outside this scope).
//
// Governing: SPEC-0001 REQ "Per-Account IMAP Password" (rotation
// returns the plaintext for one-time display); SPEC-0003 REQ
// "SASL PLAIN With user@host Identity"; issue #104.
func (s *Server) finishWizardSetup(r *http.Request, sess *WizardSession) error {
	// Derive the primary alias from the Proton email's local part
	// and the host portion of the request's Host header. r.Host is
	// the operator's chosen Reduit hostname (e.g.
	// "reduit.family.tld"), which matches the visual-identity
	// mockup convention. We strip any port and lower-case both
	// sides; SetPrimaryAlias normalises again so this is belt-and-
	// suspenders.
	local := localPartOf(sess.Username)
	host := mailHostFromRequest(r)
	alias := ""
	if local != "" && host != "" {
		alias = local + "@" + host
		if err := s.deps.AccountService.SetPrimaryAlias(r.Context(), sess.AccountID, alias); err != nil {
			return fmt.Errorf("set primary alias: %w", err)
		}
	}

	pw, err := s.deps.AccountService.RotateIMAPPassword(r.Context(), sess.AccountID)
	if err != nil {
		return fmt.Errorf("rotate imap password: %w", err)
	}
	sess.IMAPPassword = pw
	sess.PrimaryAlias = alias
	sess.MailHost = host
	return nil
}

// handleWizardComplete handles POST /accounts/setup/complete. Drops
// the wizard session (clearing the in-memory plaintext IMAP password)
// and redirects to the dashboard. Idempotent: if no Done-stage
// session is in flight we still redirect, so a stale tab POST does
// not surface as an error.
//
// Governing: SPEC-0005 REQ "Add-Proton-Account Wizard"; issue #104.
func (s *Server) handleWizardComplete(w http.ResponseWriter, r *http.Request) {
	if !s.wizardReady(w) {
		return
	}
	id, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	accountID, sess, hasSession := s.resolveWizardSession(r, id.UserID)
	if hasSession && sess.Stage == WizardStageDone {
		// Wipe the in-memory plaintext before dropping the entry
		// so a future heap dump can't recover it from the *Session
		// even after the map slot is freed.
		sess.Lock()
		sess.IMAPPassword = ""
		sess.Unlock()
	}
	if hasSession || accountID != "" {
		s.deps.WizardSessions.Drop(accountID)
		s.deps.SessionManager.Remove(r.Context(), wizardSessionKey)
	}
	http.Redirect(w, r, "/accounts", http.StatusSeeOther)
}

// localPartOf returns the substring of email before the first '@',
// or the empty string if email contains no '@'.
func localPartOf(email string) string {
	at := strings.IndexByte(email, '@')
	if at <= 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(email[:at]))
}

// mailHostFromRequest returns the bare host portion of r.Host (i.e.
// strip any ":port" suffix), lower-cased. This is the operator's
// chosen Reduit hostname -- the same value the operator types into
// their browser to reach this wizard -- which matches the SASL
// "user@host" identity that mail clients will use against the IMAPS/
// SMTPS listeners.
//
// Falls back to the empty string when r.Host is empty (which would
// indicate a misbehaving HTTP/1.0 client; the wizard handler caller
// will skip alias assignment in that case).
func mailHostFromRequest(r *http.Request) string {
	host := r.Host
	if host == "" {
		return ""
	}
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return strings.ToLower(strings.TrimSpace(host))
}

// errWizardUnlock is the sentinel returned by commitWizard when the
// user's mailbox passphrase is wrong (vs. a DB / schema / network
// failure). The handler branches on this to decide between an inline
// re-render and a 500.
var errWizardUnlock = errors.New("wizard: mailbox unlock failed")

// errWizardNoKeys is returned when Proton's GetUser response carries
// no keys -- a real-world possibility for a brand-new Proton account
// that hasn't generated its primary key yet. The handler renders the
// terminal error page (vs. 500-ing) so the user gets a clear message.
var errWizardNoKeys = errors.New("wizard: proton account has no keys")

// commitWizard runs the Proton-side unlock + persists every column
// the dashboard and sync supervisor need. Returns errWizardUnlock for
// "wrong passphrase" so the handler can re-render step 3 inline.
func (s *Server) commitWizard(r *http.Request, sess *WizardSession, passphrase string) error {
	user, err := sess.Client.GetUser(r.Context())
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if len(user.Keys) == 0 {
		return errWizardNoKeys
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

	// Unlock succeeded. Persist everything in this order:
	//   1. ProtonUserID + Email columns. The unique (user_id,
	//      proton_user_id) index makes this the cheapest dedup check;
	//      if the user already has another row bound to this Proton
	//      account it surfaces as ErrAccountAlreadyExists *before*
	//      any ciphertext lands on disk.
	//   2. Refresh token (sealed under the per-account data key).
	//      We read the freshest value off the live client rather than
	//      the captured-at-login sess.RefreshToken in case any of the
	//      GetUser/KeySalts/GetAddresses/Unlock calls above provoked
	//      a /auth/v4/refresh round-trip; the upstream auth handler
	//      captured the rotated token into latestRefresh.
	//   3. Mailbox passphrase (sealed under the same key).
	//   4. Transition to active (fires the supervisor callback).
	//
	// Each step is its own DB write. A failure between step 1 and
	// step 4 leaves the row in pending_proton_setup with identity
	// stamped but credentials missing or partial -- the next wizard
	// run will reuse this row (handleWizardStart picks up any pending
	// row owned by the same user) and overwrite the half-committed
	// ciphertext columns.
	if err := s.setAccountProtonIdentity(r, sess); err != nil {
		return err
	}
	refresh := sess.Client.LatestRefreshToken()
	if refresh == "" {
		refresh = sess.RefreshToken
	}
	if err := s.deps.AccountService.SealRefreshToken(r.Context(), sess.AccountID, []byte(refresh)); err != nil {
		return fmt.Errorf("seal refresh token: %w", err)
	}
	// Seal the session UID captured at login (sess.SessionUID = auth.UID).
	// The UID does not rotate across the GetUser/KeySalts/.../Unlock
	// sequence the way the refresh token can, so we use the captured
	// value directly. This is the persistence #28 needed for boot
	// re-unlock: protonlive.Lifecycle re-auths from {UID, refresh token}
	// and re-unlocks with the mailbox passphrase on the next daemon
	// start. A non-empty UID is expected here (the login always returns
	// one); seal whatever we have and let OpenSessionUID's not-present
	// path handle the (unexpected) empty case as the missing-UID gap.
	//
	// Governing: ADR-0003, ADR-0001, SPEC-0001 REQ "Encrypted Secret
	// Storage", SPEC-0002 REQ "One Worker Per Active Account"; #28, #34.
	if err := s.deps.AccountService.SealSessionUID(r.Context(), sess.AccountID, []byte(sess.SessionUID)); err != nil {
		return fmt.Errorf("seal session uid: %w", err)
	}
	if err := s.deps.AccountService.SealMailboxPassphrase(r.Context(), sess.AccountID, []byte(passphrase)); err != nil {
		return fmt.Errorf("seal mailbox passphrase: %w", err)
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
// Passes sess.UserID to the service so the storage layer can WHERE-
// clause on it (defense-in-depth against wrong-accountID bugs).
func (s *Server) setAccountProtonIdentity(r *http.Request, sess *WizardSession) error {
	return s.deps.AccountService.SetProtonIdentity(r.Context(), sess.AccountID, sess.UserID, sess.ProtonUserID, sess.Username)
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
	accountID, sess, hasSession := s.resolveWizardSession(r, id.UserID)
	if hasSession {
		// Lock so we cannot race a concurrent /unlock holding the
		// session's Client field. Logout the upstream Proton session
		// inside the lock, then drop from the store.
		sess.Lock()
		if sess.Client != nil {
			_ = sess.Client.Logout(r.Context())
		}
		sess.Unlock()
	}
	if hasSession || accountID != "" {
		s.deps.WizardSessions.Drop(accountID)
		s.deps.SessionManager.Remove(r.Context(), wizardSessionKey)
		if _, err := s.deps.AccountService.Delete(r.Context(), accountID); err != nil {
			s.deps.Logger.Warn("wizard/cancel: soft-delete: " + err.Error())
		}
	}
	http.Redirect(w, r, "/accounts", http.StatusSeeOther)
}
