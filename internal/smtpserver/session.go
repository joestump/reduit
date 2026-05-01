// Per-connection SMTP submission session. Owns the SASL PLAIN auth
// flow. MAIL FROM authorization, recipient cap, and the DATA stub
// land in a follow-up commit.
//
// Governing: ADR-0007 (emersion go-smtp), SPEC-0004.

package smtpserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-sasl"
	smtp "github.com/emersion/go-smtp"

	"github.com/joestump/reduit/internal/account"
)

// loginTimeout bounds the database lookup + bcrypt verify. bcrypt
// cost 12 takes ~250ms on commodity hardware; 5s is comfortable
// headroom even on slow ARM SBCs while still preventing a slowloris-
// style auth that holds the connection forever.
const loginTimeout = 5 * time.Second

// session is one SMTP client connection. Implements emersion/go-smtp's
// `Session` and `AuthSession` interfaces.
type session struct {
	backend *Backend
	conn    *smtp.Conn
	remote  string
	rateKey string
	logger  *slog.Logger

	mu         sync.Mutex
	accountID  string
	primary    string // normalised primary alias of the authed account
	registered bool
}

// Compile-time interface assertions.
var (
	_ smtp.Session     = (*session)(nil)
	_ smtp.AuthSession = (*session)(nil)
)

// AuthMechanisms returns the SASL mechanisms we accept. PLAIN only —
// matching SPEC-0003's parallel commitment for IMAP.
//
// Governing: SPEC-0004 REQ "SASL PLAIN Authentication Matching IMAP".
func (s *session) AuthMechanisms() []string {
	return []string{sasl.Plain}
}

// Auth returns a SASL server for the requested mechanism. Anything
// other than PLAIN is rejected with the byte-identical 535 ERR plus a
// dummy bcrypt burn so a wire observer cannot enumerate accepted
// mechanisms by latency.
func (s *session) Auth(mech string) (sasl.Server, error) {
	if mech != sasl.Plain {
		s.logFailure("sasl_mechanism_not_supported",
			slog.String("mech", mech))
		s.backend.rateLimit.RecordFailure(s.rateKey)
		// Uniform-time: burn a bcrypt comparison so this branch matches
		// the cost of a successful AUTH PLAIN with a wrong password.
		s.backend.burnDummyBcrypt([]byte(mech))
		return nil, ErrAuthFailed
	}
	return sasl.NewPlainServer(func(identity, username, password string) error {
		// SASL PLAIN allows an authorisation identity distinct from
		// the authentication identity. We do not support delegation;
		// reject any non-empty `identity` that does not match
		// `username`.
		if identity != "" && identity != username {
			s.logFailure("sasl_identity_mismatch")
			s.backend.rateLimit.RecordFailure(s.rateKey)
			s.backend.burnDummyBcrypt([]byte(password))
			return ErrAuthFailed
		}
		return s.login(username, password)
	}), nil
}

// login is the shared verifier for SASL PLAIN. Mirrors the IMAP
// implementation so the two listeners' auth code paths are byte-for-
// byte alignable in review.
//
// Governing: SPEC-0004 REQ "SASL PLAIN Authentication Matching IMAP",
// SPEC-0004 Security checklist (uniform-time auth).
func (s *session) login(username, password string) error {
	// Step 1: per-IP rate-limit cooldown on repeated failures.
	s.backend.rateLimit.Throttle(s.rateKey)

	// Step 2: input validation. Failures here log a structured INFO
	// and return the byte-identical 535 so an attacker cannot tell
	// validation failure apart from credential failure.
	//
	// IMPORTANT: never include `username` (the raw client-supplied
	// SASL identity) in any string we put on the wire — embedded
	// CR/LF could otherwise inject a fake SMTP response. Validation
	// already rejects those bytes; the principle of "never echo user
	// input on the wire" is belt-and-suspenders.
	if err := validateSASLIdentity(username); err != nil {
		s.logFailure("identity_invalid",
			slog.String("reason", invalidIdentityReason(err)),
			slog.Int("identity_bytes", len(username)))
		s.backend.rateLimit.RecordFailure(s.rateKey)
		s.backend.burnDummyBcrypt([]byte(password))
		return ErrAuthFailed
	}

	// Step 3: account lookup.
	ctx, cancel := context.WithTimeout(context.Background(), loginTimeout)
	defer cancel()

	acct, err := s.backend.accounts.GetByPrimaryAlias(ctx, username)
	if err != nil {
		if errors.Is(err, account.ErrAccountNotFound) {
			s.logFailure("account_not_found")
		} else {
			s.logFailure("account_lookup_error",
				slog.String("error", err.Error()))
		}
		s.backend.rateLimit.RecordFailure(s.rateKey)
		s.backend.burnDummyBcrypt([]byte(password))
		return ErrAuthFailed
	}

	// Step 4: state check BEFORE password verify. Order matters for
	// the constant-response invariant: we must not branch to a
	// different return value depending on which fail mode fires
	// first. Both branches return ErrAuthFailed.
	if acct.State != account.StateActive {
		s.logFailure("account_inactive",
			slog.String("account_id", acct.ID),
			slog.String("state", string(acct.State)))
		s.backend.rateLimit.RecordFailure(s.rateKey)
		s.backend.burnDummyBcrypt([]byte(password))
		return ErrAuthFailed
	}

	// Step 5: password verify. Real bcrypt at cost 12 (matches the
	// dummy bcrypt cost above for uniform timing).
	if err := s.backend.accounts.VerifyIMAPPassword(ctx, acct.ID, []byte(password)); err != nil {
		s.logFailure("password_mismatch",
			slog.String("account_id", acct.ID),
			slog.String("error", err.Error()))
		s.backend.rateLimit.RecordFailure(s.rateKey)
		return ErrAuthFailed
	}

	// Step 6: commit. Register in the live-session map so the
	// supervisor's suspension call can find us.
	s.mu.Lock()
	s.accountID = acct.ID
	s.primary = strings.ToLower(strings.TrimSpace(acct.PrimaryAlias))
	s.registered = true
	s.mu.Unlock()
	s.backend.sessions.register(acct.ID, s)
	s.backend.rateLimit.RecordSuccess(s.rateKey)
	s.logger.Info("smtp login",
		slog.String("remote", s.remote),
		slog.String("account_id", acct.ID))
	return nil
}

// Mail implements smtp.Session.Mail. STUB — MAIL FROM authorization
// against the primary alias lands in a follow-up commit. For now we
// require AUTH and reject any sender so the listener is unusable for
// actual submission until the rest of the spec is wired.
func (s *session) Mail(_ string, _ *smtp.MailOptions) error {
	s.mu.Lock()
	authed := s.accountID != ""
	s.mu.Unlock()
	if !authed {
		return smtp.ErrAuthRequired
	}
	// Stub: deferred to the MAIL FROM authorization commit.
	return &smtp.SMTPError{
		Code:         421,
		EnhancedCode: smtp.EnhancedCode{4, 0, 0},
		Message:      "submission not yet implemented",
	}
}

// Rcpt implements smtp.Session.Rcpt. STUB — recipient handling lands
// in the same follow-up commit as Mail.
func (s *session) Rcpt(_ string, _ *smtp.RcptOptions) error {
	return smtp.ErrAuthRequired
}

// Data implements smtp.Session.Data. STUB — drains the reader and
// returns a deferred error. Real implementation in the follow-up.
func (s *session) Data(r io.Reader) error {
	_, _ = io.Copy(io.Discard, r)
	return &smtp.SMTPError{
		Code:         421,
		EnhancedCode: smtp.EnhancedCode{4, 0, 0},
		Message:      "submission not yet implemented",
	}
}

// Reset implements smtp.Session.Reset. No per-message state to clear
// in this initial commit.
func (s *session) Reset() {}

// Logout implements smtp.Session.Logout. Called once when the
// connection ends. Unregister from the live-session map so a later
// DropForAccount does not race with a finished connection.
func (s *session) Logout() error {
	s.mu.Lock()
	acct := s.accountID
	registered := s.registered
	s.registered = false
	s.mu.Unlock()
	if registered {
		s.backend.sessions.unregister(acct, s)
	}
	return nil
}

// logFailure emits a structured INFO record for an authentication
// failure. The supplied SASL identity is NOT included — only the
// remote address and the categorised reason.
func (s *session) logFailure(reason string, extras ...slog.Attr) {
	attrs := []slog.Attr{
		slog.String("event", "smtp_auth_failed"),
		slog.String("remote", s.remote),
		slog.String("reason", reason),
	}
	attrs = append(attrs, extras...)
	s.logger.LogAttrs(context.Background(), slog.LevelInfo, "smtp auth failure", attrs...)
}
