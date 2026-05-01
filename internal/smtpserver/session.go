// Per-connection SMTP submission session. Owns the SASL PLAIN auth
// flow, MAIL FROM authorization, recipient cap, and the DATA stub
// that drops the body and logs a stub event. The real outbox handoff
// (encryption + Proton submission) lands in story #22; the suspension
// drop (dropWith421 / forceClose) lands in the follow-up commit on
// the same branch.
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

	// Per-message state (cleared on Reset / successful Data).
	hasFrom    bool
	from       string
	recipients []string
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

// Mail implements smtp.Session.Mail. SPEC-0004's "Submission
// Authorization" requirement: the MAIL FROM address must match the
// authenticated account's primary alias. Multi-alias support requires
// a per-alias table populated by the sync worker; the SPEC carves
// that out as future work.
//
// Governing: SPEC-0004 REQ "Submission Authorization".
//
// TODO(spec-0004): multi-alias support pending sync worker. Today the
// only authorised sender is the SASL identity itself.
func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	s.mu.Lock()
	authed := s.accountID != ""
	primary := s.primary
	s.mu.Unlock()

	if !authed {
		// SPEC-0004 inherits SPEC-0003's auth posture: no submission
		// without prior AUTH. emersion's framing already requires the
		// HELO + AUTH dance, but defence in depth.
		return smtp.ErrAuthRequired
	}

	normalised := strings.ToLower(strings.TrimSpace(from))
	if normalised == "" || normalised != primary {
		s.logger.Info("smtp mail rejected",
			slog.String("event", "smtp_mail_rejected"),
			slog.String("remote", s.remote),
			slog.String("account_id", s.accountIDLocked()),
			slog.String("reason", "not_primary_alias"),
			slog.Int("from_bytes", len(from)))
		return errSenderRejected
	}

	s.mu.Lock()
	s.hasFrom = true
	s.from = normalised
	s.recipients = nil
	s.mu.Unlock()
	return nil
}

// Rcpt implements smtp.Session.Rcpt. The recipient cap is enforced by
// the upstream library (`server.MaxRecipients`); we just echo the
// recipient back into the per-message state so DATA can log it. We
// require AUTH and a prior MAIL FROM defensively.
//
// Governing: SPEC-0004 REQ "Recipient and Message Size Limits".
func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	s.mu.Lock()
	authed := s.accountID != ""
	hasFrom := s.hasFrom
	s.mu.Unlock()

	if !authed {
		return smtp.ErrAuthRequired
	}
	if !hasFrom {
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "MAIL FROM required before RCPT TO",
		}
	}

	s.mu.Lock()
	s.recipients = append(s.recipients, to)
	s.mu.Unlock()
	return nil
}

// Data implements smtp.Session.Data. STUB: this story stops at
// accepting the message body. The real outbox handoff (encryption +
// Proton submission via the per-account worker) lands in story #22.
//
// We still fully consume the reader so the upstream library can write
// a clean response, AND we propagate any read error (notably
// smtp.ErrDataTooLarge from the size-limited dataReader) so a 1 GiB
// attempt fails fast at the size limit rather than buffering 1 GiB
// before rejection.
//
// Governing: SPEC-0004 REQ "Recipient and Message Size Limits", and
// SPEC-0004 REQ "Outbox Handoff and Synchronous Confirmation"
// (deferred to #22).
func (s *session) Data(r io.Reader) error {
	// TODO(#22): hand to per-account outbox worker. For now, count the
	// bytes, log the envelope + size, and drop the body.
	n, err := io.Copy(io.Discard, r)
	if err != nil {
		// Streaming size cap (smtp.ErrDataTooLarge) and any other
		// read error are returned verbatim. The upstream library maps
		// *smtp.SMTPError to its code/message; non-SMTP errors map to
		// the 554 fallback in dataErrorToStatus.
		s.logger.Info("smtp data error",
			slog.String("event", "smtp_data_error"),
			slog.String("remote", s.remote),
			slog.String("account_id", s.accountIDLocked()),
			slog.Int64("bytes_read", n),
			slog.String("error", err.Error()))
		return err
	}

	s.mu.Lock()
	rcpt := append([]string(nil), s.recipients...)
	from := s.from
	acct := s.accountID
	s.mu.Unlock()

	s.logger.Info("smtp data accepted",
		slog.String("event", "smtp_data_accepted_stub"),
		slog.String("remote", s.remote),
		slog.String("account_id", acct),
		slog.String("from", from),
		slog.Int("recipients", len(rcpt)),
		slog.Int64("bytes", n))
	return nil
}

// Reset implements smtp.Session.Reset. Clear per-message state but
// preserve the auth state — RFC 5321: RSET resets the transaction,
// not the connection.
func (s *session) Reset() {
	s.mu.Lock()
	s.hasFrom = false
	s.from = ""
	s.recipients = nil
	s.mu.Unlock()
}

// Logout implements smtp.Session.Logout. Called once when the
// connection ends (QUIT or remote close). Unregister from the live-
// session map so a later DropForAccount does not race with a
// finished connection.
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

// accountIDLocked returns the current account ID, taking the session
// lock to read it. Useful for logging where the caller doesn't already
// hold s.mu.
func (s *session) accountIDLocked() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accountID
}

// logFailure emits a structured INFO record for an authentication
// failure. The supplied SASL identity is NOT included — only the
// remote address and the categorised reason. Mirrors the IMAP
// listener's same-named helper.
func (s *session) logFailure(reason string, extras ...slog.Attr) {
	attrs := []slog.Attr{
		slog.String("event", "smtp_auth_failed"),
		slog.String("remote", s.remote),
		slog.String("reason", reason),
	}
	attrs = append(attrs, extras...)
	s.logger.LogAttrs(context.Background(), slog.LevelInfo, "smtp auth failure", attrs...)
}
