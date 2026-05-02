// Per-connection SMTP submission session. Owns the SASL PLAIN auth
// flow, MAIL FROM authorization, recipient cap, and the DATA stub that
// will hand off to the per-account outbox in story #22.
//
// Governing: ADR-0007 (emersion go-smtp), SPEC-0004.

package smtpserver

import (
	"bytes"
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
	"github.com/joestump/reduit/internal/outbox"
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
	_ sessionDropper   = (*session)(nil)
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

// Data implements smtp.Session.Data. The handler reads the body
// (streamed, size-capped), assembles an outbox.Submission, and blocks
// on the per-account outbox worker until the Proton submission either
// succeeds (`250 OK`), fails with a typed error (mapped to 4xx/5xx),
// or the submission deadline elapses (`451 4.4.7`).
//
// Body buffering: we read the entire body into memory before handing
// to the outbox. The streamed size cap (DefaultMaxMessageBytes, 25 MiB)
// caps the in-memory cost. A future optimisation could stream into a
// disk-backed buffer, but at 25 MiB per concurrent send and a per-
// account cap of 4 the worst case is 100 MiB resident per account —
// fine for the v0.1 deployment shape.
//
// Encryption-mode selection happens INSIDE outbox.Submit (see
// outbox.SelectMode); the SMTP layer is intentionally agnostic of
// encryption decisions so the security boundary lives in one place.
//
// Governing: SPEC-0004 REQ "Recipient and Message Size Limits",
// SPEC-0004 REQ "Outbox Handoff and Synchronous Confirmation",
// SPEC-0004 REQ "Encryption Pipeline".
func (s *session) Data(r io.Reader) error {
	// Buffer the body. The upstream library wraps r in a size-limited
	// reader so io.ReadAll cannot exceed MaxMessageBytes — a 1 GiB
	// attempt is rejected mid-stream with smtp.ErrDataTooLarge before
	// any allocation balloon.
	var buf bytes.Buffer
	n, err := io.Copy(&buf, r)
	if err != nil {
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

	// Defence in depth: an authenticated session that never issued a
	// MAIL FROM should never reach Data (the upstream library enforces
	// the order), but guard the outbox call anyway so a malformed
	// envelope produces a 503 instead of an outbox panic.
	if acct == "" || from == "" || len(rcpt) == 0 {
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "Bad sequence of commands",
		}
	}

	// Synchronous outbox call. The worker enforces its own deadline
	// (REDUIT_SMTP_SUBMIT_TIMEOUT, default 60s); we pass a parent
	// ctx so a forced server shutdown can short-circuit the wait.
	timeout := s.backend.submitTimeout
	if timeout <= 0 {
		timeout = DefaultSubmitTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer cancel()

	submitStart := time.Now()
	res := s.backend.outbox.Submit(ctx, outbox.Submission{
		AccountID:  acct,
		MailFrom:   from,
		Recipients: rcpt,
		Body:       buf.Bytes(),
	})
	elapsed := time.Since(submitStart)

	if res.Err == nil {
		s.logger.Info("smtp data accepted",
			slog.String("event", "smtp_data_accepted"),
			slog.String("remote", s.remote),
			slog.String("account_id", acct),
			slog.String("from", from),
			slog.Int("recipients", len(rcpt)),
			slog.Int64("bytes", n),
			slog.Duration("elapsed", elapsed))
		return nil
	}

	// Map the typed outbox error to an SMTP code per SPEC-0004's
	// "outbox returns failure → appropriate 4xx or 5xx" requirement.
	smtpErr := mapOutboxError(res.Err)
	s.logger.Info("smtp data rejected",
		slog.String("event", "smtp_data_rejected"),
		slog.String("remote", s.remote),
		slog.String("account_id", acct),
		slog.String("from", from),
		slog.Int("recipients", len(rcpt)),
		slog.Int64("bytes", n),
		slog.Duration("elapsed", elapsed),
		slog.Int("smtp_code", smtpErr.Code),
		slog.String("err", res.Err.Error()))
	return smtpErr
}

// mapOutboxError translates the outbox's typed error vocabulary to
// the SMTP reply code SPEC-0004 mandates. The mapping is intentionally
// conservative: anything we don't recognise becomes 451 (transient,
// retry) so a flaky upstream doesn't manifest as permanent rejections.
//
// Reduit does NOT run a server-side retry loop after a synchronous
// timeout. The 451 4.4.7 text deliberately does not promise retry;
// recovery is the sender's MTA re-attempting the SMTP submission per
// RFC 5321, which is the canonical SMTP-level retry mechanism.
//
// Mapping:
//
//	ErrSubmissionTimedOut  → 451 4.4.7  Submission timed out
//	ErrAccountClosed       → 421 4.7.0  Account no longer authorised
//	ErrSubmissionEnvelope  → 503 5.5.1  Bad sequence of commands
//	*ErrKeyLookup          → 451 4.4.4  Key lookup failed (transient)
//	*ErrProtonAuth         → 535 5.7.8  Authentication credentials revoked
//	*ErrProtonRateLimit    → 421 4.7.0  Throttled by upstream, retry later
//	*ErrProtonReject       → 550 5.6.0  Message rejected by upstream
//	*ErrProtonServer       → 451 4.5.0  Upstream server error, retry
//	context cancelled      → 451 4.4.5  Connection terminating
//	default                → 451 4.0.0  Transient unspecified failure
//
// Governing: SPEC-0004 REQ "Outbox Handoff and Synchronous Confirmation".
func mapOutboxError(err error) *smtp.SMTPError {
	if err == nil {
		// Should be unreachable; defence in depth.
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 0, 0},
			Message:      "Transient failure",
		}
	}
	switch {
	case errors.Is(err, outbox.ErrSubmissionTimedOut):
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 4, 7},
			Message:      "Submission timed out",
		}
	case errors.Is(err, outbox.ErrAccountClosed):
		return &smtp.SMTPError{
			Code:         421,
			EnhancedCode: smtp.EnhancedCode{4, 7, 0},
			Message:      "Account no longer authorised",
		}
	case errors.Is(err, outbox.ErrSubmissionEnvelope):
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "Bad sequence of commands",
		}
	}
	var keyErr *outbox.ErrKeyLookup
	if errors.As(err, &keyErr) {
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 4, 4},
			Message:      "Key lookup failed",
		}
	}
	var authErr *outbox.ErrProtonAuth
	if errors.As(err, &authErr) {
		return &smtp.SMTPError{
			Code:         535,
			EnhancedCode: smtp.EnhancedCode{5, 7, 8},
			Message:      "Authentication credentials revoked",
		}
	}
	var rateErr *outbox.ErrProtonRateLimit
	if errors.As(err, &rateErr) {
		return &smtp.SMTPError{
			Code:         421,
			EnhancedCode: smtp.EnhancedCode{4, 7, 0},
			Message:      "Upstream rate limit, retry later",
		}
	}
	var rejectErr *outbox.ErrProtonReject
	if errors.As(err, &rejectErr) {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 6, 0},
			Message:      "Message rejected by upstream",
		}
	}
	var srvErr *outbox.ErrProtonServer
	if errors.As(err, &srvErr) {
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 5, 0},
			Message:      "Upstream server error, message will be retried",
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 4, 5},
			Message:      "Connection terminating",
		}
	}
	return &smtp.SMTPError{
		Code:         451,
		EnhancedCode: smtp.EnhancedCode{4, 0, 0},
		Message:      "Transient failure",
	}
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

// dropWith421 implements sessionDropper. Called by the Sessions
// registry on suspension / deletion. There is no public hook in
// emersion/go-smtp to inject a synthetic response onto a live
// connection, so we write the line directly to the underlying conn
// and then close it.
//
// SAFETY: the conn handed to us by go-smtp is a *lockedConn (wired in
// at the listener layer in server.go). Both this Write and the
// handler goroutine's response flushes go through the same per-conn
// write mutex, so a 250-line EHLO continuation cannot interleave with
// our 421 line on the wire. Without the lockedConn wrapper this would
// be a wire-protocol corruption race.
//
// We deliberately do NOT set a write deadline here. The `*tls.Conn`
// is shared with the handler goroutine; mutating its deadline would
// race against any in-flight handler write. The Sessions registry
// owns the per-session deadline (`dropPerSessionDeadline`, 750ms) and
// the top-level deadline (`dropTotalDeadline`, 1s); when either
// expires it calls `forceClose` which hard-closes the underlying
// socket. Any in-flight write here will then observe net.ErrClosed
// and unwind — no separate write-deadline needed.
//
// Governing: SPEC-0004 REQ "Per-Session Authentication Lifetime".
func (s *session) dropWith421(reason string) {
	if s.conn == nil {
		return
	}
	nc := s.conn.Conn()
	if nc == nil {
		return
	}
	// Format: `421 4.7.1 <reason>\r\n`. Mirrors the canonical
	// errAccountSuspended response so a client that knows the spec
	// gets the same payload regardless of which path delivered it.
	// Single Write call so the lockedConn mutex covers the whole line
	// in one atomic transaction against any concurrent handler write.
	line := "421 " +
		smtpEnhancedCodeString(errAccountSuspended.EnhancedCode) +
		" " + reason + "\r\n"
	_, _ = nc.Write([]byte(line))
	// Best-effort close. forceClose is the deadline fallback.
	_ = nc.Close()
}

// forceClose hard-closes the underlying TCP/TLS connection. Used by
// the Sessions registry when the dropWith421 deadline expires. After
// this returns, any goroutine still mid-write on this connection
// observes net.ErrClosed on its next syscall.
func (s *session) forceClose() {
	if s.conn == nil {
		return
	}
	if nc := s.conn.Conn(); nc != nil {
		_ = nc.Close()
	}
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

// smtpEnhancedCodeString renders an EnhancedCode as `X.Y.Z`. The
// upstream library has an internal formatter but does not export it,
// and we only use this for the dropWith421 wire format so a tiny
// helper is fine.
func smtpEnhancedCodeString(c smtp.EnhancedCode) string {
	return itoa(c[0]) + "." + itoa(c[1]) + "." + itoa(c[2])
}

// itoa is a tiny non-allocating int formatter for single-digit class
// codes. We avoid strconv.Itoa to keep the dropWith421 hot path free
// of allocations under load. (Premature? Possibly. But the alternative
// is one more import in a security-critical file.)
func itoa(n int) string {
	if n >= 0 && n < 10 {
		return string(rune('0' + n))
	}
	// Fallback for anything weird; should never happen with our codes.
	if n < 0 {
		n = 0
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if i == len(buf) {
		return "0"
	}
	return string(buf[i:])
}
