// Per-connection IMAP session. The interesting logic in this file is
// the Login path; every other Session method is a stub that returns
// the same `NO Mailbox does not exist` (or equivalent) the spec
// allows for an empty backend at this milestone.
//
// Future stories layer on the real implementations:
//   - #19 (UID stability + folder hierarchy) replaces the stubbed
//     List / Select / Status / Fetch / etc.
//   - #20 (IDLE live updates) wires Idle / Poll into the pubsub bus.
//
// Governing: ADR-0007, SPEC-0003.

package imapserver

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-sasl"

	"github.com/joestump/reduit/internal/account"
)

// loginTimeout bounds the database lookup + bcrypt verify. bcrypt
// cost 12 takes ~250ms on commodity hardware; 5s is comfortable
// headroom even on slow ARM SBCs while still preventing a slowloris-
// style auth that holds the connection forever.
const loginTimeout = 5 * time.Second

// session is one IMAP client connection. It implements
// emersion/go-imap's `Session` interface; the methods that
// authenticate live in this file and the rest are stubs in
// session_stubs.go.
type session struct {
	backend *Backend
	conn    *imapserver.Conn
	remote  string
	rateKey string
	logger  *slog.Logger

	mu         sync.Mutex
	accountID  string
	registered bool
}

// Compile-time interface assertions. `imapserver.Session` is what
// emersion/go-imap requires; `sessionDropper` is our internal hook
// for the Sessions registry to call into the connection.
var (
	_ imapserver.Session = (*session)(nil)
	_ sessionDropper     = (*session)(nil)
)

// Close is called by emersion/go-imap when the connection ends. We
// unregister from the live-session map so a later DropForAccount
// does not race with a finished connection.
func (s *session) Close() error {
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

// dropWithBye implements sessionDropper. It is called by the
// Sessions registry on suspension / deletion. Emits `* BYE <reason>`
// and forces the connection closed. Safe to call concurrently with
// in-flight commands; the underlying TCP close is observable to the
// other goroutines via their next read returning net.ErrClosed.
//
// Governing: SPEC-0003 REQ "Per-Session Authentication Lifetime".
func (s *session) dropWithBye(reason string) {
	if s.conn == nil {
		return
	}
	// `Conn.Bye` writes `* BYE <reason>` and closes the connection.
	// We deliberately ignore the write error: if the client already
	// hung up, the close still happens.
	_ = s.conn.Bye(reason)
}

// Login implements emersion/go-imap's Session.Login. It is invoked
// for both the SASL PLAIN flow and the legacy IMAP `LOGIN` command
// — we route both through the same verifier so there is exactly one
// authentication code path to audit.
//
// Governing: SPEC-0003 REQ "SASL PLAIN With user@host Identity",
// SPEC-0003 REQ "Authentication failure returns NO with no detail",
// SPEC-0003 REQ "Suspended account is rejected even with correct
// password".
func (s *session) Login(username, password string) error {
	// Step 1: per-IP rate-limit cooldown on repeated failures. This
	// is the v0.5 placeholder rate limit — full sliding-window auth
	// throttling lands later.
	s.backend.rateLimit.Throttle(s.rateKey)

	// Step 2: input validation. Failures here log a structured INFO
	// and return the byte-identical AUTHENTICATIONFAILED so an
	// attacker cannot tell validation failure apart from credential
	// failure.
	//
	// IMPORTANT: never include `username` (the raw client-supplied
	// SASL identity) in any string we put on the wire — embedded
	// CR/LF could otherwise inject a fake IMAP response. Validation
	// already rejects those bytes; the principle of "never echo user
	// input on the wire" is belt-and-suspenders.
	if err := validateSASLIdentity(username); err != nil {
		s.logFailure("identity_invalid",
			slog.String("reason", invalidIdentityReason(err)),
			slog.Int("identity_bytes", len(username)))
		s.backend.rateLimit.RecordFailure(s.rateKey)
		return ErrAuthFailed
	}

	// Step 3: account lookup. Service.GetByPrimaryAlias does its own
	// trim+lowercase normalisation so the on-disk index matches.
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
		return ErrAuthFailed
	}

	// Step 4: state check BEFORE password verify. Order matters for
	// the constant-response invariant: we must not branch to a
	// different return value depending on which fail mode fires
	// first. Both branches return ErrAuthFailed.
	//
	// Governing: SPEC-0003 REQ "Suspended account is rejected even
	// with correct password".
	if acct.State != account.StateActive {
		s.logFailure("account_inactive",
			slog.String("account_id", acct.ID),
			slog.String("state", string(acct.State)))
		s.backend.rateLimit.RecordFailure(s.rateKey)
		return ErrAuthFailed
	}

	// Step 5: password verify. bcrypt is constant-time-ish; the
	// short-circuit on missing hash above (state != active path)
	// also avoids any timing-side-channel that would distinguish
	// a never-rotated account from a wrong password.
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
	s.registered = true
	s.mu.Unlock()
	s.backend.sessions.register(acct.ID, s)
	s.backend.rateLimit.RecordSuccess(s.rateKey)
	s.logger.Info("imap login",
		slog.String("remote", s.remote),
		slog.String("account_id", acct.ID))
	return nil
}

// AuthenticateMechanisms returns the SASL mechanisms we accept. We
// implement SessionSASL ourselves so the server's CAPABILITY logic
// uses this list verbatim instead of the default ("PLAIN" plus
// anything the underlying SASL library chooses to register).
//
// Governing: SPEC-0003 REQ "PLAIN is the only advertised SASL
// mechanism".
func (s *session) AuthenticateMechanisms() []string {
	return []string{sasl.Plain}
}

// Authenticate implements imapserver.SessionSASL. Returns a SASL
// server for the requested mechanism, or an error wrapping
// AUTHENTICATIONFAILED for anything other than PLAIN.
//
// The PlainServer's authenticator reuses the shared Login path so
// validation, rate limiting, state checks, and audit logging are
// applied identically across SASL PLAIN and the legacy IMAP LOGIN
// command.
func (s *session) Authenticate(mech string) (sasl.Server, error) {
	if mech != sasl.Plain {
		s.logFailure("sasl_mechanism_not_supported",
			slog.String("mech", mech))
		return nil, ErrAuthFailed
	}
	return sasl.NewPlainServer(func(identity, username, password string) error {
		// SASL PLAIN allows an authorisation identity distinct from
		// the authentication identity. We do not support user
		// impersonation so reject any non-empty `identity` that does
		// not match `username`. Rejecting outright keeps the contract
		// simple: there is exactly one principal per session.
		if identity != "" && identity != username {
			s.logFailure("sasl_identity_mismatch")
			s.backend.rateLimit.RecordFailure(s.rateKey)
			return ErrAuthFailed
		}
		return s.Login(username, password)
	}), nil
}

// logFailure emits a structured INFO record for an authentication
// failure. The supplied SASL identity is NOT included — only the
// remote address and the categorised reason. This keeps logs useful
// for incident response without echoing potentially attacker-
// controlled data into a log aggregator that may surface it elsewhere.
//
// Governing: SPEC-0003 REQ "Authentication failure returns NO with
// no detail" + Security checklist "Output encoding (no IMAP response
// injection from username)".
func (s *session) logFailure(reason string, extras ...slog.Attr) {
	attrs := []slog.Attr{
		slog.String("event", "imap_auth_failed"),
		slog.String("remote", s.remote),
		slog.String("reason", reason),
	}
	attrs = append(attrs, extras...)
	s.logger.LogAttrs(context.Background(), slog.LevelInfo, "imap auth failure", attrs...)
}

// imap is referenced from this file via ErrAuthFailed indirectly;
// keep the import alive even if a future refactor removes the local
// use, so the package compiles without churn.
var _ = imap.StatusResponseTypeNo
