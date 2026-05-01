// Backend wires Reduit's account service into emersion/go-smtp.
// Each accepted TCP connection produces a new Session via NewSession;
// the Session owns the per-connection state and the link back to the
// shared registry + account service.
//
// Governing: ADR-0007 (emersion go-smtp), SPEC-0004.

package smtpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"

	smtp "github.com/emersion/go-smtp"
	"golang.org/x/crypto/bcrypt"

	"github.com/joestump/reduit/internal/account"
)

// AccountLookup is the slice of `account.Service` the SMTP backend
// needs. Decoupling lets unit tests stub auth without spinning up a
// SQLite + cryptenv stack. Identical shape to internal/imapserver.
// AccountLookup so a future shared-deps refactor is trivial.
type AccountLookup interface {
	GetByPrimaryAlias(ctx context.Context, alias string) (*account.Account, error)
	VerifyIMAPPassword(ctx context.Context, accountID string, candidate []byte) error
}

// Backend implements emersion/go-smtp's `Backend` interface. One
// Backend instance is shared across every connection; per-connection
// state lives on session.
type Backend struct {
	accounts  AccountLookup
	sessions  *Sessions
	logger    *slog.Logger
	rateLimit *authRateLimiter

	// dummyBcryptHash is a fixed bcrypt hash generated at construction
	// time and reused on every auth failure branch that does NOT reach
	// the real password verify. By forcing every failure path to
	// perform one bcrypt comparison at the SAME cost as the real verify
	// (per `internal/account.bcryptCost = 12`), we make
	// `unknown alias`, `account suspended`, `pending Proton setup`,
	// `malformed identity`, and `non-PLAIN mechanism` all take the
	// same wall-clock time as the wrong-password branch. Without this,
	// an attacker can enumerate which OIDC subjects exist (and their
	// state) by timing alone.
	//
	// Mirrors internal/imapserver/Backend.dummyBcryptHash. Duplicated
	// rather than extracted into a shared package — see the doc on
	// the IMAP version for the rationale.
	//
	// Governing: SPEC-0004 Security checklist + the parallel SPEC-0003
	// REQ "Authentication failure returns NO with no detail" — uniform-
	// time auth.
	//
	// TODO: extract shared SASL helpers if a third listener appears.
	dummyBcryptHash []byte
}

// bcryptDummyCost is pinned to internal/account.bcryptCost. If that
// constant ever changes and this one does not, the dummy bcrypt no
// longer matches the real bcrypt's wall-clock cost and the timing
// side-channel returns.
const bcryptDummyCost = 12

// NewBackend constructs a Backend. logger may be nil; the default
// slog logger is used in that case. The Sessions registry is REQUIRED
// — it is the public hook the suspension code path calls to drop
// sessions for a freshly-suspended account.
//
// Governing: SPEC-0004 REQ "Per-Session Authentication Lifetime".
func NewBackend(accounts AccountLookup, sessions *Sessions, logger *slog.Logger) (*Backend, error) {
	if accounts == nil {
		return nil, errors.New("smtpserver: accounts is required")
	}
	if sessions == nil {
		return nil, errors.New("smtpserver: sessions registry is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	dummyHash, err := bcrypt.GenerateFromPassword([]byte("decoy"), bcryptDummyCost)
	if err != nil {
		return nil, errors.New("smtpserver: failed to generate dummy bcrypt hash")
	}
	return &Backend{
		accounts:        accounts,
		sessions:        sessions,
		logger:          logger,
		rateLimit:       newAuthRateLimiter(),
		dummyBcryptHash: dummyHash,
	}, nil
}

// burnDummyBcrypt runs a bcrypt comparison against the precomputed
// dummy hash and discards the result. Called from every Auth failure
// branch that does NOT otherwise reach the real bcrypt verify, so the
// CPU cost of every failure path is uniform.
//
// Governing: SPEC-0004 Security checklist — uniform-time auth.
func (b *Backend) burnDummyBcrypt(candidate []byte) {
	// The error is intentionally discarded — we are spending CPU, not
	// validating anything. Use the candidate bytes (not a fixed input)
	// so a clever optimizer cannot fold the call away.
	_ = bcrypt.CompareHashAndPassword(b.dummyBcryptHash, candidate)
}

// disableRateLimitForTest sets the limiter's free-attempt budget to a
// huge number so back-off never fires. Used by the timing-side-channel
// test which needs to issue many sequential auth attempts from the
// same IP without being throttled.
func (b *Backend) disableRateLimitForTest() {
	b.rateLimit.mu.Lock()
	defer b.rateLimit.mu.Unlock()
	b.rateLimit.free = 1 << 30
}

// NewSession is the callback emersion/go-smtp invokes for every
// accepted connection. We mint a fresh session bound to the
// connection's remote address so per-IP rate limiting has a key.
//
// Governing: SPEC-0004 REQ "TLS Required, SMTPS Only" — by the time
// this runs the underlying connection is already a *tls.Conn (the
// listener is `tls.Listen` in server.go); we reject any non-TLS conn
// defensively in case a future caller wires us into a plain listener
// by mistake.
func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	netConn := c.Conn()
	if !isTLSConn(netConn) {
		// Defence in depth: the listener must already be tls.Listen.
		// If it isn't, refuse the session rather than allow cleartext
		// authentication on a path that would never be tested.
		b.logger.Warn("smtpserver: rejecting non-TLS connection",
			slog.String("remote", remoteHost(netConn)))
		return nil, &smtp.SMTPError{
			Code:         523,
			EnhancedCode: smtp.EnhancedCode{5, 7, 10},
			Message:      "TLS required",
		}
	}

	s := &session{
		backend: b,
		conn:    c,
		remote:  remoteHost(netConn),
		rateKey: remoteIP(netConn),
		logger:  b.logger,
	}
	return s, nil
}

// remoteHost is the full "host:port" form used for log breadcrumbs.
// remoteIP strips the port for use as a rate-limit key (so a single
// attacker behind one NAT doesn't dilute their failure count by
// reconnecting from new ephemeral ports).
func remoteHost(c net.Conn) string {
	if c == nil {
		return ""
	}
	if a := c.RemoteAddr(); a != nil {
		return a.String()
	}
	return ""
}

// isTLSConn returns true when c is (or wraps, via an `Unwrap() net.Conn`
// chain) a *tls.Conn.
func isTLSConn(c net.Conn) bool {
	for c != nil {
		if _, ok := c.(*tls.Conn); ok {
			return true
		}
		u, ok := c.(interface{ Unwrap() net.Conn })
		if !ok {
			return false
		}
		c = u.Unwrap()
	}
	return false
}

func remoteIP(c net.Conn) string {
	host := remoteHost(c)
	if host == "" {
		return ""
	}
	ip, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return ip
}

// ErrAuthFailed is the byte-identical SMTP error every authentication
// failure path returns, regardless of underlying cause (bad password,
// unknown user, suspended account, malformed identity, non-PLAIN
// mechanism). Per the parallel SPEC-0003 REQ that SPEC-0004 inherits
// via "SASL PLAIN Authentication Matching IMAP".
//
// The text intentionally does NOT include any attacker-controlled
// bytes (especially not the supplied SASL identity), which would
// otherwise be a vector for SMTP response injection.
var ErrAuthFailed = &smtp.SMTPError{
	Code:         535,
	EnhancedCode: smtp.EnhancedCode{5, 7, 8},
	Message:      "Authentication failed",
}

// errSenderRejected is the canonical SPEC-0004 "MAIL FROM does not
// match a known alias" response. Wired up exactly per the spec's
// "Submission Authorization" requirement so a black-box client probe
// gets the byte-identical text the spec mandates.
//
// Governing: SPEC-0004 REQ "Submission Authorization".
var errSenderRejected = &smtp.SMTPError{
	Code:         553,
	EnhancedCode: smtp.EnhancedCode{5, 7, 1},
	Message:      "Sender address rejected: not authorized for this account",
}

// errAccountSuspended is the response the suspension fan-out injects
// onto every live session for the suspended account. The connection
// is force-closed immediately after.
//
// Governing: SPEC-0004 REQ "Per-Session Authentication Lifetime".
var errAccountSuspended = &smtp.SMTPError{
	Code:         421,
	EnhancedCode: smtp.EnhancedCode{4, 7, 1},
	Message:      "Account suspended",
}
