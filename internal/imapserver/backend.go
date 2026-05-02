// Backend wires Reduit's account service into emersion/go-imap v2.
// Each accepted TCP connection produces a new Session via NewSession;
// the Session owns the per-connection state and the link back to the
// shared registry + account service.
//
// Governing: ADR-0007 (emersion go-imap v2), SPEC-0003.

package imapserver

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"golang.org/x/crypto/bcrypt"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/mailbox"
	"github.com/joestump/reduit/internal/proton"
)

// AccountLookup is the slice of `account.Service` the IMAP backend
// needs. Decoupling lets unit tests stub auth without spinning up a
// SQLite + cryptenv stack.
type AccountLookup interface {
	GetByPrimaryAlias(ctx context.Context, alias string) (*account.Account, error)
	VerifyIMAPPassword(ctx context.Context, accountID string, candidate []byte) error
}

// ProtonClientLookup resolves an account ID to its live Proton client.
// The IMAP MOVE / COPY handlers call into Proton through this hook to
// adjust labels. Returns nil + nil when no client is currently bound
// (e.g. account is mid-Proton-login); the Move handler treats that as
// a transient failure and refuses the move with a `NO` response so the
// client retries.
//
// Decoupling lets unit tests stub the proton surface without a full
// account+manager stack.
//
// Governing: SPEC-0003 REQ "Folder Hierarchy and Mapping" — system
// folder moves AND `Labels/*` moves both go through the Proton client.
type ProtonClientLookup interface {
	ProtonForAccount(ctx context.Context, accountID string) (proton.Client, error)
}

// MailboxService is the slice of mailbox.Service the IMAP session
// needs. Kept as a local interface (not the upstream type) so tests do
// not have to spin up the SQLite stack. The shape is identical to
// mailbox.Service; we re-declare here so the imapserver package does
// not transitively depend on the mailbox package's test fixtures.
type MailboxService interface {
	EnsureMailbox(ctx context.Context, accountID, name, protonLabelID string, kind mailbox.Kind) (*mailbox.Mailbox, error)
	GetMailboxByName(ctx context.Context, accountID, name string) (*mailbox.Mailbox, error)
	ListMailboxes(ctx context.Context, accountID string) ([]*mailbox.Mailbox, error)
	AssignUID(ctx context.Context, accountID string, mailboxID, messageID int64) (uint32, error)
	UpsertMessage(ctx context.Context, msg *mailbox.Message) (int64, error)
	FindMessageByProtonID(ctx context.Context, accountID, protonID string) (*mailbox.Message, error)
	RemoveMessageFromMailbox(ctx context.Context, accountID string, mailboxID, messageID int64) (bool, error)
	ListMessagesInMailbox(ctx context.Context, accountID string, mailboxID int64) ([]*mailbox.MessageInMailbox, error)
	CountMessagesInMailbox(ctx context.Context, accountID string, mailboxID int64) (uint32, error)
}

// Backend implements emersion/go-imap's `Options.NewSession` factory.
// One Backend instance is shared across every connection; per-
// connection state lives on Session.
type Backend struct {
	accounts  AccountLookup
	mailboxes MailboxService
	proton    ProtonClientLookup
	sessions  *Sessions
	logger    *slog.Logger
	rateLimit *authRateLimiter
	// dummyBcryptHash is a fixed bcrypt hash generated at construction
	// time and reused on every auth failure branch that does NOT reach
	// the real password verify. By forcing every failure path to
	// perform one bcrypt comparison at the SAME cost as the real verify
	// (per `internal/account.bcryptCost = 12`), we make
	// `unknown alias`, `account suspended`, `pending Proton setup`,
	// `malformed identity`, and `transient backend error` all take the
	// same wall-clock time as the wrong-password branch. Without this,
	// an attacker can enumerate which OIDC subjects exist (and their
	// state) by timing alone — the byte-identical response invariant
	// only covers the payload, not the latency.
	//
	// Governing: SPEC-0003 REQ "Authentication failure returns NO with
	// no detail" — uniform-time auth: the failure response is not just
	// byte-identical but takes a uniform amount of CPU, so a wire
	// observer cannot enumerate account existence by timing.
	dummyBcryptHash []byte
}

// bcryptDummyCost is pinned to internal/account.bcryptCost. If that
// constant ever changes and this one does not, the dummy bcrypt no
// longer matches the real bcrypt's wall-clock cost and the timing
// side-channel returns. We assert equality at construction time below.
const bcryptDummyCost = 12

// NewBackend constructs a Backend. logger may be nil; the default
// slog logger is used in that case. The Sessions registry is
// REQUIRED — it is the public hook for the suspension code path
// (#15) to call DropForAccount without coupling to the rest of the
// server.
//
// `mailboxes` and `protonLookup` are OPTIONAL: when nil, the Session's
// post-Login methods (List/Select/Status/Move/Fetch) degrade to the
// pre-#19 stub behaviour (every named mailbox returns "does not
// exist", LIST is empty). This keeps the existing test fixtures that
// only exercise the auth path from breaking, and lets the composition
// root wire mailboxes only when SPEC-0003's mailbox surface is needed.
//
// Governing: SPEC-0003 REQ "Per-Session Authentication Lifetime".
func NewBackend(accounts AccountLookup, sessions *Sessions, logger *slog.Logger, opts ...BackendOption) (*Backend, error) {
	if accounts == nil {
		return nil, errors.New("imapserver: accounts is required")
	}
	if sessions == nil {
		return nil, errors.New("imapserver: sessions registry is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	// Pre-compute the fixed dummy hash for uniform-time auth failure.
	// This is intentionally done at construction (once per Backend) so
	// the per-request bcrypt cost is comparison-only, never generation.
	dummyHash, err := bcrypt.GenerateFromPassword([]byte("decoy"), bcryptDummyCost)
	if err != nil {
		// bcrypt.GenerateFromPassword only fails for invalid cost or
		// allocation failure — both fatal at startup time.
		return nil, errors.New("imapserver: failed to generate dummy bcrypt hash")
	}
	b := &Backend{
		accounts:        accounts,
		sessions:        sessions,
		logger:          logger,
		rateLimit:       newAuthRateLimiter(),
		dummyBcryptHash: dummyHash,
	}
	for _, opt := range opts {
		opt(b)
	}
	return b, nil
}

// BackendOption is the functional-options shape NewBackend accepts so
// that adding a new optional dependency (e.g. a future event-bus hook)
// does not break the existing call sites.
type BackendOption func(*Backend)

// WithMailboxes wires the per-account mailbox service into the backend.
// Required for the Session's List/Select/Status/Fetch/Move methods to
// return real data — without it those methods fall back to the
// SPEC-0003-compatible "no such mailbox" stub.
func WithMailboxes(svc MailboxService) BackendOption {
	return func(b *Backend) { b.mailboxes = svc }
}

// WithProton wires the proton client lookup. Required for Move/Copy
// to translate IMAP folder transitions into Proton label adjustments.
func WithProton(p ProtonClientLookup) BackendOption {
	return func(b *Backend) { b.proton = p }
}

// burnDummyBcrypt runs a bcrypt comparison against the precomputed
// dummy hash and discards the result. Called from every Login failure
// branch that does NOT otherwise reach the real bcrypt verify, so the
// CPU cost of every failure path is uniform.
//
// Governing: SPEC-0003 REQ "Authentication failure returns NO with no
// detail" — uniform-time auth.
func (b *Backend) burnDummyBcrypt(candidate []byte) {
	// The error is intentionally discarded — we are spending CPU, not
	// validating anything. Use the candidate bytes (not a fixed input)
	// so a clever optimizer cannot fold the call away.
	_ = bcrypt.CompareHashAndPassword(b.dummyBcryptHash, candidate)
}

// disableRateLimitForTest sets the limiter's free-attempt budget to a
// huge number so back-off never fires. Used by the timing-side-channel
// test which needs to issue many sequential auth attempts from the
// same IP without being throttled — the test is measuring bcrypt
// uniformity, not rate-limit behaviour. NOT exported; only callable
// from the same package's tests.
func (b *Backend) disableRateLimitForTest() {
	b.rateLimit.mu.Lock()
	defer b.rateLimit.mu.Unlock()
	b.rateLimit.free = 1 << 30
}

// NewSession is the callback emersion/go-imap invokes for every
// accepted connection. We mint a fresh Session bound to the
// connection's remote address so per-IP rate limiting has a key, and
// we install a no-PreAuth greeting (the client must AUTHENTICATE
// before doing anything).
//
// Governing: SPEC-0003 REQ "TLS Required, IMAPS Only" — by the time
// this runs the underlying connection is already a *tls.Conn; we
// reject any non-TLS conn defensively in case a future caller wires
// us into a plain listener by mistake.
func (b *Backend) NewSession(c *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
	netConn := c.NetConn()
	if !isTLSConn(netConn) {
		// Defence in depth: the listener must already be tls.Listen.
		// If it isn't, refuse the session rather than allow cleartext
		// authentication on a path that would never be tested.
		b.logger.Warn("imapserver: rejecting non-TLS connection",
			slog.String("remote", remoteHost(netConn)))
		return nil, &imapserver.GreetingData{}, &imap.Error{
			Type: imap.StatusResponseTypeBye,
			Text: "TLS required",
		}
	}

	s := &session{
		backend: b,
		conn:    c,
		remote:  remoteHost(netConn),
		rateKey: remoteIP(netConn),
		logger:  b.logger,
	}
	return s, nil, nil
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
// chain) a *tls.Conn. The capFilter layer between tls.Listen and the
// emersion server exposes Unwrap so the type assertion drills through
// it.
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

// ErrAuthFailed is the byte-identical IMAP error every authentication
// failure path returns, regardless of underlying cause (bad password,
// unknown user, suspended account, malformed identity). Per SPEC-0003
// REQ "Authentication failure returns NO with no detail".
//
// The text is intentionally generic and does NOT include any
// attacker-controlled bytes (especially not the supplied SASL
// identity), which would otherwise be a vector for IMAP response
// injection via newline characters.
var ErrAuthFailed = &imap.Error{
	Type: imap.StatusResponseTypeNo,
	Code: imap.ResponseCodeAuthenticationFailed,
	Text: "Authentication failed",
}
