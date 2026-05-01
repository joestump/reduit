// Public types for the outbox: a Submission is what the SMTP server
// hands in; a Result + a small error vocabulary is what comes back.
//
// Governing: SPEC-0004 REQ "Outbox Handoff and Synchronous Confirmation".

package outbox

import (
	"errors"

	"github.com/joestump/reduit/internal/proton"
)

// Submission is one accepted SMTP transaction in flight. Construction
// lives in the SMTP server; the outbox treats Submission as immutable
// once it has been handed over to Submit.
type Submission struct {
	// AccountID identifies the per-account worker that owns the
	// submission. The SMTP server has already authorised the session
	// (SASL PLAIN over TLS) and matched MAIL FROM to the account's
	// primary alias before constructing this struct; the outbox does
	// NOT re-authorise.
	AccountID string

	// MailFrom is the envelope sender (already lower-cased and trimmed
	// by the SMTP MAIL FROM handler).
	MailFrom string

	// Recipients is the envelope recipient list, in the order RCPT TO
	// commands arrived. Local-part casing is preserved.
	Recipients []string

	// Body is the full RFC 5322 message body (headers + CRLF + body).
	// The outbox does not parse this in v0.1 — it hands the body to
	// go-proton-api which constructs the on-wire encrypted packets.
	Body []byte
}

// Result describes the outcome of a synchronous Submit call. Success
// is the all-recipients-accepted-by-Proton branch; partial successes
// (some recipients accepted, others rejected) are deferred to a future
// story and surface here as Err with a concrete error type.
type Result struct {
	// Modes records the encryption mode chosen per recipient. Useful
	// for logging and tests; do not branch program behaviour on this.
	Modes map[string]EncryptionMode

	// Err is nil on success and non-nil on failure. Callers that need
	// to map to an SMTP code branch on errors.Is.
	Err error
}

// EncryptionMode is the per-recipient encryption decision the outbox
// took. Mirrors go-proton-api's EncryptionScheme but lives in the
// outbox package so callers (logger, tests, SMTP-side code) do not
// need to import the upstream constants directly.
type EncryptionMode int

const (
	// ModeUnknown is the zero value. Should never appear in a Result;
	// its presence indicates a bug in the encryption-mode selector.
	ModeUnknown EncryptionMode = iota
	// ModeProtonE2E is end-to-end PGP to a Proton-internal recipient.
	// The body is encrypted to the recipient's address key (returned
	// by /core/v4/keys with RecipientType=Internal) and signed by the
	// sender's primary key.
	ModeProtonE2E
	// ModeExternalE2E is end-to-end PGP to an external recipient that
	// has a published key (WKD or pinned) and the user's account
	// configuration permits encrypt-to-outside.
	ModeExternalE2E
	// ModeCleartext is plaintext relay via Proton's outbound MTA. The
	// body is not encrypted client-side; Proton signs the outbound
	// envelope with its own DKIM keys.
	ModeCleartext
)

// String renders the mode for logs. Stable token form so log analysis
// tooling can group on it.
func (m EncryptionMode) String() string {
	switch m {
	case ModeProtonE2E:
		return "proton_e2e"
	case ModeExternalE2E:
		return "external_e2e"
	case ModeCleartext:
		return "cleartext"
	default:
		return "unknown"
	}
}

// ErrSubmissionTimedOut is returned by Submit when the configured
// submission deadline elapses before the upstream Proton call returns.
// The SMTP server maps this to `451 4.4.7`; the outbox detaches the
// in-flight call onto a background retry goroutine.
var ErrSubmissionTimedOut = errors.New("outbox: submission timed out")

// ErrAccountClosed is returned when Submit is called for an account
// whose worker has already been shut down (Manager.Shutdown was called).
// The SMTP server maps this to `421 4.7.0`.
var ErrAccountClosed = errors.New("outbox: account worker closed")

// ErrSubmissionEnvelope is returned by Submit before any upstream call
// when the submission envelope is malformed (empty MAIL FROM, no
// recipients, or empty body). The SMTP server should never produce one
// of these — defence in depth.
var ErrSubmissionEnvelope = errors.New("outbox: invalid submission envelope")

// ErrKeyLookup wraps an upstream /core/v4/keys failure. The selector
// fails closed on this — see SelectMode for why we never silently
// downgrade to cleartext on a key-lookup error.
type ErrKeyLookup struct {
	Recipient string
	Cause     error
}

func (e *ErrKeyLookup) Error() string {
	return "outbox: key lookup failed for " + e.Recipient + ": " + e.Cause.Error()
}

func (e *ErrKeyLookup) Unwrap() error { return e.Cause }

// ErrProtonAuth wraps an upstream auth failure (refresh token revoked,
// session deleted by an admin). The SMTP server maps this to `535`
// (auth credentials revoked) so the client knows to re-authenticate.
type ErrProtonAuth struct {
	Cause error
}

func (e *ErrProtonAuth) Error() string {
	return "outbox: proton auth failed: " + e.Cause.Error()
}

func (e *ErrProtonAuth) Unwrap() error { return e.Cause }

// ErrProtonRateLimit wraps a Proton-side throttling response. The SMTP
// server maps this to `421` so the sending MTA backs off and retries
// later.
type ErrProtonRateLimit struct {
	Cause error
}

func (e *ErrProtonRateLimit) Error() string {
	return "outbox: proton rate limited: " + e.Cause.Error()
}

func (e *ErrProtonRateLimit) Unwrap() error { return e.Cause }

// ErrProtonReject wraps a Proton-side permanent rejection (message
// content rejected, recipient invalid, etc.). The SMTP server maps
// this to `550`.
type ErrProtonReject struct {
	Cause error
}

func (e *ErrProtonReject) Error() string {
	return "outbox: proton rejected: " + e.Cause.Error()
}

func (e *ErrProtonReject) Unwrap() error { return e.Cause }

// ErrProtonServer wraps an unspecified upstream server error. The SMTP
// server maps this to `451` so the sending MTA retries.
type ErrProtonServer struct {
	Cause error
}

func (e *ErrProtonServer) Error() string {
	return "outbox: proton server error: " + e.Cause.Error()
}

func (e *ErrProtonServer) Unwrap() error { return e.Cause }

// ProtonClientResolver lets the outbox obtain a session-bearing
// proton.Client for a given account ID at submission time. We resolve
// per-Submit (not once at worker construction) so a token rotation
// performed by the sync worker is observed immediately by the next
// outbox send.
//
// Implementations live in the composition root and typically wrap
// account.Service.OpenRefreshToken + proton.Manager.WithAccount.
//
// Returns ErrAccountClosed when the account has been suspended /
// soft-deleted; the outbox propagates that verbatim so the SMTP
// server returns the right code.
type ProtonClientResolver interface {
	ResolveClient(accountID string) (proton.Client, error)
}

// ProtonClientResolverFunc adapts a plain function to
// ProtonClientResolver. Useful in the composition root and tests.
type ProtonClientResolverFunc func(accountID string) (proton.Client, error)

// ResolveClient implements ProtonClientResolver.
func (f ProtonClientResolverFunc) ResolveClient(accountID string) (proton.Client, error) {
	return f(accountID)
}
