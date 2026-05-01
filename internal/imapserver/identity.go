// SASL identity validation. The wire form a client supplies in the
// PLAIN response is `local@host`. Before we hit the database we run a
// strict syntactic check so that:
//
//   - hostile input (embedded NUL / CR / LF, oversized strings) cannot
//     reach the SQL layer or the slog formatter (no IMAP response
//     injection from a malicious username);
//   - benign input mismatches (forgot to include `@`, two `@`s) fail
//     fast with a structured log entry instead of a stale UNIQUE
//     lookup.
//
// Validation here is intentionally narrower than RFC 5322. Reduit's
// alias namespace is operator-controlled — every legitimate alias is
// configured by the admin and goes through SetPrimaryAlias, which
// applies the same normalisation. That gives us a tight, predictable
// allowed-character set: ASCII printable minus a small forbid list.
//
// Governing: SPEC-0003 REQ "SASL PLAIN With user@host Identity",
// SPEC-0003 REQ "Authentication failure returns NO with no detail"
// (validation failures map to AUTHENTICATIONFAILED, never a chattier
// status code that would tell an attacker which validation rule
// tripped).
package imapserver

import (
	"errors"
	"strings"
)

// MaxSASLIdentityLength caps the raw SASL identity at a generous but
// finite size. RFC 5321 limits the local part to 64 octets and the
// domain to 255, so a hard ceiling well above 320 bytes is sufficient
// to represent any legitimate user@host while still bounding what an
// attacker can shove into a log line or a DB lookup.
const MaxSASLIdentityLength = 512

// errInvalidIdentity is the package-internal sentinel for any
// rejected SASL identity. Callers translate this to the
// IMAP-level AUTHENTICATIONFAILED response.
var errInvalidIdentity = errors.New("imapserver: invalid SASL identity")

// validateSASLIdentity returns nil when the wire-form identity meets
// the syntactic preconditions for an account lookup. It returns
// errInvalidIdentity (or a wrapping error explaining the cause) for
// anything that should be rejected outright. The returned reason is
// safe to record in a server-side structured log; it is NEVER echoed
// to the client.
func validateSASLIdentity(identity string) error {
	if identity == "" {
		return wrapInvalid("empty")
	}
	if len(identity) > MaxSASLIdentityLength {
		return wrapInvalid("oversized")
	}
	// Reject control characters (most importantly NUL, CR, LF) so the
	// value cannot inject an IMAP response line if a downstream caller
	// ever forgets to encode it. We also reject DEL and any byte > 0x7E
	// because aliases are ASCII-only by operator configuration.
	for i := 0; i < len(identity); i++ {
		b := identity[i]
		if b < 0x20 || b == 0x7F {
			return wrapInvalid("control-character")
		}
	}
	// Exactly one '@' separator. Zero means "not local@host". Two or
	// more is ambiguous and we refuse to guess.
	if strings.Count(identity, "@") != 1 {
		return wrapInvalid("at-count")
	}
	local, host, _ := strings.Cut(identity, "@")
	if local == "" {
		return wrapInvalid("empty-local")
	}
	if host == "" {
		return wrapInvalid("empty-host")
	}
	return nil
}

func wrapInvalid(reason string) error {
	// Wrap so callers can errors.Is(err, errInvalidIdentity) and so
	// the structured log can record the specific reason without
	// adding the user-supplied bytes back into the message.
	return &invalidIdentityErr{reason: reason}
}

type invalidIdentityErr struct {
	reason string
}

func (e *invalidIdentityErr) Error() string {
	return "imapserver: invalid SASL identity (" + e.reason + ")"
}

func (e *invalidIdentityErr) Is(target error) bool {
	return target == errInvalidIdentity
}

// invalidIdentityReason returns the categorised reason if err was
// produced by validateSASLIdentity, or "" otherwise. Tests use this
// to assert which validation arm fired without coupling to the
// formatted error text.
func invalidIdentityReason(err error) string {
	var ie *invalidIdentityErr
	if errors.As(err, &ie) {
		return ie.reason
	}
	return ""
}
