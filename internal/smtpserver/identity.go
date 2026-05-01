// SASL identity validation. Mirrors internal/imapserver/identity.go so
// the IMAP and SMTP listeners impose identical syntactic rules on the
// `local@host` form a client supplies in SASL PLAIN.
//
// Mirroring (rather than extracting a shared package) is a deliberate
// choice for the v0.2 surface: there are exactly two callers, the file
// is small, and a hostile reviewer flagging "over-abstraction for a
// 2-caller surface" would be correct. When a third listener appears
// (LMTP? Sieve? unlikely soon) the helpers can be lifted into a shared
// `internal/saslcommon` package.
//
// Governing: SPEC-0004 REQ "SASL PLAIN Authentication Matching IMAP",
// SPEC-0003 REQ "SASL PLAIN With user@host Identity" (parallel rules).

package smtpserver

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
// rejected SASL identity. Callers translate this to the SMTP-level
// 535 Authentication failed response.
var errInvalidIdentity = errors.New("smtpserver: invalid SASL identity")

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
	// value cannot inject an SMTP response line if a downstream caller
	// ever forgets to encode it. We also reject DEL and any byte > 0x7E
	// because aliases are ASCII-only by operator configuration.
	//
	// Governing: SPEC-0004 REQ "SASL PLAIN Authentication Matching
	// IMAP" — Reduit commits to ASCII-only identities. Admitting
	// non-ASCII would require Unicode-aware case-folding and NFC
	// normalisation to compare safely.
	for i := 0; i < len(identity); i++ {
		b := identity[i]
		if b < 0x20 || b == 0x7F {
			return wrapInvalid("control-character")
		}
		if b >= 0x80 {
			return wrapInvalid("non-ascii")
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
	return &invalidIdentityErr{reason: reason}
}

type invalidIdentityErr struct {
	reason string
}

func (e *invalidIdentityErr) Error() string {
	return "smtpserver: invalid SASL identity (" + e.reason + ")"
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
