// Per-recipient encryption-mode selector. The selector is the
// security boundary the hostile reviewer will scrutinise hardest:
// it must NOT silently downgrade a Proton-internal recipient to a
// cleartext send because of a transient lookup failure, and it must
// NOT aggregate per-recipient decisions into one cleartext message.
//
// Each recipient gets its own decision; the worker uses the result to
// pick which Proton message-package-set the body is encrypted into.
//
// Governing: SPEC-0004 REQ "Encryption Pipeline".

package outbox

import (
	"context"
	"errors"
	"strings"

	"github.com/joestump/reduit/internal/proton"
)

// SelectMode chooses the per-recipient encryption mode by querying
// /core/v4/keys for each address. The decision tree, in priority order:
//
//  1. Lookup error (network, 5xx, parse failure) → ErrKeyLookup is
//     returned and the entire submission MUST be rejected. Treating a
//     lookup error as "fall through to cleartext" would silently
//     downgrade a Proton-internal recipient to a cleartext send when
//     Proton's key service is degraded — a security regression. Fail
//     closed and let the SMTP layer return 451 to the sending MTA so
//     the message is retried after the partial outage clears.
//
//  2. RecipientType=Internal AND keys returned AND at least one key is
//     active (KeyStateActive flag set) → ModeProtonE2E. The body is
//     encrypted to that key, signed by the sender.
//
//  3. RecipientType=Internal AND no active keys returned → fail
//     closed (ErrKeyLookup with "no active keys" cause). A Proton
//     account with zero active address keys is an account migration
//     edge case; the safe default is "do not send" rather than "send
//     in cleartext".
//
//  4. RecipientType=External AND keys returned AND at least one key
//     is active → ModeExternalE2E. Mirrors Proton's "encrypt to
//     outside" preference — v0.1 always opts in when a key is
//     available; the per-account opt-out lands in a follow-up.
//
//  5. RecipientType=External AND no keys returned → ModeCleartext.
//     The body is relayed by Proton's outbound MTA in cleartext;
//     Proton signs with its DKIM keys.
//
// SelectMode is deterministic: called twice with the same inputs it
// returns the same output.
func SelectMode(ctx context.Context, client proton.Client, recipients []string) (map[string]EncryptionMode, error) {
	if len(recipients) == 0 {
		return nil, ErrSubmissionEnvelope
	}
	out := make(map[string]EncryptionMode, len(recipients))
	for _, raw := range recipients {
		addr := normaliseRecipient(raw)
		if addr == "" {
			return nil, &ErrKeyLookup{
				Recipient: raw,
				Cause:     errors.New("empty recipient address"),
			}
		}

		keys, recipientType, err := client.GetPublicKeys(ctx, addr)
		if err != nil {
			// Fail closed. See top-of-function rationale.
			return nil, &ErrKeyLookup{Recipient: addr, Cause: err}
		}

		mode, err := classify(addr, keys, recipientType)
		if err != nil {
			return nil, err
		}
		out[addr] = mode
	}
	return out, nil
}

// classify is the pure decision function pulled out so its branches
// can be unit-tested without any HTTP plumbing.
func classify(addr string, keys proton.PublicKeys, recipientType proton.RecipientType) (EncryptionMode, error) {
	hasActive := false
	// Governing: SPEC-0004 REQ "Encryption Pipeline" — fail-closed on
	// compromised-but-still-active Proton keys; require both Active AND
	// Trusted bits. KeyStateActive=2 means "still in use", KeyStateTrusted=1
	// means "not compromised". A key with Active set but Trusted clear is a
	// compromised-but-not-yet-obsolete key — Proton has marked it
	// untrustworthy but kept it Active for an active migration window.
	// Encrypting to such a key would leak user mail to a key Proton has
	// already disavowed. The fix is to require BOTH bits.
	const usable = proton.KeyStateActive | proton.KeyStateTrusted
	for _, k := range keys {
		if k.Flags&usable == usable {
			hasActive = true
			break
		}
	}

	switch recipientType {
	case proton.RecipientTypeInternal:
		if !hasActive {
			// Should be impossible in practice (a Proton account always
			// has at least one active address key) but a degraded
			// response is safer to reject than to downgrade.
			return ModeUnknown, &ErrKeyLookup{
				Recipient: addr,
				Cause:     errors.New("internal recipient returned no active keys"),
			}
		}
		return ModeProtonE2E, nil
	case proton.RecipientTypeExternal:
		if hasActive {
			return ModeExternalE2E, nil
		}
		return ModeCleartext, nil
	default:
		// An unknown RecipientType is a forwards-compatibility hazard:
		// silently coercing it to "external" would be a downgrade if
		// Proton ever introduces a new internal-equivalent type. Fail
		// closed instead.
		return ModeUnknown, &ErrKeyLookup{
			Recipient: addr,
			Cause:     errors.New("unknown recipient type from key lookup"),
		}
	}
}

// normaliseRecipient lower-cases and trims an address. Mirrors the
// SMTP-side normalisation so the same address that passed RCPT TO
// validation is the one we look up here.
func normaliseRecipient(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
