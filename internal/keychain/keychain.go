// Package keychain stores and retrieves a mailbox's two live secrets — the
// Proton refresh token and the mailbox passphrase — in the operating
// system's secret service: macOS Keychain, Linux Secret Service (libsecret
// / GNOME Keyring / KWallet via D-Bus), or Windows Credential Manager. It is
// the only component permitted to hold those secret values; everything else
// in Reduit references a mailbox by its local UUIDv7 and asks this package
// for the secret at use time.
//
// Keying (ADR-0013): every entry is written under service name "reduit" with
// account key "mailbox/<mailbox_id>/<kind>" where <kind> is one of
// "refresh_token" or "mailbox_passphrase". Secrets are per mailbox; there is
// no shared key spanning mailboxes, so removing one mailbox's secrets never
// touches another's. The SQLite store holds only the <mailbox_id> reference
// (SPEC-0001 REQ "Secret References, Not Secrets"); no secret, ciphertext, or
// key-envelope column exists in the schema.
//
// Leakage posture (SPEC-0007 REQ "No Secret Leakage"): this package never
// logs, formats, or embeds a secret value. Secrets flow only as the `secret`
// argument to Set and the return value of Get; the Store carries no secret
// state, and every error returned here is a static sentinel or a wrap of an
// OS/transport error that does not contain the secret. There is therefore no
// Stringer or error path through which a token or passphrase can be printed.
//
// Availability (SPEC-0007 REQ "Keyring Availability"): a usable, unlocked OS
// keyring is a hard precondition. When the keyring is missing or locked, the
// underlying transport error is mapped to ErrUnavailable so callers can abort
// with a clear, actionable message instead of silently falling back to an
// on-disk secret store — there is deliberately no file-based fallback
// (ADR-0013). On a headless host the operator unlocks a Secret Service
// collection out of band before sync workers run.
//
// Governing: ADR-0013 (secrets in OS keychain), SPEC-0007 (onboarding & auth)
// REQs "Secret Write, Read, and Delete" / "No Secret Leakage" / "Keyring
// Availability", SPEC-0001 REQ "Secret References, Not Secrets".
package keychain

import (
	"errors"
	"fmt"
	"strings"

	"github.com/zalando/go-keyring"
)

// ServiceName is the OS keyring service under which every Reduit secret is
// stored. Fixed by ADR-0013.
const ServiceName = "reduit"

// Kind enumerates the two — and only two — secret classes Reduit persists per
// mailbox (ADR-0013). The string values are load-bearing: they form the final
// segment of the keyring account key, so they MUST NOT change without a
// migration.
type Kind string

const (
	// RefreshToken is the Proton refresh token that renews the access token.
	RefreshToken Kind = "refresh_token"
	// MailboxPassphrase unlocks the mailbox's OpenPGP private keys.
	MailboxPassphrase Kind = "mailbox_passphrase"
)

// allKinds lists every secret kind a mailbox can own. DeleteAll iterates it so
// that adding a future kind automatically extends mailbox teardown.
var allKinds = []Kind{RefreshToken, MailboxPassphrase}

// valid reports whether k is a recognised secret kind.
func (k Kind) valid() bool {
	switch k {
	case RefreshToken, MailboxPassphrase:
		return true
	default:
		return false
	}
}

// Sentinel errors. None of these embeds a secret value (SPEC-0007 REQ "No
// Secret Leakage"); callers match them with errors.Is.
var (
	// ErrNotFound is returned by Get and Delete when no secret exists for the
	// given mailbox and kind. It mirrors the keyring's own not-found signal so
	// "never authenticated" reads are distinguishable from a broken keyring.
	ErrNotFound = errors.New("keychain: secret not found")

	// ErrUnavailable is returned when the OS keyring / Secret Service is
	// missing or locked (SPEC-0007 REQ "Keyring Availability"). Callers SHALL
	// surface a clear, actionable message and MUST NOT fall back to on-disk
	// storage.
	ErrUnavailable = errors.New("keychain: OS keyring unavailable or locked")

	// ErrSecretTooBig is returned when a secret exceeds the platform keyring's
	// size limit. Reduit's secrets (a refresh token, a passphrase) are far
	// below any platform limit, so this signals a programming error upstream.
	ErrSecretTooBig = errors.New("keychain: secret too large for OS keyring")

	// ErrInvalidKind is returned when a Kind outside the allowed set is used.
	ErrInvalidKind = errors.New("keychain: invalid secret kind")

	// ErrInvalidMailboxID is returned when the mailbox id is empty or contains
	// a path separator that would make the account key ambiguous.
	ErrInvalidMailboxID = errors.New("keychain: invalid mailbox id")
)

// Store is the typed secret API over the OS keychain. All methods are keyed by
// the local UUIDv7 mailbox id and a Kind; no method accepts or returns a raw
// account key, so the "mailbox/<id>/<kind>" layout (ADR-0013) is enforced in
// one place.
type Store interface {
	// Set writes (creating or overwriting) the secret for the mailbox/kind.
	Set(mailboxID string, kind Kind, secret string) error
	// Get reads the secret for the mailbox/kind, or ErrNotFound if absent.
	Get(mailboxID string, kind Kind) (string, error)
	// Delete removes the secret for the mailbox/kind, or ErrNotFound if absent.
	Delete(mailboxID string, kind Kind) error
	// DeleteAll removes every secret kind owned by the mailbox. It is
	// idempotent: an already-absent kind is not an error, so mailbox removal
	// leaves no orphaned secret (SPEC-0007 scenario "Secrets deleted on
	// mailbox removal").
	DeleteAll(mailboxID string) error
}

// keyringStore is the concrete Store backed by github.com/zalando/go-keyring.
// It holds no fields — and in particular no secret state — so it is safe to
// share and its zero value plus New() are equivalent.
type keyringStore struct{}

// New returns a Store backed by the host OS keyring (ADR-0013). It performs no
// I/O; availability is checked lazily on the first Set/Get/Delete, surfacing
// as ErrUnavailable.
func New() Store {
	return keyringStore{}
}

// accountKey builds the "mailbox/<id>/<kind>" account key after validating
// both inputs, so a malformed id or kind can never produce a surprising key.
func accountKey(mailboxID string, kind Kind) (string, error) {
	if mailboxID == "" || strings.ContainsRune(mailboxID, '/') {
		return "", ErrInvalidMailboxID
	}
	if !kind.valid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidKind, kind)
	}
	return "mailbox/" + mailboxID + "/" + string(kind), nil
}

// mapErr translates a go-keyring error into a package sentinel. It never
// inspects or includes secret values; the wrapped error is the OS/transport
// error (e.g. a D-Bus failure), which does not carry the secret.
func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, keyring.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, keyring.ErrSetDataTooBig):
		return ErrSecretTooBig
	default:
		// Any other failure means the keyring could not be reached or is
		// locked. Wrap for operator context without leaking the secret.
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
}

// Set writes the secret for mailboxID/kind, overwriting any existing value.
//
// Governing: SPEC-0007 REQ "Secret Write, Read, and Delete" scenario "Secrets
// created on successful auth".
func (keyringStore) Set(mailboxID string, kind Kind, secret string) error {
	key, err := accountKey(mailboxID, kind)
	if err != nil {
		return err
	}
	return mapErr(keyring.Set(ServiceName, key, secret))
}

// Get reads the secret for mailboxID/kind. It returns ErrNotFound if no secret
// exists and ErrUnavailable if the keyring cannot be reached.
//
// Governing: SPEC-0007 REQ "Secret Write, Read, and Delete" scenario "Secrets
// read non-interactively at use time".
func (keyringStore) Get(mailboxID string, kind Kind) (string, error) {
	key, err := accountKey(mailboxID, kind)
	if err != nil {
		return "", err
	}
	secret, err := keyring.Get(ServiceName, key)
	if err != nil {
		return "", mapErr(err)
	}
	return secret, nil
}

// Delete removes the secret for mailboxID/kind. It returns ErrNotFound if no
// secret exists.
func (keyringStore) Delete(mailboxID string, kind Kind) error {
	key, err := accountKey(mailboxID, kind)
	if err != nil {
		return err
	}
	return mapErr(keyring.Delete(ServiceName, key))
}

// DeleteAll removes every secret kind owned by mailboxID, tolerating
// already-absent kinds so mailbox teardown is idempotent and leaves nothing
// orphaned. It does NOT use the keyring's service-wide DeleteAll, which would
// wipe every mailbox's secrets; each kind is deleted under its per-mailbox key.
//
// Governing: SPEC-0007 REQ "Secret Write, Read, and Delete" scenario "Secrets
// deleted on mailbox removal".
func (s keyringStore) DeleteAll(mailboxID string) error {
	// Validate the id once up front so an invalid id is reported even when the
	// per-kind deletes would all be no-ops.
	if mailboxID == "" || strings.ContainsRune(mailboxID, '/') {
		return ErrInvalidMailboxID
	}
	for _, kind := range allKinds {
		if err := s.Delete(mailboxID, kind); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	return nil
}
