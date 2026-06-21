// Daemon-restart re-unlock: re-establish an authenticated AND
// mailbox-unlocked proton.Client for an account from its sealed secrets,
// WITHOUT an interactive wizard run.
//
// This is the mechanism issue #28 needs so that, on `reduit serve` boot,
// every account already in `state = active` gets a live unlocked client
// registered (so FETCH BODY[] / MCP get_message decrypt bodies straight
// away) instead of failing with proton.ErrNotUnlocked until the operator
// happens to re-run the wizard.
//
// ┌─────────────────────────────────────────────────────────────────────┐
// │ BLOCKER — the Proton session UID is not persisted today.            │
// │                                                                     │
// │ ReUnlock needs three inputs: the session UID, the refresh token,    │
// │ and the mailbox passphrase. Reduit seals the refresh token          │
// │ (refresh_token_ciphertext) and the mailbox passphrase               │
// │ (mailbox_passphrase_ciphertext), but it does NOT persist the        │
// │ ephemeral Proton *session UID* — the wizard captures auth.UID at    │
// │ login (NewClientWithLogin) and discards it; only auth.UserID (the   │
// │ persistent proton_user_id) is stored. go-proton-api's               │
// │ /auth/v4/refresh requires the session UID, so a fresh process has   │
// │ no way to re-auth from the refresh token alone.                     │
// │                                                                     │
// │ Closing this gap is a schema + secret-handling change (a new        │
// │ sealed `session_uid_ciphertext` column, the wizard sealing          │
// │ auth.UID at commit time, and an AccountSnapshot exposing it),       │
// │ tracked as issue #34 — out of scope for #28's foundation. Until     │
// │ #34 lands, ReUnlock is fully implemented and unit-tested against    │
// │ an injected UID, and the supervisor boot hook                       │
// │ (RegisterActiveAccounts) is wired but SKIPS accounts for which no   │
// │ UID is available, logging once at WARN so the gap is operator-      │
// │ visible rather than silent.                                         │
// └─────────────────────────────────────────────────────────────────────┘
//
// Governing: ADR-0003 (master-key envelope encryption at rest — the
// passphrase and refresh token are unsealed only for the duration of this
// call), ADR-0001 (go-proton-api), SPEC-0002 REQ "One Worker Per Active
// Account" (restart re-establishes the live client an active account
// needs; the session-UID gap is tracked in #34).
package protonlive

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/joestump/reduit/internal/proton"
)

// ErrNoSessionUID is returned by ReUnlock when no session UID was
// supplied. It is the sentinel the supervisor boot hook branches on to
// SKIP (rather than fail) an account whose UID is not yet persisted — see
// the package-level BLOCKER note. Distinct from a credential-rejected
// error so callers can tell "we can't even try" apart from "we tried and
// Proton said no".
var ErrNoSessionUID = errors.New("protonlive: no persisted Proton session UID; cannot re-unlock on restart (see #34)")

// ErrCredentialRejected wraps a ReUnlock failure that the account cannot
// recover from by retrying: a revoked/invalid refresh token, a forbidden
// (403) session, a wrong mailbox passphrase (Unlock failed), or a Proton
// account with no keys. The boot hook (lifecycle.registerOne) branches on
// this — errors.Is(err, ErrCredentialRejected) — to decide whether to
// kick the account to pending_proton_setup (credential failure) or leave
// it active and WARN (transient failure).
//
// This mirrors the #12 sync-worker policy: only classified credential
// failures (isRefreshTokenRevokedError / isUnrecoverableProtonError) drive
// the account to pending; transient errors (network blips, Proton 5xx,
// 429) are left to retry. protonlive cannot import sync's unexported
// classifiers, so the equivalent classification lives in classifyAuth /
// reUnlockErr below.
//
// Governing: SPEC-0002 REQ "Backoff on Failure" — "Permanent errors do
// not retry indefinitely" (credential failure -> pending), transient
// errors are not permanent.
var ErrCredentialRejected = errors.New("protonlive: re-unlock rejected by Proton (credential failure)")

// Authenticator is the slice of proton.Manager ReUnlock needs to
// re-establish a session from a refresh token. *proton.Manager satisfies
// it; tests inject a fake.
type Authenticator interface {
	// NewClientWithRefresh re-authenticates from UID + refresh token.
	NewClientWithRefresh(ctx context.Context, uid, refreshTok string) (proton.Client, *proton.Auth, error)
}

// ReUnlockInputs bundles the per-account material ReUnlock consumes. The
// caller (the supervisor boot hook) unseals the refresh token and mailbox
// passphrase from the account's data key and supplies them here; ReUnlock
// never touches the master key or the DB.
//
// The byte slices are the caller's to zero after ReUnlock returns —
// ReUnlock does not retain references to them beyond the calls below.
type ReUnlockInputs struct {
	// AccountID is used only for error context / logging.
	AccountID string
	// SessionUID is the ephemeral Proton session UID. Empty triggers
	// ErrNoSessionUID (the not-yet-persisted gap).
	SessionUID string
	// RefreshToken is the unsealed Proton refresh token.
	RefreshToken string
	// MailboxPassphrase is the unsealed Proton mailbox password used to
	// derive the salted key that decrypts the user keyring.
	MailboxPassphrase []byte
}

// ReUnlock re-authenticates the account's Proton session from its UID +
// refresh token, then runs the same GetUser → KeySalts → SaltForKey →
// GetAddresses → Unlock sequence the wizard's commit path runs, returning
// a client whose per-address keyrings are retained in process (ready to
// hand to Registry.Set).
//
// On ANY failure the partially-established upstream session is Logout'd
// before returning so a half-open session is not leaked.
//
// The returned error is classified so the caller can distinguish a
// CREDENTIAL failure (errors.Is(err, ErrCredentialRejected): revoked
// refresh token, 403 session, wrong passphrase, no keys — account should
// go to pending_proton_setup) from a TRANSIENT failure (network blip,
// Proton 5xx/429 on a data fetch — leave the account active, retry
// later). This mirrors the #12 sync-worker policy; see
// ErrCredentialRejected.
//
// This mirrors internal/server/wizard_handlers.go commitWizard's unlock
// sequence exactly; the two SHOULD stay in sync. The duplication is
// deliberate: the wizard runs against a live login-derived client (it
// already has a session), whereas ReUnlock must first re-establish the
// session from stored credentials.
//
// Governing: ADR-0003 (envelope-sealed passphrase unsealed only here),
// SPEC-0002 REQ "One Worker Per Active Account", SPEC-0002 REQ "Backoff
// on Failure" (credential vs. transient classification).
func ReUnlock(ctx context.Context, auth Authenticator, in ReUnlockInputs) (proton.Client, error) {
	if in.SessionUID == "" {
		return nil, ErrNoSessionUID
	}
	if in.RefreshToken == "" {
		// A stored-but-empty refresh token is a credential failure: the
		// account cannot re-auth and re-running the wizard is the only fix.
		return nil, reUnlockErr(in.AccountID, "empty refresh token", nil, true)
	}

	client, _, err := auth.NewClientWithRefresh(ctx, in.SessionUID, in.RefreshToken)
	if err != nil {
		// A refresh-auth failure is credential-rejected only when Proton
		// actively rejects the token (401 / 10013 / 403); a network error
		// or 5xx on /auth/v4/refresh is transient and must NOT kick the
		// account to pending.
		return nil, reUnlockErr(in.AccountID, "refresh auth", err, isCredentialAuthError(err))
	}

	// From here on, any failure must tear down the session we just
	// established so we don't leak a live upstream client.
	user, err := client.GetUser(ctx)
	if err != nil {
		_ = client.Logout(context.Background())
		// A 401/403 on GetUser means the just-minted session is already
		// rejected (credential); anything else (5xx, network) is transient.
		return nil, reUnlockErr(in.AccountID, "get user", err, isCredentialAuthError(err))
	}
	if len(user.Keys) == 0 {
		_ = client.Logout(context.Background())
		// No keys is a durable account-side condition the operator must
		// resolve in Proton before relaying — credential-rejected.
		return nil, reUnlockErr(in.AccountID, "proton account has no keys", nil, true)
	}
	salts, err := client.KeySalts(ctx)
	if err != nil {
		_ = client.Logout(context.Background())
		return nil, reUnlockErr(in.AccountID, "key salts", err, isCredentialAuthError(err))
	}
	saltedKey, err := salts.SaltForKey(in.MailboxPassphrase, user.Keys.Primary().ID)
	if err != nil {
		_ = client.Logout(context.Background())
		// SaltForKey fails on a missing/malformed salt for the primary
		// key — a key-derivation failure on the passphrase path, which
		// retrying cannot fix. Credential-rejected.
		return nil, reUnlockErr(in.AccountID, "salt for key", err, true)
	}
	addresses, err := client.GetAddresses(ctx)
	if err != nil {
		_ = client.Logout(context.Background())
		return nil, reUnlockErr(in.AccountID, "get addresses", err, isCredentialAuthError(err))
	}
	if _, _, err := client.Unlock(user, addresses, saltedKey); err != nil {
		_ = client.Logout(context.Background())
		// Unlock is a pure local operation: a failure here is a wrong
		// mailbox passphrase (or corrupt stored passphrase), never a
		// transient network condition. Credential-rejected.
		return nil, reUnlockErr(in.AccountID, "unlock", err, true)
	}
	return client, nil
}

// reUnlockErr builds the ReUnlock error for a given stage. When
// credential is true the returned error wraps ErrCredentialRejected (so
// the caller's errors.Is hits) AND the underlying cause; otherwise it
// wraps only the cause (a transient failure the caller leaves to retry).
// cause may be nil for stages that fail without an upstream error (empty
// token, no keys).
func reUnlockErr(accountID, stage string, cause error, credential bool) error {
	switch {
	case credential && cause != nil:
		return fmt.Errorf("protonlive: re-unlock %s: %s: %w: %w", accountID, stage, ErrCredentialRejected, cause)
	case credential:
		return fmt.Errorf("protonlive: re-unlock %s: %s: %w", accountID, stage, ErrCredentialRejected)
	default:
		return fmt.Errorf("protonlive: re-unlock %s: %s: %w", accountID, stage, cause)
	}
}

// isCredentialAuthError reports whether err is a Proton authorization
// rejection that retrying cannot fix — the protonlive equivalent of the
// sync package's isRefreshTokenRevokedError + isUnrecoverableProtonError
// (which protonlive cannot import, as they are unexported). We classify
// the same surfaces:
//
//   - Code == AuthRefreshTokenInvalid (10013): the refresh token is
//     revoked/invalid (the explicit SPEC-0002 "Backoff on Failure"
//     permanent case).
//   - HTTP 401: a refresh round-trip gave up / the session is rejected.
//   - HTTP 403: the session is forbidden (locked / insufficient scope /
//     needs re-unlock) — recoverable only by re-running the wizard, so it
//     routes to pending_proton_setup the same way the sync worker does.
//
// Everything else (network/dial errors, 5xx, 429) is NOT a credential
// rejection: it is transient and must be left to retry rather than
// kicking a healthy account to pending. A nil err is not a credential
// error.
//
// Governing: SPEC-0002 REQ "Backoff on Failure" (mirrors the sync
// worker's permanent-vs-transient split).
func isCredentialAuthError(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *gpa.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.Code == gpa.AuthRefreshTokenInvalid {
		return true
	}
	return apiErr.Status == http.StatusUnauthorized || apiErr.Status == http.StatusForbidden
}
