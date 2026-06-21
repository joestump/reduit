// Lifecycle binds the Registry to account-state transitions so the set of
// live unlocked clients tracks the set of `active` accounts:
//
//   - On daemon boot, RegisterActiveAccounts re-authenticates and
//     re-unlocks every account already in `state = active` and registers
//     the resulting client. This is the restart path that makes FETCH
//     BODY[] / MCP get_message work without waiting for a wizard re-run.
//
//   - OnAccountStateChange drops an account's client when it leaves
//     `active`, mirroring where the sync supervisor stops the worker.
//     (Population on the active edge is handled by the wizard at commit
//     time and by RegisterActiveAccounts at boot; the supervisor's
//     active-edge transition fires for an account that already has a
//     live client from the wizard, so OnAccountStateChange does NOT
//     re-unlock on every activation — that would double-Logout the
//     wizard's freshly-registered client.)
//
// On an unlock/auth FAILURE during boot, Lifecycle transitions the
// account to pending_proton_setup (reusing the path #12 added for
// permanent sync failures) so the account does not sit in `active`
// silently failing every body fetch; the operator is then prompted to
// re-run the wizard.
//
// Governing: ADR-0003, ADR-0001, SPEC-0002 REQ "One Worker Per Active
// Account" (registry lifecycle mirrors worker lifecycle), SPEC-0002 REQ
// "Backoff on Failure" (auth/unlock failure -> pending_proton_setup,
// recoverable terminal).
package protonlive

import (
	"context"
	"errors"
	"log/slog"

	"github.com/joestump/reduit/internal/account"
)

// SecretSource is the slice of account.Service Lifecycle needs to unseal
// the per-account credentials. account.Service satisfies it.
type SecretSource interface {
	OpenRefreshToken(ctx context.Context, accountID string) ([]byte, error)
	OpenMailboxPassphrase(ctx context.Context, accountID string) ([]byte, error)
}

// UIDSource resolves an account's persisted Proton *session* UID. It is a
// SEPARATE interface from SecretSource because no implementation exists
// today: the session UID is not persisted (see reunlock.go's BLOCKER
// note). The composition root passes nil until a UID-sealing column and
// its accessor land; RegisterActiveAccounts treats a nil UIDSource (or an
// empty UID) as "skip this account, logged once at WARN".
//
// When the persistence gap is closed (#34), implement this against the
// account service's new OpenSessionUID accessor and pass it in —
// RegisterActiveAccounts then re-unlocks on boot with no further change
// here.
type UIDSource interface {
	OpenSessionUID(ctx context.Context, accountID string) (string, error)
}

// Transitioner is the slice of account.Service used to kick an account to
// pending_proton_setup on an unrecoverable boot-time unlock failure.
type Transitioner interface {
	Transition(ctx context.Context, id string, next account.State) (*account.Account, error)
}

// Lifecycle wires a Registry to the account service. Construct via
// NewLifecycle. It is safe for concurrent use (the Registry it wraps is,
// and Lifecycle itself holds no mutable state beyond its dependencies).
type Lifecycle struct {
	reg    *Registry
	auth   Authenticator
	secret SecretSource
	uids   UIDSource
	trans  Transitioner
	logger *slog.Logger
}

// NewLifecycle constructs a Lifecycle. uids MAY be nil — see UIDSource;
// when nil, boot-time re-unlock is skipped for every account and logged
// once per account at WARN so the missing-UID gap is visible. A nil
// logger falls back to the registry's logger.
func NewLifecycle(reg *Registry, auth Authenticator, secret SecretSource, uids UIDSource, trans Transitioner, logger *slog.Logger) *Lifecycle {
	if logger == nil {
		logger = reg.logger
	}
	return &Lifecycle{
		reg:    reg,
		auth:   auth,
		secret: secret,
		uids:   uids,
		trans:  trans,
		logger: logger,
	}
}

// RegisterActiveAccounts re-unlocks and registers a live client for each
// account in `actives`. The caller supplies the slice (typically
// account.Service.List filtered to StateActive) so Lifecycle does not need
// the full Service surface.
//
// Failure handling per account is independent: one account's auth/unlock
// failure does not abort the others. A genuine credential failure (the
// refresh token was revoked, or the passphrase no longer decrypts the
// keyring) transitions that account to pending_proton_setup. A missing
// session UID (the not-yet-persisted gap) is NOT a credential failure —
// it is logged at WARN and the account is left in `active` (its sync
// worker still runs; only body decryption is unavailable until the
// operator re-runs the wizard, which re-populates the registry directly).
//
// Governing: SPEC-0002 REQ "Backoff on Failure" (credential failure ->
// pending_proton_setup), SPEC-0002 REQ "One Worker Per Active Account".
func (l *Lifecycle) RegisterActiveAccounts(ctx context.Context, actives []*account.Account) {
	for _, a := range actives {
		if a == nil || a.State != account.StateActive {
			continue
		}
		l.registerOne(ctx, a.ID)
	}
}

// registerOne re-unlocks a single account and registers it, or handles
// the failure. Split out so RegisterActiveAccounts stays a thin loop and
// the per-account error policy lives in one place.
func (l *Lifecycle) registerOne(ctx context.Context, accountID string) {
	uid, ok := l.sessionUID(ctx, accountID)
	if !ok {
		// Missing-UID gap: not a credential failure. Leave the account
		// active; only body decryption is degraded until a wizard re-run.
		l.logger.Warn("protonlive: skipping boot re-unlock; no persisted Proton session UID (body decryption will be unavailable until the account is re-set-up)",
			slog.String("account_id", accountID))
		return
	}

	// Secret-open failures are LOCAL (DB read / envelope decrypt), not a
	// Proton credential rejection. Treat them as transient — leave the
	// account active and WARN — for the same reason a transient ReUnlock
	// error is left active: a healthy account must not be kicked to
	// pending on a SQLite lock blip or a momentary read error. A genuinely
	// corrupt sealed secret will recur and surface in the logs; it does
	// not warrant a silent state change here.
	refresh, err := l.secret.OpenRefreshToken(ctx, accountID)
	if err != nil {
		l.logger.Warn("protonlive: boot re-unlock skipped; cannot open refresh token (account left active)",
			slog.String("account_id", accountID), slog.Any("err", err))
		return
	}
	defer zero(refresh)

	passphrase, err := l.secret.OpenMailboxPassphrase(ctx, accountID)
	if err != nil {
		l.logger.Warn("protonlive: boot re-unlock skipped; cannot open mailbox passphrase (account left active)",
			slog.String("account_id", accountID), slog.Any("err", err))
		return
	}
	defer zero(passphrase)

	// NOTE on residency: string(refresh) copies the unsealed token into
	// an immutable string that `defer zero(refresh)` cannot wipe — Go
	// strings are immutable and we cannot reach their backing array. This
	// is unavoidable here because the upstream go-proton-api
	// /auth/v4/refresh entry point (NewClientWithRefresh) takes a string;
	// the token would be copied into one before the HTTP body is built
	// regardless. We still zero the []byte source so the longer-lived
	// buffer (the one we control) does not linger. The transient string
	// copy is unreachable to us and is left to the GC. The MailboxPassphrase
	// stays a []byte all the way into SaltForKey, so its residency IS
	// bounded by the defer zero(passphrase) above.
	client, err := ReUnlock(ctx, l.auth, ReUnlockInputs{
		AccountID:         accountID,
		SessionUID:        uid,
		RefreshToken:      string(refresh),
		MailboxPassphrase: passphrase,
	})
	if err != nil {
		// Mirror the #12 sync-worker policy: only a CLASSIFIED credential
		// failure (revoked token / 403 / wrong passphrase / no keys)
		// returns the account to pending_proton_setup so the operator
		// re-runs the wizard. A TRANSIENT failure (network blip, Proton
		// 5xx/429 on a data fetch) leaves the account active and is logged
		// at WARN — a later boot or a wizard re-run will re-unlock it.
		//
		// Governing: SPEC-0002 REQ "Backoff on Failure" — "Permanent
		// errors do not retry indefinitely" applies to credential
		// failures only; transient errors must not permanently halt a
		// healthy account.
		if errors.Is(err, ErrCredentialRejected) {
			l.logger.Error("protonlive: boot re-unlock rejected by Proton; account returned to pending_proton_setup",
				slog.String("account_id", accountID), slog.Any("err", err))
			l.toPending(ctx, accountID, err)
			return
		}
		l.logger.Warn("protonlive: boot re-unlock failed transiently; account left active (will retry on next boot / wizard re-run)",
			slog.String("account_id", accountID), slog.Any("err", err))
		return
	}
	l.reg.Set(accountID, client)
	l.logger.Info("protonlive: account re-unlocked on boot",
		slog.String("account_id", accountID))
}

// sessionUID returns the persisted session UID and whether one is
// available. A nil UIDSource, an OpenSessionUID error, or an empty UID
// all report "not available" (false) — the caller treats every such case
// as the missing-UID gap rather than a credential failure.
func (l *Lifecycle) sessionUID(ctx context.Context, accountID string) (string, bool) {
	if l.uids == nil {
		return "", false
	}
	uid, err := l.uids.OpenSessionUID(ctx, accountID)
	if err != nil || uid == "" {
		return "", false
	}
	return uid, true
}

// toPending transitions the account to pending_proton_setup. An
// already-left-active account (admin suspended/deleted it concurrently)
// surfaces as ErrInvalidTransition, which is benign here — the intent
// (stop treating it as a healthy active account) is already satisfied —
// so it is logged at DEBUG, not ERROR.
func (l *Lifecycle) toPending(ctx context.Context, accountID string, cause error) {
	if l.trans == nil {
		return
	}
	if _, err := l.trans.Transition(ctx, accountID, account.StatePendingProtonSetup); err != nil {
		if errors.Is(err, account.ErrInvalidTransition) {
			l.logger.Debug("protonlive: account already left active; no transition needed",
				slog.String("account_id", accountID), slog.Any("err", err))
			return
		}
		l.logger.Error("protonlive: failed to transition account to pending_proton_setup after re-unlock failure",
			slog.String("account_id", accountID),
			slog.Any("transition_err", err), slog.Any("cause", cause))
	}
}

// OnAccountStateChange drops the account's live client when it leaves
// `active`. Register it via account.Service.OnTransition alongside the
// sync supervisor's own subscription. The population side (active edge)
// is owned by the wizard (commit) and RegisterActiveAccounts (boot), so
// this handler deliberately only acts on the leaving-active edge.
//
// Governing: SPEC-0002 REQ "One Worker Per Active Account" (drop mirrors
// worker stop), ADR-0003 (keyring must not outlive `active`).
func (l *Lifecycle) OnAccountStateChange(ctx context.Context, prev, next account.State, accountID string) {
	if prev == account.StateActive && next != account.StateActive {
		l.reg.Drop(ctx, accountID)
	}
}

// zero best-effort wipes an unsealed secret buffer after use. Go offers
// no hard guarantee against compiler reuse, but explicit zeroing narrows
// the residency window — the same posture account.zeroDataKey takes.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
