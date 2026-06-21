// Package protonlive holds the process-wide registry of long-lived,
// authenticated AND mailbox-unlocked proton.Client values — one per
// active account.
//
// Motivation: the IMAP FETCH BODY[] path
// (proton.Client.GetMessageRFC822, #13) and the MCP get_message tool
// (#14) decrypt message bodies with the per-address OpenPGP keyring that
// proton.Client.Unlock retains in process. Until this registry existed
// the only place an Unlock ever ran was the add-account wizard
// (internal/server/wizard_handlers.go commitWizard), which discarded the
// returned keyring the moment the wizard session was dropped. Nothing
// held an unlocked client past that point, so every live-daemon body
// fetch hit proton.ErrNotUnlocked.
//
// The registry is the retention seam: the wizard registers the unlocked
// client here on a successful unlock, and the IMAP backend / MCP
// resolver / SMTP outbox all resolve the SAME live client out of it by
// account ID. One unlocked keyring per account, shared by every serving
// goroutine, dropped when the account leaves `active`.
//
// Concurrency: the map is read by IMAP/MCP/outbox request goroutines and
// written by the wizard handler and the sync supervisor's lifecycle
// callbacks. Every access is guarded by mu. The stored proton.Client is
// itself internally synchronised (see internal/proton/client.go's
// upMu/krMu), so callers may use a resolved client concurrently without
// further locking.
//
// Governing: ADR-0003 (master-key envelope encryption at rest — the
// unlocked private keyrings held here are the in-memory, post-decrypt
// form of that material, with the same trust posture as the upstream
// Proton bridge), ADR-0001 (go-proton-api), SPEC-0002 REQ "One Worker
// Per Active Account" (the registry's lifecycle mirrors the worker's:
// populated as an account goes active, dropped as it leaves active).
package protonlive

import (
	"context"
	"log/slog"
	"sync"

	"github.com/joestump/reduit/internal/proton"
)

// Registry is the process-wide account-ID -> live unlocked proton.Client
// map. The zero value is NOT usable; construct via New so the logger and
// map are initialised.
//
// A Registry does not own the clients' upstream sessions in the sense of
// closing them on its own schedule — Drop and Replace call Logout on the
// evicted client so a revoked/rotated session does not leak, but the
// Registry never garbage-collects entries on its own. Lifecycle is
// entirely driven by its callers (the wizard adds; the supervisor's
// state-change callback drops).
type Registry struct {
	logger *slog.Logger

	mu      sync.RWMutex
	clients map[string]proton.Client
}

// New constructs an empty Registry. A nil logger is replaced with the
// default slog logger so call sites never have to nil-check.
func New(logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.Default()
	}
	return &Registry{
		logger:  logger,
		clients: make(map[string]proton.Client),
	}
}

// Set installs (or replaces) the live unlocked client for accountID. If
// an entry already exists for the account it is Logout'd before being
// replaced so the superseded upstream session is revoked rather than
// leaked — this is the re-login / re-unlock case (the operator re-ran the
// wizard, or the supervisor re-unlocked on activation while a stale entry
// lingered).
//
// A nil client is rejected as a no-op with a WARN: registering "no
// client" would be indistinguishable at the resolver from "account not
// known", and silently storing nil would make Get return (nil, nil) for
// an account the caller believed it had just provisioned. Callers that
// genuinely want to forget an account use Drop.
//
// The Logout of the displaced client runs on context.Background(), not a
// caller context: the rotation has already happened (we are replacing the
// entry regardless), and a cancelled caller ctx must not leave the old
// session un-revoked. Logout is best-effort; an AuthDelete failure is
// logged, not surfaced, because the new client is already installed and
// the old session will expire server-side anyway.
func (r *Registry) Set(accountID string, client proton.Client) {
	if client == nil {
		r.logger.Warn("protonlive: refusing to register nil client",
			slog.String("account_id", accountID))
		return
	}
	r.mu.Lock()
	prev, existed := r.clients[accountID]
	r.clients[accountID] = client
	r.mu.Unlock()

	if existed && prev != nil && prev != client {
		// Revoke the superseded session outside the lock so a slow
		// AuthDelete round-trip cannot block a concurrent Get/Set.
		if err := prev.Logout(context.Background()); err != nil {
			r.logger.Warn("protonlive: logout of replaced client failed",
				slog.String("account_id", accountID),
				slog.Any("err", err))
		}
	}
	r.logger.Debug("protonlive: registered live client",
		slog.String("account_id", accountID))
}

// Get returns the live client for accountID. The second return value
// reports whether an entry was present. A present entry is always
// non-nil (Set rejects nil), so callers that only care about presence
// can branch on ok.
//
// Get is the hot path: it takes only the read lock so concurrent IMAP /
// MCP / outbox lookups proceed in parallel. The returned client is safe
// to use after the lock is released — a concurrent Drop will Logout the
// client, but proton.Client.Logout is lock-serialised against in-flight
// calls (internal/proton/client.go upMu), so a request goroutine holding
// this reference observes a clean ErrNotAuthenticated rather than a
// torn read if it races a Drop.
func (r *Registry) Get(accountID string) (proton.Client, bool) {
	r.mu.RLock()
	c, ok := r.clients[accountID]
	r.mu.RUnlock()
	return c, ok
}

// Drop removes accountID's client from the registry and Logout's its
// upstream session so the decrypted keyring material does not outlive the
// account's `active` state. Idempotent: dropping an unknown account is a
// no-op.
//
// Called by the supervisor's account-state-change handler when an
// account leaves `active` (suspended / soft-deleted / kicked back to
// pending_proton_setup on an unrecoverable auth failure), mirroring where
// the sync worker is stopped. Dropping here is what enforces the
// SPEC-0002 invariant that no unlocked keyring survives the account
// leaving active.
//
// Governing: SPEC-0002 REQ "One Worker Per Active Account" (registry
// lifecycle mirrors worker lifecycle); ADR-0003 (decrypted keyrings must
// not outlive the session that authorises them).
func (r *Registry) Drop(ctx context.Context, accountID string) {
	r.mu.Lock()
	c, ok := r.clients[accountID]
	delete(r.clients, accountID)
	r.mu.Unlock()
	if !ok || c == nil {
		return
	}
	if err := c.Logout(ctx); err != nil {
		r.logger.Warn("protonlive: logout on drop failed",
			slog.String("account_id", accountID),
			slog.Any("err", err))
	}
	r.logger.Debug("protonlive: dropped live client",
		slog.String("account_id", accountID))
}

// CloseAll Logout's and removes every registered client. Intended for
// daemon shutdown so the process does not exit with live Proton sessions
// dangling and decrypted keyrings resident. Best-effort: a Logout failure
// on one account is logged and the sweep continues.
func (r *Registry) CloseAll(ctx context.Context) {
	r.mu.Lock()
	snapshot := r.clients
	r.clients = make(map[string]proton.Client)
	r.mu.Unlock()
	for id, c := range snapshot {
		if c == nil {
			continue
		}
		if err := c.Logout(ctx); err != nil {
			r.logger.Warn("protonlive: logout during CloseAll failed",
				slog.String("account_id", id),
				slog.Any("err", err))
		}
	}
}

// Len reports how many accounts currently have a live client. Exposed for
// tests and operational introspection; not part of any hot path.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.clients)
}
