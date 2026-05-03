// Governing: ADR-0001 (go-proton-api as Proton client).

package proton

import (
	"context"
	"fmt"
	"sync/atomic"

	gpa "github.com/ProtonMail/go-proton-api"
)

// Manager is Reduit's wrapper around go-proton-api's *Manager. It owns
// the underlying resty client (HTTP transport, host URL, app version,
// logger) and is the factory for proton.Client values.
//
// One Manager per process is the normal pattern (multi-account is
// achieved by minting many Client values from the same Manager). The
// Manager is safe for concurrent use.
//
// The refresh-token persistence callback is stored as an atomic.Pointer
// so the composition root can install it after construction (the
// account service is sometimes initialised lazily) and every adopted
// client picks it up on the next rotation. Resolving the callback at
// fire time — instead of capturing it once at adopt time — closes the
// silent-no-op failure mode flagged in the hostile review of PR #37.
type Manager struct {
	up      *gpa.Manager
	opts    ClientOptions
	refrCBP atomic.Pointer[RefreshTokenCallback]
}

// refreshTokenCallback returns the currently registered persistence
// callback, or nil if none was wired. Safe to call from any goroutine.
func (m *Manager) refreshTokenCallback() RefreshTokenCallback {
	p := m.refrCBP.Load()
	if p == nil {
		return nil
	}
	return *p
}

// SetRefreshTokenCallback installs (or replaces) the persistence
// callback. It is safe to call after NewManager and after Clients have
// been minted: every refresh handler resolves the callback at fire
// time, so adopted clients are never deaf to a callback registered
// later in the boot sequence.
//
// Passing nil clears the callback (rotations will be silently dropped
// — which is what tests want, but production callers should treat it
// as a misconfiguration).
func (m *Manager) SetRefreshTokenCallback(cb RefreshTokenCallback) {
	if cb == nil {
		m.refrCBP.Store(nil)
		return
	}
	m.refrCBP.Store(&cb)
}

// NewManager constructs a Manager from a chain of Option values. The
// returned Manager is ready to mint Client instances. The caller is
// responsible for calling Close when the process exits to release
// idle HTTP connections.
//
// A nil/empty option list is valid: the Manager will use upstream
// defaults (Proton production host URL, no logger, default transport).
// Tests typically pass WithHostURL + WithTransport to retarget the
// httptest.Server.
func NewManager(opts ...Option) *Manager {
	resolved := resolveOptions(opts)

	upOpts := []gpa.Option{}
	if resolved.HostURL != "" {
		upOpts = append(upOpts, gpa.WithHostURL(resolved.HostURL))
	}
	if resolved.AppVersion != "" {
		upOpts = append(upOpts, gpa.WithAppVersion(resolved.AppVersion))
	}
	if resolved.Transport != nil {
		upOpts = append(upOpts, gpa.WithTransport(resolved.Transport))
	}
	// Always wire the slog<->resty adapter; if no logger was supplied
	// resolveOptions installed a discard handler so the call below is
	// still safe.
	upOpts = append(upOpts, gpa.WithLogger(newRestyLogger(resolved.Logger)))

	m := &Manager{
		up:   gpa.New(upOpts...),
		opts: resolved,
	}
	if resolved.OnRefreshTokenChange != nil {
		m.SetRefreshTokenCallback(resolved.OnRefreshTokenChange)
	}
	return m
}

// NewClient wraps an already-authenticated session (uid + access +
// refresh) as a Reduit Client. Use this on process startup, when the
// account record on disk already has tokens.
func (m *Manager) NewClient(_ context.Context, uid, accessTok, refreshTok string) Client {
	c := &clientImpl{mgr: m}
	up := m.up.NewClient(uid, accessTok, refreshTok)
	c.adoptUpstream(up)
	return c
}

// AccountSnapshot is the minimal view of an account record that the
// proton package needs in order to hydrate a Client. The real account
// service lives in internal/account (issue #10) and will satisfy this
// interface — but internal/proton intentionally does not import any
// account package so the two foundation stories can land independently.
//
// Implementations MUST return the decrypted UID/access/refresh tokens.
// Persisting rotated refresh tokens is handled separately via
// WithRefreshTokenCallback (the composition root wires that callback
// into the account service when both packages are available).
//
// Performance contract: Manager.WithAccount calls UID(), AccessToken(),
// and RefreshToken() exactly once per invocation, but it MAY be invoked
// frequently (sync workers, the SMTP outbox, and MCP tools each call
// it on demand). Implementations that decrypt-on-demand SHOULD cache
// the decrypted values inside the snapshot — three KDF derivations per
// WithAccount call adds up under load.
//
// Governing: ADR-0001 (go-proton-api).
type AccountSnapshot interface {
	// UID returns the Proton session UID for this account.
	UID() string
	// AccessToken returns the current Proton access token.
	AccessToken() string
	// RefreshToken returns the current Proton refresh token used to
	// rotate the access token after a 401.
	RefreshToken() string
}

// WithAccount hydrates a Client for the given account snapshot. It is
// the canonical entry point for sync workers, the SMTP outbox, and MCP
// tools: each one resolves an AccountSnapshot from the account service
// and hands it to WithAccount to obtain a session-bearing Client.
//
// WithAccount is equivalent to NewClient(ctx, snap.UID(),
// snap.AccessToken(), snap.RefreshToken()) but routes through a single
// named entry point so future hydration changes (e.g., on-demand
// re-decryption, account-scoped logger attributes) only land here.
//
// Returns ErrNotAuthenticated if the snapshot is missing the UID or
// either token; the error is wrapped so callers can use errors.Is.
func (m *Manager) WithAccount(ctx context.Context, snap AccountSnapshot) (Client, error) {
	if snap == nil {
		return nil, ErrNotAuthenticated
	}
	uid, acc, ref := snap.UID(), snap.AccessToken(), snap.RefreshToken()
	if uid == "" || acc == "" || ref == "" {
		return nil, ErrNotAuthenticated
	}
	return m.NewClient(ctx, uid, acc, ref), nil
}

// NewClientWithLogin runs the SRP login flow against Proton and returns
// a Client carrying the new session, the post-Auth bundle (UID, access
// token, refresh token, the persistent Proton user ID, and the 2FA
// configuration so callers can branch on TwoFA.Enabled), plus a non-
// nil error on failure.
//
// On success, the registered RefreshTokenCallback is invoked once with
// the initial refresh token so the account service can persist it
// before the first /auth/v4/refresh round-trip. If that initial
// persistence fails the login is unwound (upstream session closed,
// non-nil error returned) so the caller cannot mistakenly believe a
// session exists for which Reduit has no on-disk record.
//
// Callers that have NOT registered a Manager-level callback (the
// wizard does not, because the callback is shape-locked to (ctx,
// token) and cannot carry the account ID a per-account persist needs)
// are expected to persist auth.RefreshToken themselves before treating
// the login as durable.
//
// Governing: hostile-review Concern 4 of PR #37.
func (m *Manager) NewClientWithLogin(ctx context.Context, username, password string) (Client, *Auth, error) {
	up, auth, err := m.up.NewClientWithLogin(ctx, username, []byte(password))
	if err != nil {
		return nil, nil, err
	}

	c := &clientImpl{mgr: m}
	// Seed latestRefresh with the initial token so a caller that
	// reads LatestRefreshToken() before any rotation gets the value
	// returned in `auth`, not the empty string.
	initial := auth.RefreshToken
	c.latestRefresh.Store(&initial)
	c.adoptUpstream(up)

	if cbErr := m.fireInitialRefreshCallback(ctx, auth.RefreshToken); cbErr != nil {
		// Tear down so we don't leak a session the caller will
		// believe is alive. Logout returns the AuthDelete error,
		// which we swallow because we already have the more
		// actionable cbErr to report.
		_ = c.Logout(context.Background())
		return nil, nil, cbErr
	}

	return c, &auth, nil
}

// fireInitialRefreshCallback invokes the persistence callback exactly
// once with the freshly minted refresh token. Returns a wrapped error
// (so callers can errors.Is the underlying cause) when the callback
// fails, or nil when no callback is configured.
//
// Centralising this here lets NewClientWithLogin and any future
// Manager-level login path share the same error semantics.
func (m *Manager) fireInitialRefreshCallback(ctx context.Context, refreshToken string) error {
	cb := m.refreshTokenCallback()
	if cb == nil {
		return nil
	}
	if err := cb(ctx, refreshToken); err != nil {
		return fmt.Errorf("proton: persist initial refresh token: %w", err)
	}
	return nil
}

// Close releases the underlying *gpa.Manager's idle HTTP connections.
// It is safe to call multiple times.
func (m *Manager) Close() {
	if m.up != nil {
		m.up.Close()
	}
}
