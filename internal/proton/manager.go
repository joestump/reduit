// Governing: ADR-0001 (go-proton-api as Proton client).

package proton

import (
	"context"

	gpa "github.com/ProtonMail/go-proton-api"
)

// Manager is Reduit's wrapper around go-proton-api's *Manager. It owns
// the underlying resty client (HTTP transport, host URL, app version,
// logger) and is the factory for proton.Client values.
//
// One Manager per process is the normal pattern (multi-account is
// achieved by minting many Client values from the same Manager). The
// Manager is safe for concurrent use.
type Manager struct {
	up   *gpa.Manager
	opts ClientOptions
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

	return &Manager{
		up:   gpa.New(upOpts...),
		opts: resolved,
	}
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
// a Client carrying the new session, the AuthInfo result that drove
// the SRP exchange (callers may inspect TwoFA to decide whether to
// continue with AuthTOTP / AuthFIDO2), plus a non-nil error on failure.
//
// On success, OnRefreshTokenChange (if configured) is invoked once
// with the initial refresh token so the account service can persist
// it before the first /auth/v4/refresh round-trip.
func (m *Manager) NewClientWithLogin(ctx context.Context, username, password string) (Client, *AuthInfo, error) {
	// We need AuthInfo separately so callers can branch on the
	// returned 2FA configuration. The SRP exchange below uses the
	// same /auth/v4/info call internally, so this is a single extra
	// round-trip — acceptable for the login path.
	info, err := m.up.AuthInfo(ctx, AuthInfoReq{Username: username})
	if err != nil {
		return nil, nil, err
	}

	up, auth, err := m.up.NewClientWithLogin(ctx, username, []byte(password))
	if err != nil {
		return nil, &info, err
	}

	c := &clientImpl{mgr: m}
	c.adoptUpstream(up)

	if cb := m.opts.OnRefreshTokenChange; cb != nil {
		// Best-effort initial persistence; surface errors via the
		// configured logger but do not fail the login. The caller
		// can re-issue if needed.
		if cbErr := cb(ctx, auth.RefreshToken); cbErr != nil {
			m.opts.Logger.Error(
				"failed to persist initial proton refresh token",
				"err", cbErr,
			)
		}
	}

	return c, &info, nil
}

// Close releases the underlying *gpa.Manager's idle HTTP connections.
// It is safe to call multiple times.
func (m *Manager) Close() {
	if m.up != nil {
		m.up.Close()
	}
}
