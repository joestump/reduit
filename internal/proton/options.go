// Governing: ADR-0001 (go-proton-api as Proton client).

package proton

import (
	"context"
	"log/slog"
	"net/http"
)

// RefreshTokenCallback is invoked when go-proton-api rotates a session's
// refresh token (typically after a 401 -> /auth/v4/refresh round-trip).
// The callback is expected to persist the new token onto the owning
// account record so the next process restart can resume the session.
//
// Implementations MUST be safe to call from arbitrary goroutines and
// MUST treat ctx cancellation as a soft signal — the rotation has
// already happened upstream by the time we are notified.
type RefreshTokenCallback func(ctx context.Context, newRefreshToken string) error

// ClientOptions is the resolved configuration produced by applying a
// chain of Option values. It is exported only so tests can inspect the
// result of WithX combinators; production callers should construct it
// via NewManager(opts...).
type ClientOptions struct {
	Logger               *slog.Logger
	OnRefreshTokenChange RefreshTokenCallback
	AppVersion           string
	HostURL              string
	Transport            http.RoundTripper
}

// Option configures a Manager. Options are applied in order; later
// options overwrite earlier ones. The pattern matches the upstream
// go-proton-api Option pattern but pins the option set to what Reduit
// actually uses.
type Option func(*ClientOptions)

// WithLogger plugs a *slog.Logger into the underlying resty client via
// the slog<->resty.Logger adapter. A nil logger is treated as a no-op
// (the Manager will still function but will not emit HTTP-level logs).
func WithLogger(l *slog.Logger) Option {
	return func(o *ClientOptions) { o.Logger = l }
}

// WithAppVersion sets the X-Pm-Appversion header sent on every Proton
// API request. Proton requires this header for non-trivial requests;
// a zero value will surface as an upstream error.
func WithAppVersion(v string) Option {
	return func(o *ClientOptions) { o.AppVersion = v }
}

// WithHostURL overrides the Proton API base URL. Default is the
// upstream library's default (https://mail.proton.me/api). Tests use
// this to point the Manager at an httptest.Server.
func WithHostURL(u string) Option {
	return func(o *ClientOptions) { o.HostURL = u }
}

// WithTransport injects a custom http.RoundTripper. Useful for tests
// that want to record requests, and for production deployments that
// need a custom dialer / proxy.
func WithTransport(t http.RoundTripper) Option {
	return func(o *ClientOptions) { o.Transport = t }
}

// WithRefreshTokenCallback registers a function called when the
// upstream client rotates its refresh token. The composition root
// (cmd/reduit) wires this into the account service so token rotations
// land in the persistent account record. internal/proton does not
// import any account package — that wiring is the caller's problem.
func WithRefreshTokenCallback(fn RefreshTokenCallback) Option {
	return func(o *ClientOptions) { o.OnRefreshTokenChange = fn }
}

// resolveOptions applies a chain of options and returns the resolved
// ClientOptions plus a logger guaranteed to be non-nil (callers can
// always call methods on it without a nil check).
func resolveOptions(opts []Option) ClientOptions {
	resolved := ClientOptions{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&resolved)
	}
	if resolved.Logger == nil {
		resolved.Logger = slog.New(slog.NewTextHandler(discardWriter{}, nil))
	}
	return resolved
}

// discardWriter is a tiny io.Writer that drops everything. We use it
// for the fallback "no logger configured" case so resty.Logger calls
// remain safe even when no slog handler is plumbed in.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
