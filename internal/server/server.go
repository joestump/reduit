// Package server hosts Reduit's HTTPS control-plane server. v0.1
// scope is intentionally minimal: /healthz, /readyz, and a
// metrics-listener stub. OIDC, admin UI routes, MCP, and SSE come in
// later milestones.
//
// Governing: SPEC-0005 REQ "Authentication Gating" (allowlist of
// unauthenticated routes — /healthz, /readyz, /metrics).
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"

	"github.com/joestump/reduit/internal/auth"
	authoidc "github.com/joestump/reduit/internal/auth/oidc"
	"github.com/joestump/reduit/internal/store"
	"github.com/joestump/reduit/internal/users"
)

// Deps are the dependencies a Server needs to start. Wired by
// internal/cli/serve at startup.
type Deps struct {
	Store          *store.Store
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	Logger         *slog.Logger
	Version        string // for /healthz response body
	// SessionManager is the SCS-backed session store.
	//
	// Governing: ADR-0004, SPEC-0005 REQ "Authentication Gating".
	SessionManager *scs.SessionManager
	// OIDC is the configured Relying Party. The login/callback handlers
	// call into it.
	OIDC *authoidc.Client
	// PreSessions is the in-memory store for PKCE pre-sessions used by
	// /auth/login and /auth/callback to correlate the redirect with
	// the eventual auth-code exchange.
	PreSessions *authoidc.PreSessionStore
	// UsersService is the users repository the OIDC callback upserts
	// against (per ADR-0010 / SPEC-0001 REQ "User Identity").
	UsersService users.Service
	// AdminSubjects is the OIDC_ADMIN_SUBS allowlist. The callback's
	// session-bind path checks Principal.Subject against this list at
	// bind time per SPEC-0005 REQ "Session admin tag is computed at
	// bind time"; nil means "no admins."
	AdminSubjects []string
	// InsecureCookies disables the Secure cookie flag, ONLY for tests
	// that drive the server over plain HTTP (httptest.NewServer).
	// Production callers MUST leave this false.
	InsecureCookies bool
}

// Server holds an http.Server pre-configured with TLS and the
// allowlist routes from SPEC-0005.
type Server struct {
	addr    string
	srv     *http.Server
	deps    Deps
	stopped chan struct{}
}

// New constructs a *Server bound to addr. Routes are mounted via the
// returned Server's mux. TLS is wired through deps.GetCertificate.
func New(addr string, deps Deps) *Server {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	s, handler := newWithHandler(deps)
	s.addr = addr

	tlsCfg := &tls.Config{
		GetCertificate: deps.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(deps.Logger.Handler(), slog.LevelError),
	}
	return s
}

// NewForTest builds the same routes + middleware chain as New but
// without the http.Server / TLS setup. Tests mount the returned
// handler under their own httptest.Server and exercise the full
// production middleware stack (RequireSession, LoadAndSave, etc.).
//
// Returns the Server (for any future hooks tests need on it) and the
// http.Handler tests should serve.
func NewForTest(deps Deps) (*Server, http.Handler) {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	return newWithHandler(deps)
}

// newWithHandler is the shared construction path: builds the mux,
// mounts routes, and wraps the configured middleware chain. Returns
// the Server (with mux/routes wired but srv unset) and the composed
// handler ready to serve.
//
// The handler chain is:
//
//	ServeMux
//	  ↓
//	auth.RequireSession (302→/auth/login on miss; allowlist passes)
//	  ↓
//	scs.LoadAndSave (loads/saves the cookie-bound session row)
//
// LoadAndSave wraps the OUTERMOST so RequireSession can read the
// session via scs.GetString from the request context.
//
// Governing: SPEC-0005 REQ "Authentication Gating".
func newWithHandler(deps Deps) (*Server, http.Handler) {
	mux := http.NewServeMux()
	s := &Server{
		deps:    deps,
		stopped: make(chan struct{}),
	}
	s.routes(mux)

	var handler http.Handler = mux
	if deps.SessionManager != nil {
		handler = auth.RequireSession(auth.SessionGate{
			Manager:   deps.SessionManager,
			LoginPath: "/auth/login",
		}, handler)
		handler = deps.SessionManager.LoadAndSave(handler)
	}
	return s, handler
}

// Start begins serving. It returns when the listener exits (typically
// after Shutdown). Start blocks; run it from a dedicated goroutine.
func (s *Server) Start() error {
	defer close(s.stopped)
	s.deps.Logger.Info("http server starting",
		slog.String("addr", s.addr))
	err := s.srv.ListenAndServeTLS("", "") // certs come from GetCertificate
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("server: ListenAndServeTLS: %w", err)
}

// Shutdown asks the underlying http.Server to gracefully stop. It
// returns once shutdown completes or ctx fires.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

// Stopped returns a channel closed when Start has returned.
func (s *Server) Stopped() <-chan struct{} { return s.stopped }

func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)

	// OIDC login flow per SPEC-0005 REQ "OIDC Login Flow".
	// All three paths are allowlisted (auth.Allowlist) so the
	// RequireSession gate doesn't 302-loop them.
	mux.HandleFunc("GET /auth/login", s.handleAuthLogin)
	mux.HandleFunc("GET /auth/callback", s.handleAuthCallback)
	mux.HandleFunc("POST /auth/logout", s.handleAuthLogout)
	mux.HandleFunc("GET /auth/logout", s.handleAuthLogout)
}

// handleHealthz returns 200 OK if the process is up. It does not
// touch the database — that's /readyz.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintf(w, "ok %s\n", s.deps.Version)
}

// handleReadyz pings the database. Returns 503 if the DB is
// unreachable so a load balancer can stop sending traffic.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if s.deps.Store == nil {
		http.Error(w, "no store", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.deps.Store.DB.PingContext(ctx); err != nil {
		http.Error(w, "store unreachable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	_, _ = fmt.Fprintln(w, "ready")
}
