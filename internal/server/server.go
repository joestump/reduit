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

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/auth"
	authoidc "github.com/joestump/reduit/internal/auth/oidc"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/store"
	"github.com/joestump/reduit/internal/users"
)

// ProtonLoginer is the narrow surface the wizard handlers need from
// the Proton manager: run an SRP login and hand back a session-bearing
// Client plus the post-Auth bundle (UID, refresh token, 2FA state).
// *proton.Manager satisfies it; tests use a stub that doesn't need a
// live Proton API.
type ProtonLoginer interface {
	NewClientWithLogin(ctx context.Context, username, password string) (proton.Client, *proton.Auth, error)
}

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
	// AccountService backs the dashboard's per-user account list +
	// the wizard's create path (#24/#25). Required when the dashboard
	// routes are mounted; nil in test fixtures that don't exercise
	// /accounts.
	AccountService account.Service
	// ProtonManager mints proton.Client values for the add-account
	// wizard. The wizard handlers refuse to run without it; tests
	// that don't exercise /accounts/setup leave it nil. Held as a
	// narrow interface so wizard tests can inject a stub without
	// driving go-proton-api's full SRP exchange.
	//
	// Governing: ADR-0001, SPEC-0005 REQ "Add-Proton-Account Wizard".
	ProtonManager ProtonLoginer
	// WizardSessions is the in-memory store for partially-completed
	// wizard runs. Required when ProtonManager is wired; constructed
	// alongside in cli/serve. Tests get an isolated store per server.
	WizardSessions *WizardSessionStore
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
	// tmpl is the per-page template set shared by every HTML-rendering
	// handler. Nil when templates fail to load -- handlers degrade to
	// 500 rather than panic.
	tmpl *templateSet
}

// New constructs a *Server bound to addr. Routes are mounted via the
// returned Server's mux. TLS is wired through deps.GetCertificate;
// passing a nil GetCertificate puts the server in plaintext mode --
// Start uses ListenAndServe (HTTP) instead of ListenAndServeTLS. Use
// only when reduit sits behind a TLS-terminating reverse proxy.
func New(addr string, deps Deps) *Server {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	s, handler := newWithHandler(deps)
	s.addr = addr

	s.srv = &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(deps.Logger.Handler(), slog.LevelError),
	}
	if deps.GetCertificate != nil {
		s.srv.TLSConfig = &tls.Config{
			GetCertificate: deps.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		}
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
	if tmpl, err := loadTemplates(); err != nil {
		// A template-parse failure at boot is fatal-class -- the
		// dashboard can't render -- but we don't want to panic the
		// whole server when /healthz still works. Log loud, leave
		// s.tmpl nil; the dashboard handler returns 500.
		deps.Logger.Error("server: load templates: " + err.Error())
	} else {
		s.tmpl = tmpl
	}
	s.routes(mux)

	var handler http.Handler = mux
	if deps.SessionManager != nil {
		handler = auth.RequireSession(auth.SessionGate{
			Manager:   deps.SessionManager,
			LoginPath: "/auth/login",
			// OnDestroy fires on every gate-initiated session
			// invalidation (malformed-shape, AccountActive false).
			// We use it to tear down any in-flight wizard so partial
			// credentials don't outlive the session per SPEC-0005.
			OnDestroy: s.dropInFlightWizard,
		}, handler)
		handler = deps.SessionManager.LoadAndSave(handler)
	}
	return s, handler
}

// Start begins serving. It returns when the listener exits (typically
// after Shutdown). Start blocks; run it from a dedicated goroutine.
//
// If a TLSConfig is wired (deps.GetCertificate was non-nil at New
// time) the listener uses ListenAndServeTLS; otherwise it falls
// back to ListenAndServe for the reverse-proxy-fronted deployment
// (tls.disabled = true).
func (s *Server) Start() error {
	defer close(s.stopped)
	if s.srv.TLSConfig != nil {
		s.deps.Logger.Info("https server starting",
			slog.String("addr", s.addr))
		err := s.srv.ListenAndServeTLS("", "") // certs come from GetCertificate
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("server: ListenAndServeTLS: %w", err)
	}
	s.deps.Logger.Info("http server starting (plaintext; expect a TLS-terminating reverse proxy in front)",
		slog.String("addr", s.addr))
	err := s.srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("server: ListenAndServe: %w", err)
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

	// Favicon, served from the embedded static FS. Allowlisted (see
	// auth.Allowlist) so a logged-out browser hitting /auth/login can
	// fetch the brand mark without 302-looping through the session
	// gate. Cosmetic asset; long Cache-Control acceptable per the
	// issue's "Suggested fix" guidance.
	//
	// Governing: SPEC-0005 REQ "Authentication Gating"; issue #77.
	mux.HandleFunc("GET /favicon.svg", s.handleFavicon)

	// Root path: 302 to /accounts. Without this, an authenticated
	// browser landing on `/` (e.g., after a login that captured
	// `?return_to=/` from a stale link, or an operator typing the
	// hostname) gets a 404 because no other handler claims `/`.
	// /accounts is the canonical dashboard per SPEC-0005.
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/accounts", http.StatusFound)
	})

	// OIDC login flow per SPEC-0005 REQ "OIDC Login Flow".
	// All three paths are allowlisted (auth.Allowlist) so the
	// RequireSession gate doesn't 302-loop them.
	mux.HandleFunc("GET /auth/login", s.handleAuthLogin)
	mux.HandleFunc("GET /auth/callback", s.handleAuthCallback)
	mux.HandleFunc("POST /auth/logout", s.handleAuthLogout)
	mux.HandleFunc("GET /auth/logout", s.handleAuthLogout)

	// Account dashboard per SPEC-0005 REQ "Account Dashboard".
	// Sits behind RequireSession; authenticated users see their own
	// accounts, admins see every account grouped by owner.
	mux.HandleFunc("GET /accounts", s.handleAccountsDashboard)

	// Add-Proton-account wizard per SPEC-0005 REQ "Add-Proton-Account
	// Wizard". GET renders whichever step the in-flight wizard
	// session is on (or step 1 if none); POSTs advance the flow.
	mux.HandleFunc("GET /accounts/setup", s.handleWizardStart)
	mux.HandleFunc("POST /accounts/setup/auth", s.handleWizardAuth)
	mux.HandleFunc("POST /accounts/setup/2fa", s.handleWizardTOTP)
	mux.HandleFunc("POST /accounts/setup/unlock", s.handleWizardUnlock)
	mux.HandleFunc("POST /accounts/setup/cancel", s.handleWizardCancel)
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

// handleFavicon serves the embedded brand-mark SVG. The bytes are
// loaded into memory at package init so the hot path is a single
// Write. Cache-Control: 24h is plenty for a near-static brand mark
// and lets browsers re-use the cached copy across navigations
// without revalidation.
//
// Method match (`GET /favicon.svg`) is enforced by the mux pattern
// itself in Go 1.22+; no method check needed in the handler.
func (s *Server) handleFavicon(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(faviconBytes)
}
