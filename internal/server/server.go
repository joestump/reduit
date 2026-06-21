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
	"net"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/auth"
	authoidc "github.com/joestump/reduit/internal/auth/oidc"
	"github.com/joestump/reduit/internal/notify"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/pubsub"
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

// LiveClientRegistrar is the narrow surface the wizard needs from the
// process-wide live-client registry (internal/protonlive.Registry): hand
// off the authenticated+unlocked client for an account. Declared here as
// a one-method interface so the server package does not import
// internal/protonlive and wizard tests can assert registration with a
// stub.
//
// Governing: issue #28; SPEC-0002 REQ "One Worker Per Active Account".
type LiveClientRegistrar interface {
	// Set installs (or replaces) the live unlocked client for accountID.
	Set(accountID string, client proton.Client)
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
	// LiveClients receives the authenticated+unlocked proton.Client the
	// wizard produces at commit time, so the IMAP backend / MCP resolver
	// / SMTP outbox can resolve a live unlocked client for the account
	// (without which FETCH BODY[] and MCP get_message fail with
	// proton.ErrNotUnlocked in the daemon). The wizard already runs
	// Unlock to validate the passphrase; this hands the resulting client
	// to the process-wide registry instead of discarding it.
	//
	// Held as a narrow interface (just Set) so wizard tests can assert
	// registration without importing internal/protonlive. nil means the
	// composition root did not wire a registry (e.g. NewForTest fixtures
	// not exercising live-client retention); the wizard then skips
	// registration and logs at WARN -- body decryption stays unavailable
	// until a registry is present.
	//
	// Governing: ADR-0003 (the retained keyring is the in-memory form of
	// the at-rest envelope material), SPEC-0002 REQ "One Worker Per
	// Active Account" (the live client's lifecycle mirrors the worker's);
	// issue #28.
	LiveClients LiveClientRegistrar
	// AdminSubjects is the OIDC_ADMIN_SUBS allowlist. The callback's
	// session-bind path checks Principal.Subject against this list at
	// bind time per SPEC-0005 REQ "Session admin tag is computed at
	// bind time"; nil means "no admins."
	AdminSubjects []string
	// InsecureCookies disables the Secure cookie flag, ONLY for tests
	// that drive the server over plain HTTP (httptest.NewServer).
	// Production callers MUST leave this false.
	InsecureCookies bool
	// MCPHandler is the embedded MCP server's HTTP handler, mounted
	// at `/mcp` on this same admin listener. Per ADR-0008 there is
	// no separate process and no separate port -- one binary, one
	// fault domain. Nil means MCP is not wired (e.g. NewForTest
	// fixtures that don't exercise the MCP surface); the route is
	// then unbound and 404s.
	//
	// IMPORTANT: this handler MUST embed its own bearer auth (per
	// SPEC-0006). The session gate that wraps the rest of the admin
	// surface is bypassed for `/mcp` -- bearer-auth replaces it.
	//
	// Governing: ADR-0008, SPEC-0006.
	MCPHandler http.Handler
	// IMAPSessions is the live IMAP session registry. When non-nil,
	// action handlers call DropForAccount after credential rotation or
	// account suspension so clients are kicked within 1s.
	// Governing: SPEC-0005 REQ "Per-User IMAP/SMTP Credentials",
	// REQ "Admin Account Management".
	IMAPSessions interface {
		DropForAccount(accountID, reason string) int
	}
	// SMTPSessions is the live SMTP session registry. Mirrors IMAPSessions:
	// action handlers call DropForAccount after credential rotation or
	// account suspension to satisfy SPEC-0005 REQ "Per-User IMAP/SMTP
	// Credentials" (both IMAP and SMTP sessions dropped within 1s).
	// Governing: SPEC-0005 REQ "Per-User IMAP/SMTP Credentials",
	// REQ "Admin Account Management".
	SMTPSessions interface {
		DropForAccount(accountID, reason string) int
	}
	// AutoCreate mirrors config.OIDC.AutoCreate. When false, a
	// validated OIDC subject that has no existing users row is denied
	// (403 contact-admin) instead of being auto-provisioned, UNLESS the
	// subject is an admin (admins are always admitted so a fresh
	// deployment's operator can bootstrap). Per ADR-0010 the flag
	// governs USER admittance, not account creation.
	//
	// Governing: ADR-0004 (OIDC_AUTO_CREATE), ADR-0010 (users/accounts
	// split), SPEC-0005 REQ "OIDC Login Flow" / "First-time login
	// establishes user identity only".
	AutoCreate bool
	// TrustedProxies is the operator-supplied list of trusted reverse-
	// proxy addresses (bare IPs or CIDR ranges). The auth-callback
	// audit log derives the real client IP from X-Forwarded-For /
	// X-Real-IP only when the immediate peer matches one of these.
	// Empty (the default) trusts no proxy and logs r.RemoteAddr.
	//
	// Governing: ADR-0011 (reverse-proxy fronting), ADR-0009.
	TrustedProxies []string
	// StatusBus is the in-process pubsub bus carrying per-account
	// status updates (lifecycle state changes today; sync-progress and
	// error events when the sync worker grows them). The SSE handler
	// at GET /sse/accounts/{id}/status subscribes to
	// pubsub.StatusKey(accountID) and streams each Update to the
	// browser. Nil disables the live stream: the SSE handler then
	// emits only heartbeats (the connection stays open and proxy-
	// tolerant, it just never carries a state event) so the dashboard
	// degrades to its server-rendered badge without erroring.
	//
	// Governing: SPEC-0005 REQ "Sync Status via SSE", ADR-0005
	// (HTMX + SSE).
	StatusBus *pubsub.Bus

	// Notifications is the admin-notification surface (internal/notify).
	// The admin accounts page renders unacknowledged notifications (sync
	// worker crashes, permanent-error auto-reverts) as a dismissable
	// banner list, and the acknowledge POST route stamps a row dismissed.
	// nil disables the surface: the page renders without the banner and
	// the acknowledge route 500s ("not configured"). Held as a narrow
	// interface (the read + acknowledge verbs) so admin handler tests can
	// stub it without a database; notify.Service satisfies it.
	//
	// Governing: SPEC-0002 REQ "Panic Isolation" (a worker crash must
	// surface to an operator), SPEC-0002 REQ "Backoff on Failure"
	// (permanent-error auto-revert emits an admin notification).
	Notifications AdminNotifier
}

// AdminNotifier is the read + acknowledge slice of notify.Service the
// admin UI consumes. Declared here as an interface (rather than taking a
// concrete *notify.Service) so admin handler tests can inject a stub.
// notify.Service satisfies it.
//
// Governing: SPEC-0002 REQ "Panic Isolation", REQ "Backoff on Failure".
type AdminNotifier interface {
	ListUnacknowledged(ctx context.Context, limit int) ([]*notify.Notification, error)
	CountUnacknowledged(ctx context.Context) (int, error)
	Acknowledge(ctx context.Context, id string) error
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
	// trustedProxies is the parsed form of deps.TrustedProxies, used by
	// the auth-callback audit log's client-IP derivation. Parsed once
	// at construction so the request path is a cheap range check.
	trustedProxies []*net.IPNet
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
// securityHeaders wraps the OUTERMOST so the baseline browser-hardening
// headers ride on every response -- including allowlisted routes,
// gate-issued 302s, and SCS-managed responses. LoadAndSave wraps
// inside it so RequireSession can read the session via scs.GetString
// from the request context.
//
// Governing: SPEC-0005 REQ "Authentication Gating", SPEC-0005 design
// "Content security and CSRF".
func newWithHandler(deps Deps) (*Server, http.Handler) {
	mux := http.NewServeMux()
	s := &Server{
		deps:    deps,
		stopped: make(chan struct{}),
	}
	// Parse the trusted-proxy list once. Invalid entries are logged
	// loudly so an operator typo doesn't silently disable XFF handling.
	nets, invalid := parseTrustedProxies(deps.TrustedProxies)
	s.trustedProxies = nets
	if len(invalid) > 0 {
		deps.Logger.Warn("server: ignoring unparseable trusted_proxies entries",
			slog.Any("invalid", invalid))
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
	// Security headers wrap everything so they ride on every response,
	// including allowlisted routes and gate-issued 302s.
	handler = securityHeaders(handler)
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

	// Pre-built frontend assets (Tailwind+DaisyUI CSS, HTMX core + SSE
	// extension, Inter variable font), embedded in the binary and
	// served from the same origin instead of a runtime CDN. The
	// /static/* prefix is already allowlisted (auth.Allowlist) so the
	// login page's stylesheet/JS load without the session gate.
	// Immutable, version-pinned bytes -> a long, immutable Cache-Control
	// (filenames carry the version, e.g. htmx-2.0.4.min.js, so cache
	// busting is by URL).
	//
	// Governing: ADR-0005 (pre-built committed assets, no runtime CDN);
	// SPEC-0005 REQ "Authentication Gating"; issue #20.
	mux.Handle("GET /static/vendor/", http.StripPrefix("/static/vendor/", s.staticVendorHandler()))

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
	//
	// Logout is POST-only: SPEC-0005 REQ "Logout clears local session"
	// specifies `POST /auth/logout`, and a GET logout is a CSRF vector
	// under SameSite=Lax (a cross-site top-level navigation to
	// /auth/logout would log the user out). The POST is protected by a
	// per-session CSRF token validated in the handler. Registering only
	// the POST pattern makes the mux return 405 for a GET automatically
	// (Go 1.22+ method-aware routing).
	//
	// Governing: SPEC-0005 REQ "OIDC Login Flow" (Scenario "Logout
	// clears local session"), SPEC-0005 design "Content security and
	// CSRF"; issue #11.
	mux.HandleFunc("GET /auth/login", s.handleAuthLogin)
	mux.HandleFunc("GET /auth/callback", s.handleAuthCallback)
	mux.HandleFunc("POST /auth/logout", s.handleAuthLogout)

	// Account dashboard per SPEC-0005 REQ "Account Dashboard".
	// Sits behind RequireSession; authenticated users see their own
	// accounts, admins see every account grouped by owner.
	mux.HandleFunc("GET /accounts", s.handleAccountsDashboard)

	// Add-Proton-account wizard per SPEC-0005 REQ "Add-Proton-Account
	// Wizard". GET renders whichever step the in-flight wizard
	// session is on (or step 1 if none); POSTs advance the flow.
	//
	// Every wizard POST is CSRF-protected (csrfProtect): the multi-step
	// HTMX flow threads the per-session token through the hx-headers
	// X-CSRF-Token on <body> AND each step form carries the hidden
	// csrf_token field, so both the HTMX and no-JS submit paths validate.
	// Fail-closed: a missing/invalid token 403s before any Proton-side
	// state change.
	//
	// Governing: SPEC-0005 design "Content security and CSRF"; issue #26.
	mux.HandleFunc("GET /accounts/setup", s.handleWizardStart)
	mux.Handle("POST /accounts/setup/auth", s.csrfProtectFunc(s.handleWizardAuth))
	mux.Handle("POST /accounts/setup/2fa", s.csrfProtectFunc(s.handleWizardTOTP))
	mux.Handle("POST /accounts/setup/unlock", s.csrfProtectFunc(s.handleWizardUnlock))
	mux.Handle("POST /accounts/setup/complete", s.csrfProtectFunc(s.handleWizardComplete))
	mux.Handle("POST /accounts/setup/cancel", s.csrfProtectFunc(s.handleWizardCancel))

	// Per-account actions on the dashboard cards. Each handler
	// verifies session-bound ownership (or admin) before any state
	// change. See dashboard_actions.go. All are CSRF-protected
	// (csrfProtect) — the no-JS <form> submits carry the hidden
	// csrf_token field; the HTMX rotate button carries the X-CSRF-Token
	// header via base.html's hx-headers. Fail-closed: 403 on a
	// missing/invalid token before the ownership check or state change.
	//
	// Governing: SPEC-0005 REQ "Account Dashboard" (Scenario "User
	// manages account state"), SPEC-0005 design "Content security and
	// CSRF"; issues #102, #103, #26.
	mux.Handle("POST /accounts/{id}/delete", s.csrfProtectFunc(s.handleAccountDelete))
	mux.Handle("POST /accounts/{id}/suspend", s.csrfProtectFunc(s.handleAccountSuspend))
	mux.Handle("POST /accounts/{id}/reactivate", s.csrfProtectFunc(s.handleAccountReactivate))
	mux.Handle("POST /accounts/{id}/imap-password/rotate", s.csrfProtectFunc(s.handleAccountIMAPRotate))

	// Live sync-status stream per SPEC-0005 REQ "Sync Status via SSE".
	// Server-Sent Events keyed on the account; the dashboard subscribes
	// per status card via the HTMX SSE extension. Gated by the same
	// ownership check as the action handlers above (requireOwnedAccount):
	// a non-owner, non-admin session gets 403. See sse_handlers.go.
	//
	// Governing: SPEC-0005 REQ "Sync Status via SSE", ADR-0005.
	mux.HandleFunc("GET /sse/accounts/{id}/status", s.handleAccountStatusSSE)

	// Embedded MCP server (per ADR-0008). The handler enforces its
	// own bearer auth + per-account concurrency cap; the SCS session
	// gate skips this path via auth.Allowlist. The MCP transport is
	// HTTP+SSE Streamable HTTP per the modelcontextprotocol/go-sdk;
	// all methods (POST for tool calls, GET for SSE streaming, DELETE
	// for session teardown) land on the same path.
	//
	// Governing: ADR-0008, SPEC-0006.
	if s.deps.MCPHandler != nil {
		mux.Handle("/mcp", s.deps.MCPHandler)

		// Path-prefixed account selector per SPEC-0006 REQ "Selector
		// Precedence": `/accounts/{id}/mcp` carries the account as a
		// path parameter. The MCP handler reads it via r.PathValue("id")
		// (stamped here by the mux) and, when present, ignores the
		// X-Reduit-Account header entirely -- the path wins. This route
		// is the canonical selector for OIDC-bearer clients that can
		// shape a URL but not set a custom header. It shares the exact
		// same handler -- and therefore the same bearer auth and
		// per-account concurrency cap -- as the bare `/mcp` route above.
		//
		// Allowlisted from the SCS session gate (auth.Allowlist) just
		// like `/mcp`; bearer auth replaces the session gate here.
		//
		// Governing: ADR-0008, SPEC-0006 REQ "Selector Precedence".
		mux.Handle("/accounts/{id}/mcp", s.deps.MCPHandler)
	}

	// Per-user credentials view and rotation per SPEC-0005 REQ
	// "Per-User IMAP/SMTP Credentials". GET renders connection details
	// (host, port, username) with a rotate button; POST generates a
	// fresh password and returns a one-time-display HTMX modal.
	// Gated: account.user_id == session.user_id || session.is_admin.
	//
	// The rotate POST is CSRF-protected (csrfProtect): the credentials
	// page's HTMX rotate button carries the X-CSRF-Token header via
	// base.html's hx-headers. Fail-closed 403 on a missing/invalid token.
	//
	// Governing: SPEC-0005 REQ "Per-User IMAP/SMTP Credentials",
	// SPEC-0005 design "Content security and CSRF"; issue #26.
	mux.HandleFunc("GET /accounts/{id}/credentials", s.handleAccountCredentials)
	mux.Handle("POST /accounts/{id}/credentials/rotate", s.csrfProtectFunc(s.handleAccountCredentialsRotate))

	// Admin-only account management routes. All routes below are
	// wrapped by auth.RequireAdmin so a 403 is returned for any
	// non-admin session. See admin_handlers.go.
	//
	// Governing: SPEC-0005 REQ "Admin Account Management".
	adminHandler := func(h http.HandlerFunc) http.Handler {
		if s.deps.SessionManager != nil {
			return auth.RequireAdmin(s.deps.SessionManager, h)
		}
		return h
	}
	// adminPOSTHandler is adminHandler with CSRF validation composed
	// INSIDE the admin gate: RequireAdmin runs first (so a non-admin
	// gets the 403-forbidden admin shape, not a CSRF 403), then
	// csrfProtect rejects a missing/invalid token before the handler.
	// Both layers reject before any state change. The admin templates'
	// no-JS <form> submits carry the hidden csrf_token field.
	//
	// Governing: SPEC-0005 REQ "Admin Account Management", SPEC-0005
	// design "Content security and CSRF"; issue #26.
	adminPOSTHandler := func(h http.HandlerFunc) http.Handler {
		csrfed := s.csrfProtect(h)
		if s.deps.SessionManager != nil {
			return auth.RequireAdmin(s.deps.SessionManager, csrfed)
		}
		return csrfed
	}
	mux.Handle("GET /admin/accounts", adminHandler(s.handleAdminAccounts))
	mux.Handle("POST /admin/accounts/{id}/suspend", adminPOSTHandler(s.handleAdminAccountSuspend))
	mux.Handle("POST /admin/accounts/{id}/unsuspend", adminPOSTHandler(s.handleAdminAccountUnsuspend))
	mux.Handle("POST /admin/accounts/{id}/delete", adminPOSTHandler(s.handleAdminAccountDelete))

	// Admin-notification acknowledge route. Dismisses one notification
	// (worker crash / auto-revert) so it drops off the admin banner.
	// CSRF-protected like the other admin POSTs.
	//
	// Governing: SPEC-0002 REQ "Panic Isolation" (the crash surfaces to
	// the operator; acknowledging is how they clear it from view);
	// SPEC-0005 design "Content security and CSRF"; issue #26.
	mux.Handle("POST /admin/notifications/{id}/ack", adminPOSTHandler(s.handleAdminNotificationAck))
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
