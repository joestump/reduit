// Package auth is the foundation layer for HTTP request authentication
// in Reduit's control plane and MCP surface. It composes:
//
//   - The OIDC client (internal/auth/oidc) for the login flow.
//   - The SCS-backed session manager (internal/auth/session) for
//     browser-side identity binding.
//   - The MCP token repository (internal/auth/mcptoken) for per-user
//     bearer tokens.
//
// And exposes:
//
//   - Allowlist: the small set of paths that bypass auth entirely.
//   - RequireSession / RequireAdmin: HTTP middleware enforcing
//     SPEC-0005's "Authentication Gating" requirement.
//   - BearerValidator + RequireBearer: the SPEC-0006 MCP-side
//     authenticator that accepts both OIDC ID tokens and per-user
//     MCP tokens.
//
// The login / callback / logout HTTP handlers themselves live in the
// http server (issue #23). This package gives that story everything
// it needs to plug into the existing internal/server scaffolding.
//
// Governing: ADR-0004 (OIDC), SPEC-0005 REQ "Authentication Gating",
// SPEC-0005 REQ "OIDC Login Flow", SPEC-0006 REQ "Bearer Authentication
// Required".
package auth

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/alexedwards/scs/v2"

	"github.com/joestump/reduit/internal/auth/session"
)

// Allowlist is the set of paths that MUST bypass session auth per
// SPEC-0005's "Allowlist bypasses auth" scenario. Paths ending with
// "/*" match by prefix; bare paths match exactly.
//
// Governing: SPEC-0005 REQ "Authentication Gating" (Scenario:
// Allowlist bypasses auth).
var Allowlist = []string{
	"/healthz",
	"/readyz",
	"/metrics",
	"/auth/login",
	"/auth/callback",
	// /auth/logout is allowlisted so it is idempotent for an
	// unauthenticated visit. The handler always destroys the
	// session (a no-op when there isn't one) and redirects to "/"
	// or the IdP's end_session_endpoint. Without allowlisting, a
	// stale browser tab would redirect-loop through /auth/login.
	"/auth/logout",
	"/static/*",
	// /favicon.svg is allowlisted so the brand mark loads on the
	// pre-login /auth/login page without 302-looping through the
	// gate. Cosmetic, unprivileged asset; same treatment as
	// /static/*.
	//
	// Governing: SPEC-0005 REQ "Authentication Gating"; issue #77.
	"/favicon.svg",
}

// IsAllowlisted reports whether path is exempt from auth gating.
// Comparison is a prefix-match for entries ending in "/*", exact-match
// otherwise. Query strings are not consulted.
func IsAllowlisted(path string) bool {
	for _, entry := range Allowlist {
		if strings.HasSuffix(entry, "/*") {
			prefix := strings.TrimSuffix(entry, "/*")
			if strings.HasPrefix(path, prefix+"/") || path == prefix {
				return true
			}
			continue
		}
		if entry == path {
			return true
		}
	}
	return false
}

// SessionGate is the dependencies RequireSession needs to make a
// gating decision. Wiring the manager + login URL through a struct
// (rather than a closure) keeps the middleware composable in tests.
type SessionGate struct {
	// Manager is the SCS session manager. RequireSession does NOT call
	// LoadAndSave for you — wrap your mux with mgr.LoadAndSave once at
	// the top of the chain.
	Manager *scs.SessionManager
	// LoginPath is the redirect target on a missing/invalid session.
	// SPEC-0005 mandates "/auth/login"; pass that as the value.
	LoginPath string
	// AccountActive optionally checks that the session's bound account
	// is still in a usable state. Returns:
	//   - (true, nil) when the account is active and the request may
	//     proceed.
	//   - (false, nil) when the account exists but is suspended,
	//     soft-deleted, or otherwise not authorised — the gate force-
	//     destroys the session and treats the request as
	//     unauthenticated (302 to LoginPath for GETs, 401 otherwise).
	//   - (false, err) when the account state could not be checked
	//     (DB outage). The gate fails closed: 503 Service Unavailable
	//     so an administrator notices, rather than silently allowing
	//     a possibly-suspended user through.
	//
	// May be nil — when nil, the gate accepts any session that
	// resolves to a non-empty Subject (the pre-C6 behaviour). Wiring
	// this in production binds the gate to account lifecycle per
	// SPEC-0005 REQ "Admin Account Management".
	//
	// When wired, a session that has Subject set but AccountID empty
	// (a malformed shape currently unreachable through PutIdentity but
	// possible via future caller wiring bugs) is treated as no session:
	// destroyed + denied + a structured warning is logged.
	//
	// Governing: SPEC-0005 REQ "Authentication Gating" (Scenario
	// "Authenticated request proceeds" — "active session for an
	// account"); SPEC-0005 REQ "Admin Account Management" (suspend /
	// soft-delete must immediately revoke access).
	AccountActive func(ctx context.Context, accountID string) (bool, error)

	// OnDestroy, when non-nil, is invoked synchronously just before
	// every gate-initiated Destroy call (malformed-shape fail-closed,
	// AccountActive returns false). Lets the composition root attach
	// per-session cleanup that the auth package can't see directly --
	// the server uses this to drop in-flight wizard state per
	// SPEC-0005's "WHEN session invalidated THEN partial credentials
	// discarded from memory" requirement, since logout is only one
	// of several invalidation paths.
	//
	// Implementations MUST be cheap and self-contained -- the gate
	// fires this on every gated request that fails the account-state
	// check, so a slow OnDestroy stalls the deny-and-redirect
	// response.
	OnDestroy func(ctx context.Context)
}

// RequireSession returns middleware that allows allowlisted paths
// through, lets authenticated requests pass, and 302-redirects
// unauthenticated requests to /auth/login with a `return_to` query
// parameter pointing to the originally requested URL.
//
// When SessionGate.AccountActive is wired, every authenticated
// request is checked against the bound account's current state — a
// suspended/soft-deleted account is treated as unauthenticated even
// if the cookie is otherwise valid. The session is destroyed in
// passing so the dropped browser cannot replay the cookie at a
// future re-login.
//
// Governing: SPEC-0005 REQ "Authentication Gating" (Scenarios:
// Unauthenticated request redirects to login, Authenticated request
// proceeds, Allowlist bypasses auth); SPEC-0005 REQ "Admin Account
// Management".
func RequireSession(gate SessionGate, next http.Handler) http.Handler {
	loginPath := gate.LoginPath
	if loginPath == "" {
		loginPath = "/auth/login"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IsAllowlisted(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if gate.Manager != nil && session.IsAuthenticated(r.Context(), gate.Manager) {
			// SPEC-0005 "Authenticated request proceeds" anchors on
			// "an active session for an account". Without re-checking
			// account state on each gated request, a session issued
			// before suspend remains usable until idle-timeout — that
			// is the gap C6 closes.
			if gate.AccountActive != nil {
				id := session.GetIdentity(r.Context(), gate.Manager)
				if id.AccountID == "" {
					// Subject is set (we are past IsAuthenticated) but
					// AccountID is empty — a malformed session shape.
					// PutIdentity always sets both, so this is currently
					// unreachable through the foundation API; a future
					// wiring bug in any caller would otherwise let a
					// session bypass the suspend/soft-delete gate.
					// Fail closed: destroy the session, log a structured
					// warning so operators can spot the wiring bug, and
					// deny as if no cookie were present.
					//
					// Governing: SPEC-0005 REQ "Authentication Gating"
					// (auth code MUST fail closed on unexpected shapes);
					// hostile-R2 finding C6-N1.
					slog.Default().LogAttrs(r.Context(), slog.LevelWarn,
						"RequireSession: session has Subject but empty AccountID; failing closed",
						slog.String("subject", id.Subject),
						slog.String("path", r.URL.Path),
					)
					if gate.OnDestroy != nil {
						gate.OnDestroy(r.Context())
					}
					_ = gate.Manager.Destroy(r.Context())
					denySessionMissing(w, r, loginPath)
					return
				}
				ok, err := gate.AccountActive(r.Context(), id.AccountID)
				if err != nil {
					// DB outage: fail closed. A 503 is louder than a
					// silent allow on a possibly-suspended user.
					http.Error(w, "auth-state check unavailable", http.StatusServiceUnavailable)
					return
				}
				if !ok {
					// Account no longer authorised. Destroy the
					// session token (best-effort; failures here MUST
					// NOT block the response) and force re-login.
					if gate.OnDestroy != nil {
						gate.OnDestroy(r.Context())
					}
					_ = gate.Manager.Destroy(r.Context())
					denySessionMissing(w, r, loginPath)
					return
				}
			}
			next.ServeHTTP(w, r)
			return
		}
		denySessionMissing(w, r, loginPath)
	})
}

// denySessionMissing emits the standard "no/invalid session" response:
// 302 to /auth/login?return_to=… for browser GETs, 401 for other
// methods. Extracted from RequireSession so the post-account-check
// "session was valid but account is suspended" branch shares the same
// response shape — a downstream HTMX swapper can treat both
// identically.
func denySessionMissing(w http.ResponseWriter, r *http.Request, loginPath string) {
	if r.Method != http.MethodGet {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	u, err := url.Parse(loginPath)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	q := u.Query()
	q.Set("return_to", r.URL.RequestURI())
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// RequireAdmin returns middleware that 403s any request whose session
// identity is not an admin. It MUST be composed AFTER RequireSession —
// if the session is unauthenticated, RequireAdmin treats that as 403,
// not as a redirect.
//
// Governing: SPEC-0005 REQ "Admin Account Management" (admin-only
// routes), SPEC-0001 REQ "Admin Status".
func RequireAdmin(mgr *scs.SessionManager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := session.GetIdentity(r.Context(), mgr)
		if id.Subject == "" || !id.IsAdmin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
