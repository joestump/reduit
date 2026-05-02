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
	"/static/*",
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
}

// RequireSession returns middleware that allows allowlisted paths
// through, lets authenticated requests pass, and 302-redirects
// unauthenticated requests to /auth/login with a `return_to` query
// parameter pointing to the originally requested URL.
//
// Governing: SPEC-0005 REQ "Authentication Gating" (Scenarios:
// Unauthenticated request redirects to login, Authenticated request
// proceeds, Allowlist bypasses auth).
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
			next.ServeHTTP(w, r)
			return
		}
		// Browser GETs get a 302 to /auth/login with return_to. Other
		// methods get a 401 — POSTs from an expired session shouldn't
		// silently round-trip through the IdP and lose form state.
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
	})
}

// RequireAdmin returns middleware that 403s any request whose session
// identity is not an admin. It MUST be composed AFTER RequireSession —
// if the session is unauthenticated, RequireAdmin treats that as 403,
// not as a redirect.
//
// Governing: SPEC-0005 REQ "Admin Account Management" (admin-only
// routes), SPEC-0001 REQ "Admin Flag".
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
