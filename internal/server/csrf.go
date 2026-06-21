// Anti-CSRF validation for state-changing POST routes.
//
// Issue #11 minted a per-session synchronizer CSRF token
// (session.CSRFToken / session.ValidCSRF) and wired it on exactly one
// route: POST /auth/logout. SPEC-0005's "Content security and CSRF"
// design section requires ALL state-changing requests to carry an
// anti-CSRF token; before this file the destructive POSTs (account
// delete/suspend/reactivate, IMAP-password rotation, the admin
// suspend/unsuspend/delete + notification-ack, and the five wizard
// POSTs) relied solely on the SameSite=Lax cookie attribute. SameSite
// is defence-in-depth, not a complete control: it does not cover
// same-site sub-origin attackers, older browsers that ignore the
// attribute, or the method-override / form-post shapes that some
// gadgets reach. issue #26 closes that gap.
//
// csrfProtect is the shared middleware applied (in server.routes) to
// every state-changing POST handler. It validates the per-session
// token taken from EITHER the form field (csrfFieldName, for the
// no-JS <form> submits) OR the X-CSRF-Token request header (for HTMX
// requests, which carry the token via the hx-headers attribute on
// <body> in base.html). Missing or non-matching token => 403, before
// the wrapped handler runs and before any state change. Fail-closed:
// a logged-out, token-less, or rand-failure session never validates.
//
// MIDDLEWARE ORDERING. csrfProtect MUST run after the SCS session has
// been loaded (so session.ValidCSRF can read the stored token off the
// request context) and before the wrapped handler mutates state. In
// the composed chain (see server.newWithHandler) SCS LoadAndSave wraps
// the whole mux, so by the time any muxed handler — and therefore this
// per-route wrapper — runs, the session is already loaded. For the
// admin routes, csrfProtect is composed INSIDE RequireAdmin (admin
// gate first, then CSRF) so a non-admin still gets the 403-forbidden
// admin response shape rather than a CSRF 403; either way the request
// is rejected before the handler.
//
// Governing: SPEC-0005 design "Content security and CSRF"; ADR-0005
// (HTMX delivery); issue #26.

package server

import (
	"net/http"

	"github.com/joestump/reduit/internal/auth/session"
)

// csrfHeaderName is the request header HTMX requests carry the
// per-session CSRF token in. base.html sets it on every HTMX request
// via an hx-headers attribute on <body>; the middleware accepts it as
// an alternative to the csrfFieldName form field so HTMX endpoints
// (which post no form body for the button-triggered actions) are
// covered without a hidden input.
//
// Governing: SPEC-0005 design "Content security and CSRF"; issue #26.
const csrfHeaderName = "X-CSRF-Token"

// csrfTokenFromRequest extracts the submitted CSRF token, preferring
// the X-CSRF-Token header (HTMX path) and falling back to the
// csrfFieldName form field (no-JS <form> path). Returns "" when
// neither is present, which never validates (fail closed).
//
// The form-field read goes through r.PostFormValue, which parses the
// body on first call; a parse failure leaves the value empty, again
// failing closed. We read the header first so a body-parse error (e.g.
// an over-long or malformed body) cannot mask a valid header token.
func csrfTokenFromRequest(r *http.Request) string {
	if tok := r.Header.Get(csrfHeaderName); tok != "" {
		return tok
	}
	return r.PostFormValue(csrfFieldName)
}

// csrfProtect wraps an http.Handler with synchronizer-token CSRF
// validation. It rejects (403) any request whose submitted token does
// not match the session's stored token, before next runs. The session
// manager is read from the server so a nil manager (narrow template
// tests that don't wire sessions) fails closed too — without a manager
// there is no stored token to match, so every request is rejected.
//
// Reuses session.ValidCSRF (the constant-time comparison minted in
// issue #11); it does NOT mint a token — minting happens lazily in
// session.CSRFToken on the render path (renderPage / the meta tag), so
// a GET that renders a form is what establishes the token a later POST
// validates against.
//
// Governing: SPEC-0005 design "Content security and CSRF"; issue #26.
func (s *Server) csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.deps.SessionManager == nil {
			http.Error(w, "session subsystem not configured", http.StatusInternalServerError)
			return
		}
		if !session.ValidCSRF(r.Context(), s.deps.SessionManager, csrfTokenFromRequest(r)) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrfProtectFunc is the http.HandlerFunc-friendly form of csrfProtect
// so server.routes can wrap the existing handler methods without an
// explicit http.HandlerFunc conversion at every call site.
//
// Governing: SPEC-0005 design "Content security and CSRF"; issue #26.
func (s *Server) csrfProtectFunc(h http.HandlerFunc) http.Handler {
	return s.csrfProtect(h)
}
