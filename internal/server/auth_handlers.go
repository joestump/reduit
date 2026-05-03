// /auth/login, /auth/callback, /auth/logout HTTP handlers.
//
// Per SPEC-0005 REQ "OIDC Login Flow":
//
//   - /auth/login generates a state, nonce, PKCE verifier, and bind
//     token; persists them in the in-memory PreSessionStore; sets a
//     `__Host-Reduit-Bind` cookie; and 302s to the IdP's authorize
//     endpoint with the standard parameters.
//
//   - /auth/callback validates state + nonce, exchanges the code +
//     verifier for tokens, validates the ID token, and hands off to
//     auth.BindFromOIDC which upserts the users row, computes the
//     admin tag from OIDC_ADMIN_SUBS, and binds the session.
//
//   - /auth/logout destroys the SCS session, clears the bind cookie
//     (defensive; should already be cleared by /auth/callback), and
//     redirects to the IdP's end_session_endpoint when one is
//     advertised, otherwise to "/".
//
// The handlers refuse to run when the OIDC client / pre-session store
// / users service / session manager are missing -- those are
// startup-time wiring that MUST be in place; no graceful "OIDC not
// configured" fallback exists at request time.
//
// Governing: ADR-0004 (OIDC), ADR-0010 (multi-Proton-account per
// user), SPEC-0005 REQ "OIDC Login Flow", SPEC-0005 REQ "Session
// admin tag is computed at bind time", SPEC-0005 REQ "First-time
// login establishes user identity only".

package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/joestump/reduit/internal/auth"
	authoidc "github.com/joestump/reduit/internal/auth/oidc"
)

// defaultPostLoginPath is where /auth/callback sends the browser when
// the pre-session has no return_to (or the return_to was rejected as
// open-redirect bait). SPEC-0005 anchors this on the account
// dashboard.
const defaultPostLoginPath = "/accounts"

// oidcExchangeTimeout bounds the IdP token-exchange round-trip. The
// server's WriteTimeout (60s) is the outer bound; this inner deadline
// makes a hung IdP surface as a clear "exchange timeout" log line at
// 15s rather than as a 60s server timeout. Generous for an OAuth2
// token exchange against a healthy IdP (Pocket ID returns sub-second
// in production); tighten if real-world telemetry says otherwise.
const oidcExchangeTimeout = 15 * time.Second

// handleAuthLogin starts the OIDC auth-code-with-PKCE flow.
//
// Validates and stashes a return_to (relative paths only -- absolute
// URLs are rejected to prevent open-redirect via a crafted
// /auth/login?return_to=https://attacker.example/...). Generates the
// state/nonce/PKCE verifier and bind token, stores the PreSession,
// sets the __Host- bind cookie on the response, and 302s to the IdP.
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if !s.authReady(w) {
		return
	}

	pkce, err := authoidc.NewPKCE()
	if err != nil {
		s.deps.Logger.Error("auth/login: pkce: " + err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	state, err := authoidc.RandomState()
	if err != nil {
		s.deps.Logger.Error("auth/login: state: " + err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := authoidc.RandomNonce()
	if err != nil {
		s.deps.Logger.Error("auth/login: nonce: " + err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	bindToken, err := authoidc.NewBindToken()
	if err != nil {
		s.deps.Logger.Error("auth/login: bind token: " + err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	returnTo := sanitizeReturnTo(r.URL.Query().Get("return_to"))

	s.deps.PreSessions.Put(authoidc.PreSession{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: pkce.Verifier,
		ReturnTo:     returnTo,
		BindToken:    bindToken,
	})

	http.SetCookie(w, authoidc.BuildBindCookie(bindToken, s.deps.InsecureCookies))

	authURL := s.deps.OIDC.AuthCodeURL(authoidc.AuthURLOptions{
		State:         state,
		Nonce:         nonce,
		CodeChallenge: pkce.Challenge,
	})
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleAuthCallback validates and consumes a PreSession, exchanges
// the auth code for tokens, and binds the session via
// auth.BindFromOIDC.
//
// Failure modes are deliberately uniform "401 Unauthorized" responses
// so the handler cannot be used as an oracle to distinguish "no
// pre-session" from "bind token mismatch" from "code exchange
// failed". Operator-relevant detail goes to the structured log.
func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	if !s.authReady(w) {
		return
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		s.callbackUnauthorized(w, r, "missing state or code", nil)
		return
	}

	bindToken := authoidc.ReadBindCookie(r)
	pre, err := s.deps.PreSessions.Take(state, bindToken)
	if err != nil {
		s.callbackUnauthorized(w, r, "pre-session take", err)
		return
	}

	// Spent bind cookie -- clear it before any other write so a
	// failure later doesn't leave it sitting in the browser jar.
	http.SetCookie(w, authoidc.ClearBindCookie(s.deps.InsecureCookies))

	exchangeCtx, cancelExchange := context.WithTimeout(r.Context(), oidcExchangeTimeout)
	defer cancelExchange()
	exchange, err := s.deps.OIDC.Exchange(exchangeCtx, code, pre.CodeVerifier, pre.Nonce)
	if err != nil {
		s.callbackUnauthorized(w, r, "code exchange", err)
		return
	}

	id, err := auth.BindFromOIDC(r.Context(), s.deps.SessionManager, s.deps.Store.DB.DB, s.deps.UsersService, auth.OIDCClaims{
		Subject:     exchange.Subject,
		Email:       exchange.Email,
		DisplayName: exchange.Name,
	}, s.deps.AdminSubjects)
	if err != nil {
		// BindFromOIDC writes the session in stages (PutIdentity ->
		// Commit -> BindSessionToUser). A failure after Commit leaves
		// the browser holding a valid SCS cookie pointing at a
		// session row whose Subject is set -- IsAuthenticated would
		// return true on the next request, letting the user past the
		// gate with a half-bound session that no users-scoped
		// revocation can find. Destroy unconditionally so any partial
		// state is cleared. Destroy is idempotent and cheap.
		if destroyErr := s.deps.SessionManager.Destroy(r.Context()); destroyErr != nil {
			s.deps.Logger.Warn("auth/callback: destroy after bind error",
				slog.String("error", destroyErr.Error()))
		}
		s.deps.Logger.Error("auth/callback: bind",
			slog.String("error", err.Error()),
			slog.String("subject", exchange.Subject))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	target := pre.ReturnTo
	if target == "" {
		target = defaultPostLoginPath
	}
	s.deps.Logger.Info("auth/callback: bound",
		slog.String("user_id", id.UserID),
		slog.String("subject", id.Subject),
		slog.Bool("admin", id.IsAdmin),
		slog.String("return_to", target))

	http.Redirect(w, r, target, http.StatusFound)
}

// handleAuthLogout destroys the SCS session, clears any lingering
// bind cookie, and redirects to the IdP's end_session_endpoint when
// one is advertised, otherwise to "/".
//
// Accepts both POST (the SPEC-0005 canonical method) and GET (so a
// plain anchor in the navbar works without HTMX). GET-based logout
// is normally a CSRF risk -- here it is bounded by the SCS session
// cookie itself: an unauthenticated visit to /auth/logout is a
// no-op. The destroy path is idempotent.
//
// If the user has an in-flight wizard, the in-memory wizard session
// is dropped before the SCS session is destroyed -- otherwise the
// live proton.Client + freshly-minted refresh token would linger in
// process memory until the wizard's 30-min idle TTL fired, in
// violation of SPEC-0005's "WHEN ... session invalidated THEN
// partial credentials discarded from memory" requirement.
func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if s.deps.SessionManager == nil {
		http.Error(w, "session subsystem not configured", http.StatusInternalServerError)
		return
	}
	if s.deps.WizardSessions != nil {
		if accountID := s.deps.SessionManager.GetString(r.Context(), wizardSessionKey); accountID != "" {
			if sess, ok := s.deps.WizardSessions.Get(accountID); ok {
				sess.Lock()
				if sess.Client != nil {
					_ = sess.Client.Logout(r.Context())
				}
				sess.Unlock()
			}
			s.deps.WizardSessions.Drop(accountID)
		}
	}
	if err := s.deps.SessionManager.Destroy(r.Context()); err != nil {
		s.deps.Logger.Warn("auth/logout: destroy: " + err.Error())
	}
	// Defensive: clear any stray bind cookie too.
	http.SetCookie(w, authoidc.ClearBindCookie(s.deps.InsecureCookies))

	target := "/"
	if s.deps.OIDC != nil {
		if endSession := s.deps.OIDC.EndSessionEndpoint(); endSession != "" {
			target = endSession
		}
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// authReady gates the OIDC handlers on having every dependency wired
// at startup. Returns true when the handler may proceed; otherwise
// writes a 500 and returns false.
//
// `serve` constructs all of these together, so a missing one means
// either an in-process test forgot to wire them or the operator did
// not configure OIDC. Both cases want a clear log line and an opaque
// 500.
func (s *Server) authReady(w http.ResponseWriter) bool {
	missing := []string{}
	if s.deps.OIDC == nil {
		missing = append(missing, "OIDC")
	}
	if s.deps.PreSessions == nil {
		missing = append(missing, "PreSessions")
	}
	if s.deps.SessionManager == nil {
		missing = append(missing, "SessionManager")
	}
	if s.deps.UsersService == nil {
		missing = append(missing, "UsersService")
	}
	if len(missing) == 0 {
		return true
	}
	s.deps.Logger.Error("auth handler called without required deps",
		slog.String("missing", strings.Join(missing, ",")))
	http.Error(w, "auth subsystem not configured", http.StatusInternalServerError)
	return false
}

// sanitizeReturnTo accepts only same-origin relative paths. Absolute
// URLs (scheme://host or scheme-relative //host) are dropped -- a
// crafted /auth/login?return_to=https://attacker.example/... would
// otherwise let an unrelated site funnel users through Reduit's
// login and land them somewhere off-host.
//
// Backslash variants get the same treatment: Chrome and Firefox
// normalize `\` to `/` when parsing a `Location:` header value, so
// `/\attacker.example/path` and `\\attacker.example/path` both
// land the user at attacker.example even though `url.Parse` reports
// Scheme=Host="" for the raw string. We reject any input whose first
// two bytes (after a leading `/`, if any) include a `\` -- that's the
// shape every known browser-side open-redirect bypass for this case
// takes. See OWASP "Unvalidated Redirects and Forwards".
//
// Returns "" on rejection; the caller falls back to defaultPostLoginPath.
func sanitizeReturnTo(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Strip any backslashes from inspection -- a single \ in the first
	// few bytes is enough to flip browser parsing to authority mode.
	// Cheap to just reject anything containing \ in the first 3 bytes
	// (covers `\\x`, `/\x`, `\foo`).
	for i := 0; i < len(s) && i < 3; i++ {
		if s[i] == '\\' {
			return ""
		}
	}
	// Reject scheme://host and //host. These are the two open-redirect
	// shapes a return_to query param can take that url.Parse alone
	// catches.
	if strings.HasPrefix(s, "//") {
		return ""
	}
	if u, err := url.Parse(s); err != nil || u.Scheme != "" || u.Host != "" {
		// Parse error => junk; non-empty Scheme/Host => off-origin.
		return ""
	}
	// Require leading "/" so a plain "accounts" doesn't accidentally
	// resolve relative to /auth/.
	if !strings.HasPrefix(s, "/") {
		return ""
	}
	return s
}

// SanitizeReturnToForTest exposes sanitizeReturnTo for the
// open-redirect bypass test suite. Production callers MUST NOT use
// this -- handlers call sanitizeReturnTo directly.
func SanitizeReturnToForTest(s string) string { return sanitizeReturnTo(s) }

// callbackUnauthorized renders the uniform 401 used for every
// callback-validation failure. The reason flows to the log only --
// not to the response -- so an attacker cannot use the response body
// to distinguish failure modes.
func (s *Server) callbackUnauthorized(w http.ResponseWriter, r *http.Request, reason string, err error) {
	attrs := []slog.Attr{
		slog.String("reason", reason),
		slog.String("remote", r.RemoteAddr),
	}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	s.deps.Logger.LogAttrs(r.Context(), slog.LevelWarn, "auth/callback rejected", attrs...)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
