package mcpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/auth"
	"github.com/joestump/reduit/internal/users"
)

// xReduitAccount is the canonical out-of-band account-selector header
// for OIDC-bearer MCP requests on the bare `/mcp` route. Per
// SPEC-0006 REQ "Selector Precedence" the path-parameter form
// (`/accounts/{id}/mcp`) wins when both are present and the header is
// then NOT consulted; the header is read only on routes without an
// account-id path parameter (today: the bare `/mcp` endpoint).
const xReduitAccount = "X-Reduit-Account"

// accountPathValue is the name of the path-parameter wildcard the
// `/accounts/{id}/mcp` route binds. http.ServeMux stamps it onto the
// request via r.SetPathValue before the handler runs, so
// requireBearerAndAccount reads it with r.PathValue. On the bare
// `/mcp` route the wildcard is unbound and r.PathValue returns "".
//
// Governing: SPEC-0006 REQ "Selector Precedence".
const accountPathValue = "id"

// selectorFromRequest implements SPEC-0006 REQ "Selector Precedence":
// the path-parameter account selector wins over the X-Reduit-Account
// header. When a non-empty path parameter is present the header is NOT
// consulted at all -- not read, not parsed, not validated -- so an
// attacker cannot use the header value to probe whether it matches the
// path id and learn ownership of a non-owned account. The header is
// read only when the path carries no selector (the bare `/mcp` route).
//
// Governing: SPEC-0006 REQ "Selector Precedence".
func selectorFromRequest(r *http.Request) string {
	if pathSel := strings.TrimSpace(r.PathValue(accountPathValue)); pathSel != "" {
		// Path wins. Per the spec the header MUST NOT be parsed when a
		// path parameter is present, so we return here without ever
		// touching r.Header.
		return pathSel
	}
	return r.Header.Get(xReduitAccount)
}

// requireBearerAndAccount is the MCP-side authentication middleware.
// It composes auth.RequireBearer (which validates the Authorization
// header and stamps a *Principal on the context) with an
// account-resolution step that:
//
//   - For PrincipalSourceMCPToken: uses Principal.AccountID directly.
//     The token row was issued for exactly one account at mint time,
//     so the bearer alone disambiguates -- no selector is required or
//     consulted. Per SPEC-0006 "Per-account MCP token authenticates
//     as the bound account".
//
//   - For PrincipalSourceOIDC: requires an X-Reduit-Account header
//     carrying the account UUID, looks up users.id from the JWT's
//     subject, looks up the account by ID, and verifies
//     account.user_id == users.id. Three failure modes -- selector
//     references a non-existent UUID; selector references an account
//     owned by a different user; JWT subject has no users row at all
//     -- all collapse to a byte-identical 403 to satisfy SPEC-0006
//     REQ "Authorization-Failure Indistinguishability". The single
//     distinct response is 400 selector_required when no header is
//     present (which carries no account identifier and so leaks
//     nothing).
//
// On success the resolved *account.Account is stashed on the request
// context (read by AccountFromContext) and the next handler runs.
//
// Governing: SPEC-0006 REQ "Bearer Authentication Required",
// SPEC-0006 REQ "Selector Precedence", SPEC-0006 REQ
// "Authorization-Failure Indistinguishability".
func requireBearerAndAccount(deps Deps, next http.Handler) http.Handler {
	bearerMW := auth.RequireBearer(deps.Validator, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := auth.PrincipalFromContext(r.Context())
		if !ok || p == nil {
			// Defense in depth: RequireBearer guarantees a Principal
			// on success, but a future middleware re-ordering bug
			// could land here. Fail closed.
			respondUnauthenticated(w, "")
			return
		}

		switch p.Source {
		case auth.PrincipalSourceMCPToken:
			acct, err := deps.Accounts.GetByID(r.Context(), p.AccountID)
			if err != nil {
				// An MCP-token row whose account_id no longer
				// resolves means the account was hard-deleted
				// (FK CASCADE would have dropped the token, so
				// this is racing against a delete) or the schema
				// invariant has drifted. Either way the bearer
				// can't bind to an account -- 401 is the right
				// shape because the bearer is no longer usable.
				deps.Logger.WarnContext(r.Context(),
					"mcpserver: mcp-token bearer references non-resolvable account",
					slog.String("account_id", p.AccountID),
					slog.String("error", err.Error()))
				respondUnauthenticated(w, "")
				return
			}
			if !accountUsable(acct) {
				// Suspended / soft-deleted accounts MUST NOT be
				// reachable via MCP -- per SPEC-0005's "drop
				// sessions" contract for state changes, they're
				// effectively offline. 401 keeps the failure mode
				// consistent with revoked-token behaviour.
				respondUnauthenticated(w, "")
				return
			}
			next.ServeHTTP(w, r.WithContext(withAccount(r.Context(), acct)))

		case auth.PrincipalSourceOIDC:
			// Per SPEC-0006 REQ "Selector Precedence": a path-param
			// selector (`/accounts/{id}/mcp`) wins over the header and
			// suppresses header parsing entirely. selectorFromRequest
			// encapsulates that rule.
			acct, status := resolveAccountFromOIDC(r.Context(), deps, p, selectorFromRequest(r))
			switch status {
			case oidcResolutionOK:
				next.ServeHTTP(w, r.WithContext(withAccount(r.Context(), acct)))
			case oidcResolutionMissingSelector:
				// 400 selector_required is the ONE distinct
				// response code by design -- it leaks nothing
				// because it carries no UUID. Per SPEC-0006 REQ
				// "Selector Precedence" Scenario "No selector at
				// all".
				respondJSON(w, http.StatusBadRequest, `{"error":"selector_required"}`)
			case oidcResolutionForbidden:
				// All three forbidden cases -- non-existent
				// account, existing-but-not-owned, and "JWT
				// subject has no users row at all" -- collapse
				// to byte-identical 403 per SPEC-0006 REQ
				// "Authorization-Failure Indistinguishability".
				respondForbidden(w)
			default:
				// Programmer error: unreachable.
				deps.Logger.ErrorContext(r.Context(),
					"mcpserver: unexpected OIDC resolution status",
					slog.Int("status", int(status)))
				http.Error(w, "internal error", http.StatusInternalServerError)
			}

		default:
			// PrincipalSourceUnknown or a future variant we don't
			// understand -- fail closed.
			deps.Logger.WarnContext(r.Context(),
				"mcpserver: principal with unknown source rejected",
				slog.Int("source", int(p.Source)))
			respondUnauthenticated(w, "")
		}
	}))

	return bearerMW
}

// oidcResolution enumerates the three observable outcomes of resolving
// an OIDC-bearer request to an account. The byte-identical-response
// contract for the forbidden case is enforced at the call site by
// branching on this enum, not on the underlying error -- the resolver
// deliberately collapses three internal failures into one external
// signal.
type oidcResolution int

const (
	oidcResolutionOK oidcResolution = iota
	oidcResolutionMissingSelector
	oidcResolutionForbidden
)

// resolveAccountFromOIDC turns a validated OIDC bearer + the optional
// X-Reduit-Account header into either an authorised *account.Account
// or a deliberately-flat 403/400 signal.
//
// The three forbidden cases ("non-existent UUID", "existing UUID owned
// by a different user", "JWT subject has no users row at all") collapse
// to oidcResolutionForbidden so the caller cannot accidentally leak
// the distinction onto the wire. Operator-side log lines DO record
// the distinction for triage -- the privacy contract is wire-only,
// per SPEC-0006 REQ "Authorization-Failure Indistinguishability".
//
// Governing: SPEC-0006 REQ "Bearer Authentication Required" (Scenarios:
// OIDC bearer token requires account selector, OIDC bearer subject
// with no users row), SPEC-0006 REQ "Authorization-Failure
// Indistinguishability".
func resolveAccountFromOIDC(ctx context.Context, deps Deps, p *auth.Principal, selector string) (*account.Account, oidcResolution) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return nil, oidcResolutionMissingSelector
	}

	// Resolve the JWT subject to a users row. A missing row means the
	// caller has a valid IdP-issued JWT but has never completed a web
	// OIDC login at Reduit -- per SPEC-0006 REQ "OIDC bearer subject
	// with no `users` row is rejected" we MUST NOT silently upsert
	// from the MCP path. The single seam for new subjects is the web
	// /auth/callback handler.
	usrSvc := deps.Users
	var userID string
	var subjectKnown bool
	if usrSvc != nil {
		u, err := usrSvc.GetByOIDCSubject(ctx, p.Subject)
		switch {
		case err == nil:
			userID = u.ID
			subjectKnown = true
		case errors.Is(err, users.ErrUserNotFound):
			// Fall through; subjectKnown stays false. We still go
			// through the account lookup below so the timing of the
			// "no users row" path approximates the timing of the
			// "account not found" / "account not owned" paths --
			// SPEC-0006 RECOMMENDS coarse same-order-of-magnitude
			// timing parity.
			deps.Logger.WarnContext(ctx,
				"mcpserver: OIDC bearer subject has no users row; rejecting",
				slog.String("subject", p.Subject))
		default:
			// Real DB error -- log loudly. We still return forbidden
			// (not 500) so the caller's wire response stays in the
			// indistinguishability bucket; the operator-side log
			// is the trail to the underlying failure.
			deps.Logger.ErrorContext(ctx,
				"mcpserver: users lookup failed during OIDC bearer auth",
				slog.String("subject", p.Subject),
				slog.String("error", err.Error()))
			return nil, oidcResolutionForbidden
		}
	} else {
		// No users service wired -- treat as forbidden, not 500.
		// Same indistinguishability contract.
		deps.Logger.WarnContext(ctx,
			"mcpserver: OIDC bearer received without a users service wired")
		return nil, oidcResolutionForbidden
	}

	acct, err := deps.Accounts.GetByID(ctx, selector)
	if err != nil {
		// Account does not exist OR a real DB error. Either way the
		// wire response is 403; the log line distinguishes for ops.
		if errors.Is(err, account.ErrAccountNotFound) {
			deps.Logger.WarnContext(ctx,
				"mcpserver: OIDC bearer selector references non-existent account",
				slog.String("subject", p.Subject),
				slog.String("selector", selector))
		} else {
			deps.Logger.ErrorContext(ctx,
				"mcpserver: account lookup failed during OIDC bearer auth",
				slog.String("subject", p.Subject),
				slog.String("selector", selector),
				slog.String("error", err.Error()))
		}
		return nil, oidcResolutionForbidden
	}

	// Account exists. If the JWT subject doesn't have a users row OR
	// the account isn't owned by this user, we land here. Both cases
	// flatten to forbidden by design. We perform the ownership check
	// even when subjectKnown=false so the code path executes the
	// same comparisons in the same order -- subjectKnown=false means
	// userID is "" which can never match acct.UserID, so the result
	// is "forbidden" but the timing matches the "wrong owner" case.
	if !subjectKnown || acct.UserID != userID {
		deps.Logger.WarnContext(ctx,
			"mcpserver: OIDC bearer not owner of selected account",
			slog.String("subject", p.Subject),
			slog.String("selector", selector),
			slog.Bool("subject_known", subjectKnown),
		)
		return nil, oidcResolutionForbidden
	}

	if !accountUsable(acct) {
		// Owner check passed but account is suspended / soft-deleted.
		// Deny via the same forbidden response so MCP is consistent
		// with the "account is offline" contract on the rest of
		// Reduit's surfaces.
		deps.Logger.WarnContext(ctx,
			"mcpserver: OIDC bearer hit non-active account",
			slog.String("subject", p.Subject),
			slog.String("selector", selector),
			slog.String("state", string(acct.State)))
		return nil, oidcResolutionForbidden
	}

	return acct, oidcResolutionOK
}

// accountUsable reports whether an account is in a state that admits
// MCP traffic. Only StateActive accounts are usable: a
// StatePendingProtonSetup account has not finished the wizard and so
// has no usable Proton credentials (the tool surface would fail with
// proton.ErrNotUnlocked); suspended and soft-deleted accounts are
// offline by the SPEC-0005 "drop sessions on state change" contract.
//
// This was loosened to also admit StatePendingProtonSetup during the
// auth+concurrency scaffolding story (#13) so fixtures didn't need
// state-flip plumbing. Now that the tool surface (#14) has landed,
// pending accounts can reach real tools but have no credentials to
// service them, so we tighten to active-only here -- failing closed at
// the auth boundary rather than surfacing a confusing decrypt error
// from deep inside a tool handler.
//
// Governing: SPEC-0006 REQ "Bearer Authentication Required" (requests
// bind to a usable account); SPEC-0005 "drop sessions" contract for
// non-active states.
func accountUsable(a *account.Account) bool {
	return a != nil && a.State == account.StateActive
}

// respondUnauthenticated emits the standard 401 shape for missing /
// invalid / revoked bearers. The body is a generic JSON envelope per
// SPEC-0006 REQ "Bearer Authentication Required" Scenario
// "Unauthenticated MCP request is rejected". The WWW-Authenticate
// header advertises the Bearer scheme but MUST NOT include a realm
// parameter -- the spec forbids leaking deployment-internal
// identifiers there.
func respondUnauthenticated(w http.ResponseWriter, _ string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", "Bearer")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthenticated"}`))
}

// respondForbidden emits the byte-identical 403 shape for all three
// indistinguishable OIDC-bearer authz failures (non-existent UUID,
// existing-but-not-owned, no users row for subject). Headers are
// kept minimal -- Content-Type only, no WWW-Authenticate realm leak,
// no X-Reduit-* diagnostic headers -- so the wire response cannot be
// fingerprinted to learn which case fired.
//
// Governing: SPEC-0006 REQ "Authorization-Failure Indistinguishability".
func respondForbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"forbidden"}`))
}

// respondJSON writes the supplied JSON-encoded body with the given
// status. Keeps the auth-failure paths above terse and uniform.
func respondJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
