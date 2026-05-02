package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/joestump/reduit/internal/auth/mcptoken"
	"github.com/joestump/reduit/internal/auth/oidc"
)

// Principal is the resolved authenticated caller of a bearer-token
// request. The bearer middleware stashes a *Principal in the request
// context under PrincipalContextKey; downstream handlers retrieve it
// via PrincipalFromContext.
//
// Source distinguishes the two valid bearer types — OIDC ID tokens
// and Reduit-issued per-user MCP tokens — so handlers can log the
// authentication mechanism without needing to re-classify.
//
// Subject is the OIDC `sub` of the underlying account, regardless of
// the bearer mechanism. For PrincipalSourceOIDC it is read from the
// validated ID token's `sub` claim. For PrincipalSourceMCPToken it
// is resolved from `accounts.oidc_subject` via the
// SubjectResolver callback supplied to NewBearerValidator. If the
// resolver is nil, or returns an error, the field is left empty —
// downstream handlers MUST therefore treat Subject as best-effort
// audit metadata, not as a primary identity key. The primary
// identity key for MCP-token bearers is AccountID.
type Principal struct {
	Subject    string // OIDC sub when known; empty when SubjectResolver is nil or fails
	AccountID  string // empty for OIDC tokens; account resolution is the caller's job
	Email      string
	Source     PrincipalSource
	MCPTokenID string // populated when Source == PrincipalSourceMCPToken
	IDTokenRaw string // populated when Source == PrincipalSourceOIDC
	IDTokenIAT time.Time
	IDTokenExp time.Time
}

// PrincipalSource enumerates the bearer-token mechanisms.
type PrincipalSource int

const (
	// PrincipalSourceUnknown is the zero value — never returned from a
	// successful validation, used to detect uninitialised structs.
	PrincipalSourceUnknown PrincipalSource = iota
	// PrincipalSourceOIDC means the bearer was a verified OIDC ID token.
	PrincipalSourceOIDC
	// PrincipalSourceMCPToken means the bearer was a Reduit MCP token
	// that resolved to an active mcp_tokens row.
	PrincipalSourceMCPToken
)

// principalCtxKey is the unexported context key under which the
// Principal is stashed by RequireBearer. Use PrincipalFromContext to
// retrieve it from outside the package.
type principalCtxKey struct{}

// PrincipalFromContext returns the Principal placed on ctx by the
// bearer middleware. The bool reports whether one was present.
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalCtxKey{}).(*Principal)
	return p, ok
}

// WithPrincipal returns a new context with p attached. Exported
// primarily for tests; production code goes through RequireBearer.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalCtxKey{}, p)
}

// BearerValidator turns an Authorization-header value into a Principal
// or an error. It is safe for concurrent use.
//
// Two bearer formats are accepted:
//
//  1. A Reduit-issued per-user MCP token (prefix `rdmcp_`). Looked up
//     by SHA-256 hash in the mcp_tokens table.
//  2. An OIDC ID token (JWT) verified against the configured IdP. Sub
//     extraction is left to the caller — they typically resolve `sub`
//     to a local account row before proceeding.
//
// Governing: SPEC-0006 REQ "Bearer Authentication Required" (Scenarios:
// OIDC bearer token, Per-user MCP token, Unauthenticated rejected).
type BearerValidator struct {
	OIDC      *oidc.Client
	MCPTokens *mcptoken.Repository
	// SubjectResolver returns the OIDC `sub` for the given internal
	// account ID. Used to populate Principal.Subject for MCP-token
	// bearers so downstream handlers and audit logs see a consistent
	// "authenticated as <sub>" identity regardless of the bearer
	// mechanism. May be nil — when nil, MCP-token Principals carry an
	// empty Subject and callers MUST fall back to AccountID for
	// identity. Errors from the resolver are swallowed (not surfaced to
	// the caller) because Subject is audit metadata, not an authz key
	// — a transient DB hiccup MUST NOT 401 a request whose token is
	// otherwise valid.
	//
	// Governing: SPEC-0006 REQ "Bearer Authentication Required" — the
	// spec binds requests to the *account*; Subject is a convenience
	// for log correlation across the two bearer types.
	SubjectResolver func(ctx context.Context, accountID string) (string, error)
	// Now defaults to time.Now; tests override.
	Now func() time.Time
}

// NewBearerValidator returns a configured validator. Either dependency
// may be nil — a nil OIDC client makes JWT bearers fail; a nil MCP
// repository makes MCP-token bearers fail. At least one MUST be set or
// every request 401s.
//
// SubjectResolver is left unset by this constructor; wiring code (the
// serve command) injects it after constructing the account.Service so
// the auth package keeps a one-way dependency on account/. See
// WithSubjectResolver.
func NewBearerValidator(c *oidc.Client, repo *mcptoken.Repository) *BearerValidator {
	return &BearerValidator{OIDC: c, MCPTokens: repo, Now: time.Now}
}

// WithSubjectResolver attaches the account-id-to-OIDC-sub resolver to
// v and returns v for chaining. Calling this is OPTIONAL — without it,
// Principal.Subject is empty for MCP-token bearers (still a valid
// state per the field's docstring).
func (v *BearerValidator) WithSubjectResolver(fn func(ctx context.Context, accountID string) (string, error)) *BearerValidator {
	v.SubjectResolver = fn
	return v
}

// Errors returned by Validate.
var (
	ErrBearerMissing  = errors.New("auth: missing or malformed Authorization header")
	ErrBearerInvalid  = errors.New("auth: invalid bearer token")
	ErrBearerRevoked  = errors.New("auth: bearer token revoked or expired")
	ErrBearerNoIssuer = errors.New("auth: OIDC issuer not configured")
)

// ParseBearer extracts the raw bearer value from an Authorization
// header (or "" + ErrBearerMissing). The check is case-insensitive on
// the "Bearer " scheme per RFC 6750. Whitespace inside the value is
// rejected.
func ParseBearer(authHeader string) (string, error) {
	if authHeader == "" {
		return "", ErrBearerMissing
	}
	const scheme = "bearer"
	if len(authHeader) < len(scheme)+2 {
		return "", ErrBearerMissing
	}
	if !strings.EqualFold(authHeader[:len(scheme)], scheme) || authHeader[len(scheme)] != ' ' {
		return "", ErrBearerMissing
	}
	value := strings.TrimSpace(authHeader[len(scheme)+1:])
	if value == "" {
		return "", ErrBearerMissing
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return "", ErrBearerInvalid
	}
	return value, nil
}

// Validate inspects bearer and returns a Principal on success. It is
// the canonical place where SPEC-0006's two bearer types are unified
// behind a single Principal abstraction.
//
// Lookup ordering: MCP-token-prefix tokens are checked against the DB
// first because the prefix discriminator is unambiguous. Anything
// else is treated as a JWT and goes through the OIDC verifier. Order
// matters only for performance (avoid a JWKS round-trip on every MCP
// request), not for correctness — a real JWT cannot start with the
// `rdmcp_` prefix.
func (v *BearerValidator) Validate(ctx context.Context, bearer string) (*Principal, error) {
	if v == nil {
		return nil, ErrBearerInvalid
	}
	if bearer == "" {
		return nil, ErrBearerMissing
	}
	if mcptoken.HasPrefix(bearer) {
		return v.validateMCPToken(ctx, bearer)
	}
	return v.validateJWT(ctx, bearer)
}

func (v *BearerValidator) validateMCPToken(ctx context.Context, bearer string) (*Principal, error) {
	if v.MCPTokens == nil {
		return nil, ErrBearerInvalid
	}
	tok, err := v.MCPTokens.FindByPlaintext(ctx, bearer)
	if err != nil {
		if errors.Is(err, mcptoken.ErrTokenNotFound) {
			return nil, ErrBearerInvalid
		}
		return nil, err
	}
	now := v.now()
	if !tok.IsActive(now) {
		return nil, ErrBearerRevoked
	}
	// MarkUsed best-effort; failures here MUST NOT 401 the caller.
	_ = v.MCPTokens.MarkUsed(ctx, tok.ID)
	// Best-effort Subject resolution: a nil resolver or a transient
	// error leaves Subject empty, but neither failure mode 401s the
	// request — Subject is audit metadata, AccountID is the authz key.
	var sub string
	if v.SubjectResolver != nil {
		if resolved, rerr := v.SubjectResolver(ctx, tok.AccountID); rerr == nil {
			sub = resolved
		}
	}
	return &Principal{
		Subject:    sub,
		AccountID:  tok.AccountID,
		Source:     PrincipalSourceMCPToken,
		MCPTokenID: tok.ID,
	}, nil
}

func (v *BearerValidator) validateJWT(ctx context.Context, bearer string) (*Principal, error) {
	if v.OIDC == nil {
		return nil, ErrBearerNoIssuer
	}
	tok, err := v.OIDC.Verifier().Verify(ctx, bearer)
	if err != nil {
		// Distinguish expiry from signature/issuer errors so callers
		// (and audit logs) can differentiate revocation-class failures.
		var expired *gooidc.TokenExpiredError
		if errors.As(err, &expired) {
			return nil, ErrBearerRevoked
		}
		return nil, ErrBearerInvalid
	}
	var claims struct {
		Email string `json:"email"`
	}
	_ = tok.Claims(&claims)
	return &Principal{
		Subject:    tok.Subject,
		Email:      claims.Email,
		Source:     PrincipalSourceOIDC,
		IDTokenRaw: bearer,
		IDTokenIAT: tok.IssuedAt,
		IDTokenExp: tok.Expiry,
	}, nil
}

// RequireBearer returns middleware that calls Validate on every
// request, attaches the resulting *Principal to the request context,
// and 401s on any failure. Intended for the MCP HTTP surface only —
// browser routes use RequireSession instead.
//
// Governing: SPEC-0006 REQ "Bearer Authentication Required".
func RequireBearer(v *BearerValidator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer, err := ParseBearer(r.Header.Get("Authorization"))
		if err != nil {
			respondUnauthorized(w, "missing bearer")
			return
		}
		p, err := v.Validate(r.Context(), bearer)
		if err != nil {
			switch {
			case errors.Is(err, ErrBearerRevoked):
				respondUnauthorized(w, "token revoked")
			case errors.Is(err, ErrBearerNoIssuer):
				respondUnauthorized(w, "issuer not configured")
			default:
				respondUnauthorized(w, "invalid bearer")
			}
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

func respondUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="reduit"`)
	http.Error(w, msg, http.StatusUnauthorized)
}

func (v *BearerValidator) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}
