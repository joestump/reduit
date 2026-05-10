// Package mcpserver hosts Reduit's embedded Model Context Protocol
// (MCP) HTTP surface. It mounts at `/mcp` on the same admin HTTPS
// listener that serves the OIDC login flow, the account dashboard,
// and the wizard -- per ADR-0008 there is no separate process and no
// separate port.
//
// The MCP HTTP transport is the streamable-HTTP+SSE shape provided by
// github.com/modelcontextprotocol/go-sdk. Reduit wraps the SDK's
// handler in two layers of middleware:
//
//  1. Bearer-auth -- accepts either an OIDC ID token (with an
//     out-of-band account selector via the `X-Reduit-Account` header)
//     or a Reduit-issued per-account MCP token (which is bound to
//     exactly one account at issuance and needs no selector). The
//     authenticated *Account is stashed on the request context for
//     downstream tool handlers.
//
//  2. Per-account concurrency cap -- a `chan struct{}` semaphore per
//     account_id with capacity MCP_PER_ACCOUNT_CONCURRENCY (default 4)
//     gates in-flight tool invocations. Above the cap, requests queue
//     up to a depth of 16; queue overflow returns 503 with
//     `Retry-After: 5`. Per ADR-0008 / SPEC-0006 this prevents a
//     single account from exhausting per-account Proton API quotas.
//
// Tool registration: SPEC-0006's read-half tool surface
// (list_messages, get_message, search_messages, list_labels) is
// registered at construction by RegisterReadTools. Write tools (#29)
// and streaming variants (#30) layer on top of the same *mcp.Server.
//
// Governing: ADR-0008 (embedded MCP server), SPEC-0006 REQ "Bearer
// Authentication Required", SPEC-0006 REQ "Account Scope on All
// Operations", SPEC-0006 REQ "Per-Account Concurrency Limit",
// SPEC-0006 REQ "Required Tool Set".
package mcpserver

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/auth"
	"github.com/joestump/reduit/internal/mailbox"
	"github.com/joestump/reduit/internal/users"
)

// Version is the MCP server's advertised implementation version. Bumped
// in lockstep with the binary version surfaced through /healthz; held
// here as a constant rather than threaded through Deps because the MCP
// implementation identifier is not user-configurable (clients pin to
// "reduit" + this version).
const Version = "0.1.0"

// MaxRequestBodyBytes is the cap on inbound MCP HTTP request bodies.
// JSON-RPC tool calls in this story carry small inputs; tool stories
// (#29-#30) may add larger payloads (e.g. send_message with inline
// attachments) and lift this. Until then, 1 MiB is a generous cap
// that bounds memory pressure from a hostile or buggy client.
//
// Governing: SPEC-0006 security checklist "Request body size limits
// enforced".
const MaxRequestBodyBytes = 1 << 20 // 1 MiB

// Deps gathers the dependencies a Server needs at construction time.
// All fields are required; New panics on a nil dependency because
// startup wiring is the only legitimate caller and a missing dep is a
// programmer error the operator cannot recover from at runtime.
type Deps struct {
	// Validator is the bearer-token validator shared with the rest of
	// the auth surface. It accepts either an OIDC JWT or a Reduit MCP
	// token and resolves the caller's identity.
	//
	// Governing: SPEC-0006 REQ "Bearer Authentication Required".
	Validator *auth.BearerValidator

	// Accounts is the account service used to (a) resolve an account
	// from an MCP-token bearer's account_id and (b) resolve an account
	// from the OIDC selector for JWT bearers, with ownership checks.
	Accounts account.Service

	// Users resolves OIDC subjects to users.id so the JWT bearer path
	// can verify account.user_id == users.id for the JWT's subject.
	// Required for the OIDC-bearer scenario; may be nil only when the
	// validator is also nil-OIDC, which would be an unusual test setup.
	Users users.Service

	// Limiter caps in-flight tool calls per account. Constructed via
	// NewConcurrencyLimiter; tests with no concurrency assertions can
	// pass a NoLimiter() to bypass the gate.
	Limiter Limiter

	// Mailboxes is the per-account mailbox + message store the read
	// tools query (list_messages, list_labels). Required when
	// constructing via New (the production path); tests using
	// NewWithTerminal may leave this nil because they never reach
	// the tool layer.
	//
	// Governing: SPEC-0006 REQ "Required Tool Set" (read).
	Mailboxes mailbox.Service

	// ProtonForAccount mints a session-bearing proton.Client for an
	// account-scoped tool invocation. Required when constructing via
	// New. The composition root wires this to a closure that resolves
	// account secrets via account.Service and calls
	// proton.Manager.NewClient.
	//
	// Governing: SPEC-0006 REQ "Required Tool Set" (read);
	// ADR-0001 (go-proton-api).
	ProtonForAccount ProtonClientFactory

	// Logger is used for structured authn/authz failures and
	// concurrency-overflow diagnostics. Required.
	Logger *slog.Logger
}

// Server wires the MCP HTTP handler with Reduit's auth + concurrency
// middleware. It exposes a single net/http.Handler suitable for
// mounting at `/mcp` on the admin listener via http.ServeMux.Handle.
type Server struct {
	deps    Deps
	handler http.Handler
	mcp     *mcp.Server
}

// New constructs a Server. Returns an http.Handler ready to serve MCP
// streamable-HTTP requests under the bearer-auth + concurrency-cap
// middleware chain.
//
// The MCP-protocol Server is constructed once at boot and reused for
// every session. Read-half tool registration runs here; subsequent
// stories (#29-#30) layer additional tools onto the same *mcp.Server
// via dedicated RegisterXxxTools entry points.
//
// Governing: ADR-0008, SPEC-0006 REQ "Required Tool Set" (read).
func New(deps Deps) *Server {
	if deps.Validator == nil {
		panic("mcpserver: nil Validator")
	}
	if deps.Accounts == nil {
		panic("mcpserver: nil Accounts")
	}
	if deps.Limiter == nil {
		panic("mcpserver: nil Limiter")
	}
	if deps.Mailboxes == nil {
		panic("mcpserver: nil Mailboxes")
	}
	if deps.ProtonForAccount == nil {
		panic("mcpserver: nil ProtonForAccount")
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}

	mcpSrv := mcp.NewServer(&mcp.Implementation{
		Name:    "reduit",
		Version: Version,
	}, nil)

	// Register the read-side tool surface (SPEC-0006 #28). Write
	// tools (#29) and streaming variants (#30) layer on top of the
	// same mcpSrv via additional RegisterXxxTools calls; that
	// keeps the registration call sites thin and per-story-scoped.
	//
	// Governing: SPEC-0006 REQ "Required Tool Set" (read).
	RegisterReadTools(mcpSrv, ToolDeps{
		Mailboxes:        deps.Mailboxes,
		ProtonForAccount: deps.ProtonForAccount,
		Logger:           deps.Logger,
	})

	// SDK's streamable-HTTP handler. The `getServer` callback returns
	// the same server for every session: per ADR-0008 the MCP server
	// is process-scoped, not per-request, so a static lookup is
	// correct. DNS rebinding protection is disabled here -- Reduit's
	// admin listener is reached over a public HTTPS endpoint with the
	// operator-selected hostname, not localhost, so the SDK's default
	// loopback-only Host check would false-positive every legitimate
	// request. CSRF on the admin UI is enforced separately at the
	// session-cookie layer; the MCP path is bearer-only and CSRF is
	// not applicable to bearer auth (the attacker would need the
	// bearer to forge the request).
	//
	// Governing: ADR-0008 (embedded MCP on admin listener).
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return mcpSrv
	}, &mcp.StreamableHTTPOptions{
		Stateless:                  true,
		JSONResponse:               true,
		Logger:                     deps.Logger,
		DisableLocalhostProtection: true,
	})

	// Compose middleware: outermost is bearer-auth (so unauth requests
	// never touch the limiter or the SDK). The limiter wraps the MCP
	// handler so the gate applies to actual tool dispatch and not to
	// the auth-failure short-circuit. A request-body size cap sits
	// outermost of all so an oversized body 4xx's before any
	// per-account state is touched.
	//
	// Governing: SPEC-0006 REQ "Bearer Authentication Required",
	// SPEC-0006 REQ "Per-Account Concurrency Limit",
	// SPEC-0006 security checklist (request body size limits).
	chain := requireConcurrencySlot(deps.Limiter, deps.Logger, mcpHandler)
	chain = requireBearerAndAccount(deps, chain)
	chain = limitRequestBody(MaxRequestBodyBytes, chain)

	return &Server{
		deps:    deps,
		handler: chain,
		mcp:     mcpSrv,
	}
}

// limitRequestBody wraps r.Body with http.MaxBytesReader so a
// downstream JSON decode of an oversized payload trips the cap and
// the SDK returns a 4xx, instead of allocating unbounded memory.
//
// Governing: SPEC-0006 security checklist "Request body size limits
// enforced".
func limitRequestBody(max int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, max)
		}
		next.ServeHTTP(w, r)
	})
}

// Handler returns the composed HTTP handler. Mount it at `/mcp` on the
// admin listener.
func (s *Server) Handler() http.Handler { return s.handler }

// MCPServer exposes the wrapped *mcp.Server for tool-registration
// callers (issues #29-#30). Returning the inner server keeps tool
// wiring reachable without re-plumbing every dependency through Deps.
func (s *Server) MCPServer() *mcp.Server { return s.mcp }

// defaultLogger returns the package's fallback logger -- slog.Default
// at the call site. Centralised so the test seam in export_test.go
// can share the same fallback policy.
func defaultLogger() *slog.Logger { return slog.Default() }

// AccountFromContext returns the *account.Account stashed on ctx by
// the bearer-auth middleware. Tool handlers retrieve it to scope
// their SQL by account_id. Returns nil if the middleware did not run
// (e.g. a test that builds a context manually without going through
// the chain).
//
// Governing: SPEC-0006 REQ "Account Scope on All Operations".
func AccountFromContext(ctx context.Context) *account.Account {
	if v, ok := ctx.Value(accountCtxKey{}).(*account.Account); ok {
		return v
	}
	return nil
}

// WithAccount returns a new context with acct attached. Exported for
// test-only callers that need to drive a tool handler directly without
// going through the auth/HTTP chain (the production seam is the
// requireBearerAndAccount middleware).
func WithAccount(ctx context.Context, acct *account.Account) context.Context {
	return withAccount(ctx, acct)
}

// withAccount is the unexported worker the auth middleware calls.
// Exported callers use WithAccount; the split exists so the test seam
// is explicitly separate from the production seam in code search.
func withAccount(ctx context.Context, acct *account.Account) context.Context {
	return context.WithValue(ctx, accountCtxKey{}, acct)
}

// accountCtxKey is the context key under which AccountFromContext
// reads. Unexported per the standard "type-keyed context value" idiom.
type accountCtxKey struct{}
