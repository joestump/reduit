// MCP tool surface: the read, write, and send tools Reduit exposes to
// AI agents per SPEC-0006. Registration is static (compile-time) against
// the modelcontextprotocol/go-sdk server; each tool is a thin wrapper
// around the per-account Proton client, the shared IMAP folder/label
// resolver (so folder names match the IMAP backend exactly), and -- for
// send_message -- the SPEC-0004 outbox encryption pipeline.
//
// Every tool scopes its effects to the account bound by the bearer-auth
// middleware (AccountFromContext). A message ID belonging to another
// account surfaces as a `not_found` tool error identical to a genuine
// miss, per SPEC-0006 REQ "Account Scope on All Operations".
//
// Governing: ADR-0008 (embedded MCP server), SPEC-0006 REQ "Required
// Tool Set".
package mcpserver

import (
	"context"
	"errors"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/outbox"
	"github.com/joestump/reduit/internal/proton"
)

// ClientResolver resolves an account ID to a live, session-bearing
// Proton client. It mirrors imapserver.ProtonClientLookup and
// sync.ClientFactory: the composition root wraps account.Service's
// token-unseal path plus proton.Manager.WithAccount, and tests inject a
// fake. Returning (nil, nil) is treated as "no client currently bound"
// (e.g. the account is mid-Proton-login) and surfaces to the agent as a
// retriable auth error rather than a panic.
//
// Governing: SPEC-0006 REQ "Account Scope on All Operations".
type ClientResolver interface {
	ProtonForAccount(ctx context.Context, accountID string) (proton.Client, error)
}

// ClientResolverFunc adapts a plain function to ClientResolver.
type ClientResolverFunc func(ctx context.Context, accountID string) (proton.Client, error)

// ProtonForAccount implements ClientResolver.
func (f ClientResolverFunc) ProtonForAccount(ctx context.Context, accountID string) (proton.Client, error) {
	return f(ctx, accountID)
}

// Submitter is the slice of outbox.Manager the send_message tool needs.
// Declaring it as a local interface (instead of taking *outbox.Manager
// directly) lets the tool tests assert that send_message hands the
// fully-assembled RFC 5322 envelope to the outbox -- and therefore
// reuses the SPEC-0004 encryption pipeline -- without spinning up a real
// outbox worker + Proton stack.
//
// Governing: SPEC-0006 REQ "Send-Message Encryption" (encryption is
// handled by the outbox, not reimplemented here).
type Submitter interface {
	Submit(ctx context.Context, sub outbox.Submission) outbox.Result
}

// Compile-time assertion: the production *outbox.Manager satisfies the
// local Submitter shape. If Submit's signature drifts, the build fails
// here rather than at the composition root.
var _ Submitter = (*outbox.Manager)(nil)

// ToolDeps gathers the dependencies the tool handlers need. All fields
// are required when RegisterTools is called with a non-nil ToolDeps;
// New() leaves tools unregistered when ToolDeps is nil (preserving the
// auth+concurrency-only scaffolding behaviour for tests that don't
// exercise the tool surface).
type ToolDeps struct {
	// Clients resolves the per-account Proton client. Required.
	Clients ClientResolver

	// Outbox is the SPEC-0004 outbox the send_message tool submits
	// through. Required for send_message; if nil, send_message is still
	// registered but returns a structured `unavailable` error so the
	// tool listing stays complete.
	Outbox Submitter

	// Logger is used for structured per-tool diagnostics. Nil falls back
	// to slog.Default().
	Logger *slog.Logger
}

// ToolError is the structured error payload SPEC-0006 mandates for
// folder-resolution failures and send failures. It is returned as part
// of a tool's Output (StructuredContent) -- not as a Go error -- so the
// agent receives a machine-readable code it can branch on.
//
// Governing: SPEC-0006 REQ "Folder Names Match IMAP Mapping" (Scenario
// "Unknown folder name yields a clear error"), SPEC-0006 REQ
// "Send-Message Encryption" (Scenario "Send failure surfaces structured
// error").
type ToolError struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Retriable bool           `json:"retriable"`
	Details   map[string]any `json:"details,omitempty"`
}

// Symbolic error codes per the SPEC-0006 design.md error-mapping table.
const (
	codeNotFound                = "not_found"
	codeUnknownFolder           = "unknown_folder"
	codeAuthRequired            = "auth_required"
	codeRateLimited             = "rate_limited"
	codeProtonUnavailable       = "proton_unavailable"
	codeBadRequest              = "bad_request"
	codeRecipientKeyUnavailable = "recipient_key_unavailable"
	codeInvalidArgument         = "invalid_argument"
)

// registerTools wires every read, write, and send tool onto the MCP
// server. Called from New() when tool dependencies are supplied.
//
// Tool names, parameters, and result shapes follow SPEC-0006 REQ
// "Required Tool Set" exactly; a rename or schema change is a documented
// breaking change per the "Each tool has a stable name and schema"
// scenario.
func registerTools(srv *mcp.Server, deps ToolDeps) {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	r := &toolRegistry{deps: deps}
	r.registerRead(srv)
	r.registerWrite(srv)
	r.registerSend(srv)
}

// toolRegistry carries the tool dependencies through the per-tool
// handler methods so each handler can reach the resolver / outbox /
// logger without a package-level singleton.
type toolRegistry struct {
	deps ToolDeps
}

// accountFor returns the account bound to the request context by the
// bearer-auth middleware. A nil account is a programmer error (the
// middleware runs before any tool dispatch); we surface it as a generic
// internal error so it never silently scopes to the wrong account.
func (r *toolRegistry) accountFor(ctx context.Context) (*account.Account, error) {
	acct := AccountFromContext(ctx)
	if acct == nil {
		// Defense in depth: tools are only reachable behind
		// requireBearerAndAccount, which always stamps an account on
		// success. Fail closed.
		return nil, errors.New("mcpserver: no account bound to request context")
	}
	return acct, nil
}

// clientFor resolves the per-account Proton client, mapping the
// "no client bound" sentinel (nil, nil) to a retriable auth error so the
// agent retries once the account finishes Proton login.
func (r *toolRegistry) clientFor(ctx context.Context, acct *account.Account) (proton.Client, *ToolError) {
	cl, err := r.deps.Clients.ProtonForAccount(ctx, acct.ID)
	if err != nil {
		return nil, mapProtonError(err)
	}
	if cl == nil {
		return nil, &ToolError{
			Code:      codeAuthRequired,
			Message:   "Proton session is not currently available for this account",
			Retriable: true,
		}
	}
	return cl, nil
}

// mapProtonError translates a Proton-side / resolver error into the
// SPEC-0006 structured error vocabulary. The mapping mirrors the
// design.md error table; anything unrecognised falls through to a
// retriable proton_unavailable so a transient upstream blip is retried
// rather than reported as a permanent failure.
//
// Governing: SPEC-0006 design.md "Error mapping".
func mapProtonError(err error) *ToolError {
	if err == nil {
		return nil
	}
	// account.ErrAccountNotFound from the resolver means the bound
	// account was hard-deleted out from under the request -- treat as a
	// not_found miss.
	if errors.Is(err, account.ErrAccountNotFound) {
		return &ToolError{Code: codeNotFound, Message: "account not found", Retriable: false}
	}
	if errors.Is(err, proton.ErrNotAuthenticated) {
		return &ToolError{Code: codeAuthRequired, Message: "Proton authentication required", Retriable: true}
	}
	var apiErr *proton.APIError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.Status == 401:
			return &ToolError{Code: codeAuthRequired, Message: "Proton authentication required", Retriable: false}
		case apiErr.Status == 429:
			return &ToolError{Code: codeRateLimited, Message: "Proton rate limited the request", Retriable: true}
		case apiErr.Status >= 500:
			return &ToolError{Code: codeProtonUnavailable, Message: "Proton is temporarily unavailable", Retriable: true}
		case apiErr.Status >= 400:
			return &ToolError{Code: codeBadRequest, Message: apiErr.Message, Retriable: false}
		}
	}
	return &ToolError{Code: codeProtonUnavailable, Message: "Proton request failed", Retriable: true}
}
