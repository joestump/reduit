package mcpserver

import (
	"net/http"
)

// ReservationCount returns the number of reservations currently held
// by accountID inside the limiter. Test-only -- production code MUST
// NOT consult this. Returns 0 when the limiter has no Acquire call
// for that account yet, OR when the supplied limiter is not a
// concurrencyLimiter (e.g. NoLimiter).
func ReservationCount(l Limiter, accountID string) int {
	if cl, ok := l.(*concurrencyLimiter); ok {
		return cl.reservationCount(accountID)
	}
	return 0
}

// NewWithTerminal is a test-only constructor that builds the same
// bearer-auth + concurrency-cap middleware chain as New, but installs
// `terminal` as the post-middleware downstream instead of the MCP
// SDK's streamable-HTTP handler. Tests use this to observe the
// post-auth context (and so verify that the right *account.Account is
// stamped onto it) without parsing a JSON-RPC response or driving the
// SDK.
//
// Production callers MUST use New, which wires the real SDK handler.
//
// The split is exposed via export_test.go so production code never
// imports the test-only path.
func NewWithTerminal(deps Deps, terminal http.Handler) *Server {
	if deps.Validator == nil {
		panic("mcpserver: nil Validator")
	}
	if deps.Accounts == nil {
		panic("mcpserver: nil Accounts")
	}
	if deps.Limiter == nil {
		panic("mcpserver: nil Limiter")
	}
	if deps.Logger == nil {
		deps.Logger = defaultLogger()
	}
	chain := requireConcurrencySlot(deps.Limiter, deps.Logger, terminal)
	chain = requireBearerAndAccount(deps, chain)
	chain = limitRequestBody(MaxRequestBodyBytes, chain)
	return &Server{
		deps:    deps,
		handler: chain,
	}
}
