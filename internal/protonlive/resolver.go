// Resolver adapters that expose a Registry through the per-package
// "account ID -> live proton.Client" interfaces the serving layers
// already declare:
//
//   - imapserver.ProtonClientLookup.ProtonForAccount
//   - mcpserver.ClientResolver.ProtonForAccount
//   - outbox.ProtonClientResolver.ResolveClient
//
// All three share the same intent; rather than have each serving package
// import internal/protonlive (which would couple them to the registry's
// concrete type), the composition root wraps a *Registry in the small
// adapter below and passes it where each package's interface is wanted.
// Go's structural interface satisfaction means *Resolver satisfies the
// first two directly; the outbox's differently-named/shaped method gets
// the ResolveClient shim.
//
// Governing: ADR-0001 (go-proton-api), SPEC-0002 REQ "One Worker Per
// Active Account".
package protonlive

import (
	"context"

	"github.com/joestump/reduit/internal/proton"
)

// Resolver adapts a *Registry to the resolver interfaces the serving
// layers declare. Construct via Registry.Resolver.
//
// "No live client for this account" is reported as (nil, nil), NOT an
// error. Every consumer (IMAP Move handler, MCP clientFor, outbox worker)
// already treats a nil client as "account is mid-Proton-login / not yet
// unlocked" and responds with a transient/retriable failure — exactly the
// right behaviour for an account whose keyring has not been (re-)unlocked
// in this process yet. Returning a hard error here would instead surface
// as a permanent failure at some call sites.
type Resolver struct {
	reg *Registry
}

// Resolver returns an adapter over r suitable for wiring into
// imapserver.NewBackend (WithProtonLookup), mcpserver.ToolDeps.Clients,
// and outbox.Config.Resolver.
func (r *Registry) Resolver() *Resolver { return &Resolver{reg: r} }

// ProtonForAccount implements imapserver.ProtonClientLookup and
// mcpserver.ClientResolver. ctx is accepted to satisfy those interfaces;
// the lookup itself is an in-memory map read and does not use it.
func (a *Resolver) ProtonForAccount(_ context.Context, accountID string) (proton.Client, error) {
	c, ok := a.reg.Get(accountID)
	if !ok {
		return nil, nil
	}
	return c, nil
}

// ResolveClient implements outbox.ProtonClientResolver. The outbox's
// interface is sync (no ctx) and named differently; this shim bridges the
// shape. A miss returns (nil, nil) with the same "not yet bound"
// semantics as ProtonForAccount.
func (a *Resolver) ResolveClient(accountID string) (proton.Client, error) {
	c, ok := a.reg.Get(accountID)
	if !ok {
		return nil, nil
	}
	return c, nil
}
