// Compile-time proof that *Resolver satisfies the three serving-layer
// resolver interfaces issue #28 must feed. These assertions are the
// contract between this package and the composition root: if any of the
// three upstream interfaces changes method shape, the build breaks HERE
// (with a clear message) rather than at the cli/serve wiring site or, far
// worse, at runtime.
//
// This file is the ONLY place internal/protonlive imports the serving
// packages, and it does so solely for the assertions — there is no
// runtime dependency. The serving packages do not import protonlive, so
// no import cycle is created.
//
// Governing: ADR-0001, SPEC-0002 REQ "One Worker Per Active Account".
package protonlive

import (
	"github.com/joestump/reduit/internal/imapserver"
	"github.com/joestump/reduit/internal/mcpserver"
	"github.com/joestump/reduit/internal/outbox"
)

var (
	// IMAP MOVE/COPY label adjustment resolves the live client here.
	_ imapserver.ProtonClientLookup = (*Resolver)(nil)
	// MCP read/write/send tools resolve the per-account client here.
	_ mcpserver.ClientResolver = (*Resolver)(nil)
	// The SMTP outbox resolves the session-bearing client per-Submit here.
	_ outbox.ProtonClientResolver = (*Resolver)(nil)
)
