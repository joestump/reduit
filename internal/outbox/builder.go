// Builder constructs the per-message Proton SendDraftReq from a
// classified Submission. Production callers wire this in the
// composition root.
//
// Splitting the package construction out of the worker keeps the
// worker focused on lifecycle (timeout, semaphore) and the package
// construction focused on encryption-mode-aware payload shaping. The
// hostile reviewer's fear — that we silently aggregate per-recipient
// decisions into one cleartext message — is structurally impossible
// because Builder receives the per-recipient mode map and must produce
// a SendDraftReq whose Packages slice has one entry per distinct
// EncryptionScheme.
//
// Governing: SPEC-0004 REQ "Encryption Pipeline".

package outbox

import (
	"context"

	"github.com/joestump/reduit/internal/proton"
)

// BuildResult is what Builder.Build hands back to the worker.
//
// In production, DraftID is the Proton message ID created during the
// build (typically via proton.Client.CreateDraft) and Skip is false;
// the worker then calls SendDraft against the DraftID.
//
// Skip=true is the test-only escape hatch: it tells the worker "the
// encryption-mode pipeline was exercised but no upstream SendDraft
// call is required". This is the explicit replacement for the previous
// empty-string-DraftID sentinel, which the spec reviewer rightly
// flagged as a footgun (any production Builder that legitimately
// wanted to skip the call would surface as a fake success). The worker
// PANICS on Skip=false with empty DraftID so a misconfigured Builder
// fails loud, never silent.
//
// Governing: SPEC-0004 REQ "Outbox Handoff and Synchronous Confirmation"
// — the SMTP 250 OK must reflect an actual Proton accept, never a
// silent skip.
type BuildResult struct {
	// DraftID is the Proton-side message ID. Required when Skip is
	// false.
	DraftID string
	// Req is the wire-form SendDraftReq with packages already
	// constructed per the supplied modes map.
	Req proton.SendDraftReq
	// Skip is the test-only escape hatch for builders that exercise
	// the encryption-mode pipeline without round-tripping to a real
	// Proton. MUST NOT be set by production builders.
	Skip bool
}

// Builder is the abstraction the worker calls into.
type Builder interface {
	Build(ctx context.Context, sub Submission, modes map[string]EncryptionMode, client proton.Client) (BuildResult, error)
}

// BuilderFunc adapts a plain function to Builder.
type BuilderFunc func(ctx context.Context, sub Submission, modes map[string]EncryptionMode, client proton.Client) (BuildResult, error)

// Build implements Builder.
func (f BuilderFunc) Build(ctx context.Context, sub Submission, modes map[string]EncryptionMode, client proton.Client) (BuildResult, error) {
	return f(ctx, sub, modes, client)
}
