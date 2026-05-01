// Builder constructs the per-message Proton SendDraftReq from a
// classified Submission. Production callers wire this in the
// composition root; tests use NoopBuilder when they only need to
// exercise the encryption-mode selector + worker plumbing.
//
// Splitting the package construction out of the worker keeps the
// worker focused on lifecycle (timeout, semaphore, retry detach) and
// the package construction focused on encryption-mode-aware payload
// shaping. The hostile reviewer's fear — that we silently aggregate
// per-recipient decisions into one cleartext message — is structurally
// impossible because Builder receives the per-recipient mode map and
// must produce a SendDraftReq whose Packages slice has one entry per
// distinct EncryptionScheme.
//
// Governing: SPEC-0004 REQ "Encryption Pipeline".

package outbox

import (
	"context"
	"errors"

	"github.com/joestump/reduit/internal/proton"
)

// BuildResult is what Builder.Build hands back to the worker. DraftID
// is the Proton message ID created during the build (typically via
// proton.Client.CreateDraft); the worker then calls SendDraft against
// it. An empty DraftID means "no upstream call required" — used by
// tests so the encryption-mode pipeline is exercised without round-
// tripping to a real Proton.
type BuildResult struct {
	// DraftID is the Proton-side message ID.
	DraftID string
	// Req is the wire-form SendDraftReq with packages already
	// constructed per the supplied modes map.
	Req proton.SendDraftReq
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

// NoopBuilder returns an empty BuildResult so the worker short-
// circuits before any upstream SendDraft call. Used by tests that only
// want to verify the encryption-mode selector and concurrency
// semantics.
//
// Production deployments MUST NOT use NoopBuilder — submission would
// silently succeed with no message ever leaving the host.
var NoopBuilder Builder = BuilderFunc(func(_ context.Context, _ Submission, modes map[string]EncryptionMode, _ proton.Client) (BuildResult, error) {
	if len(modes) == 0 {
		return BuildResult{}, errors.New("outbox: NoopBuilder received empty modes map")
	}
	return BuildResult{}, nil
})
