// Test-only Builder helpers. Lives in a *_test.go file so the
// production binary cannot link against them — silent-success was the
// worst failure mode the hostile reviewer flagged, and the easiest way
// to make it impossible is to remove the production-linkable seam.
//
// Production callers MUST wire a real Builder at the composition root
// (CreateDraft + per-mode MessagePackage assembly per SPEC-0004 REQ
// "Encryption Pipeline"). The follow-up issue tracks that work.
//
// Governing: SPEC-0004 REQ "Outbox Handoff and Synchronous Confirmation".

package outbox

import (
	"context"
	"errors"

	"github.com/joestump/reduit/internal/proton"
)

// noopBuilder returns BuildResult{Skip: true} so the worker exercises
// the encryption-mode selector + concurrency semantics without
// round-tripping to a real Proton SendDraft. Test-only by virtue of
// living in a _test.go file.
var noopBuilder Builder = BuilderFunc(func(_ context.Context, _ Submission, modes map[string]EncryptionMode, _ proton.Client) (BuildResult, error) {
	if len(modes) == 0 {
		return BuildResult{}, errors.New("outbox: noopBuilder received empty modes map")
	}
	return BuildResult{Skip: true}, nil
})
