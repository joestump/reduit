// Goroutine-leak coverage for the outbox package. Worker.Submit spins
// up at least two categories of long-lived goroutines (the per-Submit
// child holding a semaphore slot, and the post-shutdown drain). Any
// goroutine that survives Manager.Shutdown will fail the test binary
// here rather than slipping past per-test cleanup.
//
// Mirrors internal/sync and internal/pubsub conventions.
//
// Governing: SPEC-0004 REQ "Outbox Handoff and Synchronous
// Confirmation" — synchronous-first means no orphan goroutines after
// the synchronous waiter returns.

package outbox

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
