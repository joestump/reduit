package imapserver

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestDropForAccountMeetsSLA confirms the suspension code path returns
// within 1 second even when a slow client is wedging its per-connection
// write mutex (e.g., mid-FETCH literal). A serial-iteration drop would
// blow the SLA whenever the first session in the snapshot was stuck;
// the parallel implementation with per-session deadlines keeps the
// total cost bounded.
//
// Governing: SPEC-0003 REQ "Per-Session Authentication Lifetime".
func TestDropForAccountMeetsSLA(t *testing.T) {
	t.Parallel()
	registry := NewSessions()

	// One stuck session whose dropWithBye blocks indefinitely. This
	// simulates a slow client holding encMutex on a literal write.
	released := make(chan struct{})
	closed := make(chan struct{})
	stuck := &testDropper{
		onDrop: func(string) {
			<-released
		},
		onClose: func() {
			select {
			case <-closed:
			default:
				close(closed)
			}
		},
	}
	registry.register("acct-sla", stuck)

	// Nine fast sessions whose dropWithBye returns immediately.
	fast := make([]*testDropper, 9)
	dropCounts := make([]*int32, 9)
	for i := 0; i < 9; i++ {
		var n int32
		dropCounts[i] = &n
		ctr := &n
		fast[i] = &testDropper{
			onDrop: func(string) {
				atomic.AddInt32(ctr, 1)
			},
		}
		registry.register("acct-sla", fast[i])
	}

	if got := registry.CountForAccount("acct-sla"); got != 10 {
		t.Fatalf("expected 10 registered sessions, got %d", got)
	}

	start := time.Now()
	dropped := registry.DropForAccount("acct-sla", "Account suspended")
	elapsed := time.Since(start)

	if dropped != 10 {
		t.Errorf("DropForAccount returned %d, want 10", dropped)
	}
	if elapsed > 1*time.Second {
		t.Errorf("DropForAccount took %v, want <= 1s — the SLA must hold even with a stuck session", elapsed)
	}

	// The stuck session must have had forceClose invoked on it.
	select {
	case <-closed:
	case <-time.After(100 * time.Millisecond):
		t.Errorf("forceClose was not called on the stuck session within 100ms of the SLA deadline")
	}

	// Every fast session must have received its BYE.
	for i, n := range dropCounts {
		if got := atomic.LoadInt32(n); got != 1 {
			t.Errorf("fast session %d: dropWithBye called %d times, want 1", i, got)
		}
	}

	// Release the stuck dropper so its goroutine can unwind. (The test
	// would pass without this, but leaking goroutines triggers -race
	// noise on subsequent tests.)
	close(released)
}
