package smtpserver

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestDropForAccountMeetsSLA confirms the suspension code path returns
// within 1 second even when a slow client is wedging its drop write.
// A serial-iteration drop would blow the SLA whenever the first
// session in the snapshot was stuck; the parallel implementation with
// per-session deadlines keeps the total cost bounded.
//
// Governing: SPEC-0004 REQ "Per-Session Authentication Lifetime".
func TestDropForAccountMeetsSLA(t *testing.T) {
	t.Parallel()
	registry := NewSessions()

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

	// Nine fast sessions whose dropWith421 returns immediately.
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

	select {
	case <-closed:
	case <-time.After(100 * time.Millisecond):
		t.Errorf("forceClose was not called on the stuck session within 100ms of the SLA deadline")
	}

	for i, n := range dropCounts {
		if got := atomic.LoadInt32(n); got != 1 {
			t.Errorf("fast session %d: dropWith421 called %d times, want 1", i, got)
		}
	}

	// Release the stuck dropper so its goroutine can unwind.
	close(released)
}
