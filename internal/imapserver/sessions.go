// Live-session registry. Every authenticated session registers
// itself here at Login time and unregisters at Close time, indexed by
// account ID. Suspension and deletion paths walk the per-account
// list and call dropper functions to emit `* BYE <reason>` and force
// the connection closed.
//
// The registry is intentionally separate from the imapserver.Server
// so that the suspension call site (which lives in a future admin
// handler / supervisor in #15) can hold a reference to the registry
// without pulling in the rest of the server.
//
// Governing: SPEC-0003 REQ "Per-Session Authentication Lifetime"
// (suspension drops live IMAP sessions within 1 second).

package imapserver

import (
	"sync"
	"time"
)

// dropTotalDeadline bounds the total wall-clock cost of DropForAccount.
// SPEC-0003 mandates suspended-account sessions terminate within 1
// second; we set the budget here and forcibly close any session whose
// goroutine is still running at the deadline.
const dropTotalDeadline = 1 * time.Second

// dropPerSessionDeadline bounds how long any single session's BYE-write
// is allowed to monopolise its dropper goroutine. After this expires,
// the underlying connection is hard-closed without waiting for the BYE
// write to flush. Set comfortably below dropTotalDeadline so even a
// stuck encMutex does not keep the registry from clearing.
const dropPerSessionDeadline = 750 * time.Millisecond

// sessionDropper is the callback shape every registered session
// installs. `dropWithBye` MUST attempt to emit `* BYE <reason>` on
// the wire and close the underlying connection; `forceClose` MUST
// hard-close the underlying TCP/TLS conn without acquiring any IMAP
// write locks (used as the deadline-expiry fallback when a slow
// client wedges the BYE write).
//
// Implementations live on *Session; the interface is exposed here so
// unit tests can register fakes.
type sessionDropper interface {
	dropWithBye(reason string)
	forceClose()
}

// Sessions is the live-session registry. The zero value is not
// usable; construct via NewSessions.
//
// Every method is safe for concurrent use across an arbitrary number
// of producers (Login / Close path) and a single suspension caller.
type Sessions struct {
	mu     sync.RWMutex
	byAcct map[string]map[sessionDropper]struct{}
}

// NewSessions returns an empty registry.
func NewSessions() *Sessions {
	return &Sessions{
		byAcct: make(map[string]map[sessionDropper]struct{}),
	}
}

// register adds s to the registry under accountID. Idempotent: a
// second register call for the same (accountID, s) pair is a no-op.
func (r *Sessions) register(accountID string, s sessionDropper) {
	if accountID == "" || s == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	set, ok := r.byAcct[accountID]
	if !ok {
		set = make(map[sessionDropper]struct{})
		r.byAcct[accountID] = set
	}
	set[s] = struct{}{}
}

// unregister removes s from the registry under accountID. Safe to
// call for a session that was never registered (e.g., never reached
// the authenticated state).
func (r *Sessions) unregister(accountID string, s sessionDropper) {
	if accountID == "" || s == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	set, ok := r.byAcct[accountID]
	if !ok {
		return
	}
	delete(set, s)
	if len(set) == 0 {
		delete(r.byAcct, accountID)
	}
}

// CountForAccount returns how many live sessions are tracked for the
// given account. Mostly useful for tests and admin diagnostics.
func (r *Sessions) CountForAccount(accountID string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byAcct[accountID])
}

// DropForAccount snapshots the current set of sessions for accountID,
// removes them from the registry, and concurrently asks each one to
// emit `* BYE <reason>` and close its connection. The whole call
// returns within `dropTotalDeadline` (1s) regardless of how slow any
// individual client is — sessions whose BYE-write goroutine has not
// completed by then have their underlying TCP/TLS conn hard-closed
// via `forceClose`, which does not acquire the per-connection write
// mutex and therefore cannot be wedged by a stuck literal write.
//
// Callers SHOULD hold no other locks across this call.
//
// Governing: SPEC-0003 REQ "Per-Session Authentication Lifetime"
// (suspension drops live IMAP sessions within 1 second). The previous
// serial implementation could blow the SLA whenever a single session
// at the front of the iteration was holding its encMutex on a slow
// literal write — total cost was unbounded. Fan-out + per-session +
// top-level deadline + force-close fallback recovers the SLA.
func (r *Sessions) DropForAccount(accountID, reason string) int {
	if accountID == "" {
		return 0
	}
	r.mu.Lock()
	set := r.byAcct[accountID]
	delete(r.byAcct, accountID)
	r.mu.Unlock()

	if len(set) == 0 {
		return 0
	}

	// Launch one goroutine per session. Each goroutine attempts the
	// BYE write with a per-session deadline; if the deadline expires,
	// we hard-close the underlying conn via forceClose().
	var wg sync.WaitGroup
	for s := range set {
		wg.Add(1)
		go func(s sessionDropper) {
			defer wg.Done()
			done := make(chan struct{})
			go func() {
				s.dropWithBye(reason)
				close(done)
			}()
			select {
			case <-done:
				// BYE wrote and conn closed cleanly.
			case <-time.After(dropPerSessionDeadline):
				// The BYE write is wedged (e.g., slow client mid-
				// FETCH literal holding encMutex). Force the conn
				// closed; the in-flight write goroutine will then
				// observe the closed conn and unwind.
				s.forceClose()
			}
		}(s)
	}

	// Top-level deadline guards against pathological cases where even
	// forceClose blocks (it should not — it calls net.Conn.Close which
	// is non-blocking on stdlib types — but we keep the belt-and-
	// suspenders so the SLA is structurally enforced).
	allDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(allDone)
	}()
	select {
	case <-allDone:
	case <-time.After(dropTotalDeadline):
		// Hard-close anything still hanging. We do this here rather
		// than waiting for the per-session goroutines because the
		// caller is on the SLA hook.
		for s := range set {
			s.forceClose()
		}
	}
	return len(set)
}
