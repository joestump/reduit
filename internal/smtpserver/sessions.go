// Live-session registry. Every authenticated session registers itself
// here at AUTH-success time and unregisters at Logout time, indexed by
// account ID. Suspension and deletion paths walk the per-account list
// and call dropper functions to emit `421 4.7.1 Account suspended` and
// force-close the connection.
//
// Mirrors internal/imapserver/sessions.go — see that file for the full
// fan-out / per-session-deadline / WaitGroup-deadline rationale.
//
// Governing: SPEC-0004 REQ "Per-Session Authentication Lifetime"
// (suspension drops live SMTP sessions within 1 second).

package smtpserver

import (
	"sync"
	"time"
)

// dropTotalDeadline bounds the total wall-clock cost of DropForAccount.
// SPEC-0004 mandates suspended-account sessions terminate within 1
// second; we set the budget here and forcibly close any session whose
// goroutine is still running at the deadline.
const dropTotalDeadline = 1 * time.Second

// dropPerSessionDeadline bounds how long any single session's drop
// goroutine is allowed to monopolise its dropper. After this expires
// the underlying connection is hard-closed without waiting for the
// `421` write to flush. Set comfortably below dropTotalDeadline so
// even a stuck write does not keep the registry from clearing.
const dropPerSessionDeadline = 750 * time.Millisecond

// sessionDropper is the callback shape every registered session
// installs. `dropWith421` MUST attempt to emit `421 4.7.1 <reason>`
// on the wire and close the underlying connection; `forceClose`
// MUST hard-close the underlying TCP/TLS conn without acquiring any
// SMTP write locks (used as the deadline-expiry fallback when a slow
// client wedges the response write).
//
// Implementations live on *session; the interface is exposed here so
// unit tests can register fakes.
type sessionDropper interface {
	dropWith421(reason string)
	forceClose()
}

// Sessions is the live-session registry. The zero value is not
// usable; construct via NewSessions.
//
// Every method is safe for concurrent use across an arbitrary number
// of producers (Auth / Logout path) and a single suspension caller.
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
// emit `421 4.7.1 <reason>` and close its connection. The whole call
// returns within `dropTotalDeadline` (1s) regardless of how slow any
// individual client is — sessions whose drop goroutine has not
// completed by then have their underlying TCP/TLS conn hard-closed
// via `forceClose`, which does not acquire the per-connection write
// mutex and therefore cannot be wedged by a stuck mid-DATA write.
//
// Callers SHOULD hold no other locks across this call.
//
// Governing: SPEC-0004 REQ "Per-Session Authentication Lifetime"
// (suspension drops live SMTP sessions within 1 second).
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
	// drop write with a per-session deadline; if the deadline expires,
	// we hard-close the underlying conn via forceClose().
	var wg sync.WaitGroup
	for s := range set {
		wg.Add(1)
		go func(s sessionDropper) {
			defer wg.Done()
			done := make(chan struct{})
			go func() {
				s.dropWith421(reason)
				close(done)
			}()
			select {
			case <-done:
				// 421 wrote and conn closed cleanly.
			case <-time.After(dropPerSessionDeadline):
				// The write is wedged (e.g., slow client mid-DATA
				// holding the underlying conn write). Force the conn
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
		for s := range set {
			s.forceClose()
		}
	}
	return len(set)
}
