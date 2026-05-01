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
)

// sessionDropper is the callback shape every registered session
// installs. Calling it MUST emit `* BYE <reason>` on the wire and
// close the underlying connection. Implementations live on *Session;
// the interface is exposed here so unit tests can register fakes.
type sessionDropper interface {
	dropWithBye(reason string)
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
// removes them from the registry, and asks each one to emit
// `* BYE <reason>` and close its connection. The caller's goroutine
// returns once every dropper has been signalled; the actual
// connection close happens asynchronously inside each session's own
// goroutine but is guaranteed to be observed within the
// SPEC-0003-mandated 1 second under normal network conditions.
//
// Callers SHOULD hold no other locks across this call.
func (r *Sessions) DropForAccount(accountID, reason string) int {
	if accountID == "" {
		return 0
	}
	r.mu.Lock()
	set := r.byAcct[accountID]
	delete(r.byAcct, accountID)
	r.mu.Unlock()

	for s := range set {
		s.dropWithBye(reason)
	}
	return len(set)
}
