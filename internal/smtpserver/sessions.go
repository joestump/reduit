// Live-session registry. Every authenticated session registers itself
// here at AUTH-success time and unregisters at Logout time, indexed by
// account ID. The `DropForAccount` fan-out (suspension SLA) lands in
// a follow-up commit; this initial version exposes only the
// register/unregister/count surface the backend needs to compile.
//
// Governing: SPEC-0004 REQ "Per-Session Authentication Lifetime".

package smtpserver

import (
	"sync"
)

// Sessions is the live-session registry. The zero value is not
// usable; construct via NewSessions.
type Sessions struct {
	mu     sync.RWMutex
	byAcct map[string]map[*session]struct{}
}

// NewSessions returns an empty registry.
func NewSessions() *Sessions {
	return &Sessions{
		byAcct: make(map[string]map[*session]struct{}),
	}
}

// register adds s to the registry under accountID. Idempotent.
func (r *Sessions) register(accountID string, s *session) {
	if accountID == "" || s == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	set, ok := r.byAcct[accountID]
	if !ok {
		set = make(map[*session]struct{})
		r.byAcct[accountID] = set
	}
	set[s] = struct{}{}
}

// unregister removes s from the registry under accountID.
func (r *Sessions) unregister(accountID string, s *session) {
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

// CountForAccount returns how many live sessions are tracked.
func (r *Sessions) CountForAccount(accountID string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byAcct[accountID])
}
