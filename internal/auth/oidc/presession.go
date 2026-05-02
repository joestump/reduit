package oidc

import (
	"errors"
	"sync"
	"time"
)

// DefaultPreSessionTTL bounds how long a partially-completed login
// can sit between /auth/login and /auth/callback. Per the issue body,
// 10 minutes is the upper bound — enough for a real human round-trip
// (open IdP, type password, complete MFA), short enough that an
// abandoned authorize URL becomes useless quickly.
//
// Governing: issue #13 ("PKCE pre-session storage, short-lived, 10
// minute TTL"); SPEC-0005 REQ "OIDC Login Flow".
const DefaultPreSessionTTL = 10 * time.Minute

// PreSession is the server-side correlation record between the
// /auth/login redirect and the /auth/callback exchange. It carries
// just enough to validate the callback and recover the post-login
// landing target.
type PreSession struct {
	State        string
	Nonce        string
	CodeVerifier string
	ReturnTo     string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// PreSessionStore is the in-memory, TTL-bounded store of pending
// auth-code transactions. Production-scale Reduit (one host, one
// process, low login QPS) does not need a persistent store for these:
// they are 10-minute-lived and a process restart simply forces the
// user to re-click "Login". A persistent store would add complexity
// (encryption-at-rest, sweep) for negligible gain.
//
// Concurrent use is safe.
type PreSessionStore struct {
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	entries map[string]PreSession
}

// NewPreSessionStore returns a fresh in-memory store. Pass ttl=0 to
// use DefaultPreSessionTTL.
func NewPreSessionStore(ttl time.Duration) *PreSessionStore {
	if ttl <= 0 {
		ttl = DefaultPreSessionTTL
	}
	return &PreSessionStore{
		ttl:     ttl,
		now:     time.Now,
		entries: make(map[string]PreSession),
	}
}

// ErrPreSessionNotFound is returned when state is unknown or expired.
var ErrPreSessionNotFound = errors.New("oidc: pre-session not found or expired")

// Put records a pre-session keyed by state. CreatedAt and ExpiresAt
// are set automatically; callers should fill State / Nonce /
// CodeVerifier / ReturnTo and leave the timestamps zero.
func (s *PreSessionStore) Put(p PreSession) {
	now := s.now()
	p.CreatedAt = now
	p.ExpiresAt = now.Add(s.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[p.State] = p
}

// Take atomically loads-and-deletes a pre-session. The pre-session
// is single-use: a successful callback consumes it; a re-replayed
// callback (e.g. the user double-clicks) returns ErrPreSessionNotFound
// the second time. Expired entries also return ErrPreSessionNotFound
// and are removed in passing.
func (s *PreSessionStore) Take(state string) (PreSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.entries[state]
	if !ok {
		return PreSession{}, ErrPreSessionNotFound
	}
	delete(s.entries, state)
	if s.now().After(p.ExpiresAt) {
		return PreSession{}, ErrPreSessionNotFound
	}
	return p, nil
}

// SweepExpired removes every entry whose ExpiresAt has passed and
// returns the number of entries deleted. Callers MAY run this on a
// timer; functionally Take() also drops expired entries on access,
// so the sweep is just memory hygiene.
func (s *PreSessionStore) SweepExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for k, p := range s.entries {
		if now.After(p.ExpiresAt) {
			delete(s.entries, k)
			n++
		}
	}
	return n
}

// Len reports the current number of stored pre-sessions. Test-only
// helper; production callers don't need it.
func (s *PreSessionStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}
