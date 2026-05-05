// In-memory session store for the add-Proton-account wizard.
//
// The wizard runs across multiple HTTP round-trips. Between the
// credentials POST and the unlock POST it has to keep a live
// proton.Client (post-Auth, possibly mid-2FA) AND a copy of the
// freshly-minted refresh token. Persisting that to disk in the SCS
// session store would put bearer credentials at rest in plaintext,
// which is exactly what the spec's "encryption-at-rest" requirement
// is meant to prevent. Instead we hold it in process memory keyed by
// the pending account row's ID, with a 30-min idle TTL per
// SPEC-0005's "WHEN wizard idle 30 min ... THEN partial credentials
// discarded from memory" scenario.
//
// Sweep cadence: a janitor goroutine runs at TTL/4. Drops every
// session whose IdleAt is older than now - TTL. The sweep does NOT
// call Logout on the held proton.Client: the upstream Proton access
// token expires on its own (~30min) and a Logout call here would
// race against any in-flight handler still holding the per-session
// lock. Letting the upstream session time out on its own keeps the
// janitor's per-tick work O(map iteration) and avoids fanning out
// N concurrent HTTP calls to Proton on a single tick.
//
// If a future change wants to revoke upstream sessions on TTL
// eviction (e.g., to release Proton-side rate-limit budget faster),
// the fan-out MUST be bounded by a goroutine pool / semaphore
// (suggest 4 concurrent) so a thundering herd of evictions cannot
// saturate the Proton API or the local resty pool. Punted until
// that need is real rather than speculative.
//
// Governing: SPEC-0005 REQ "Add-Proton-Account Wizard" (idle
// expiry); ADR-0010 (per-account state); issue #81 (bounded fan-out
// design note).

package server

import (
	"sync"
	"time"

	"github.com/joestump/reduit/internal/proton"
)

// DefaultWizardIdleTimeout is the per-session inactivity window.
// SPEC-0005 mandates 30 minutes -- the same as the SCS session idle
// timeout, so a session that's idle long enough to drop the SCS
// cookie also drops the wizard side state.
const DefaultWizardIdleTimeout = 30 * time.Minute

// MaxWizardTOTPAttempts is the per-session TOTP failure budget. A
// fourth submission aborts the wizard per SPEC-0005's "three failures
// abort" scenario.
const MaxWizardTOTPAttempts = 3

// WizardStage identifies the current wizard step. The handlers branch
// on this value to refuse out-of-order POSTs (e.g., a POST /unlock
// when the session hasn't passed 2FA yet).
type WizardStage int

const (
	// WizardStageCredentials means we expect a POST /auth next. This
	// is the initial state created by GET /accounts/setup.
	WizardStageCredentials WizardStage = iota
	// WizardStageTOTP means credentials passed and Proton requires a
	// TOTP second factor.
	WizardStageTOTP
	// WizardStageUnlock means we expect a POST /unlock next.
	WizardStageUnlock
)

// WizardSession is the per-account-in-flight wizard state. Stored
// only in memory. The embedded mutex serialises mutation for the
// per-account hot path -- two concurrent POSTs from the same user
// (double-click, HTMX retry, two browser tabs) both resolve to the
// same pointer; without the lock they would race on stage/attempt
// fields and could bypass the 3-fail TOTP budget.
//
// Handlers MUST take the lock right after store.Get returns and
// hold it across the read-modify-write sequence. The store's own
// mutex protects only the map.
type WizardSession struct {
	sync.Mutex

	// AccountID is the pending account row this wizard is bound to.
	// Used as the map key.
	AccountID string
	// UserID is the owning Reduit user; we re-check it on every
	// request so a different signed-in user can't pick up someone
	// else's in-flight wizard by guessing the AccountID.
	UserID string
	// Username is the Proton login email captured at step 1.
	Username string
	// Client is the live proton session. Nil pre-auth (stage
	// Credentials) and after a successful unlock + commit. Owned
	// by this struct; the wizard handlers (and the janitor) call
	// Logout when dropping the session.
	Client proton.Client
	// RefreshToken is the freshly-minted refresh token from the
	// initial Auth response. Captured here so the unlock handler
	// can persist it via account.SealRefreshToken; the manager-level
	// callback can't carry the account ID per-call so we route this
	// token through the wizard flow explicitly.
	RefreshToken string
	// ProtonUserID is the persistent Proton account identifier
	// (auth.UserID, distinct from the session UID). Persisted onto
	// accounts.proton_user_id at unlock-success time so subsequent
	// dashboard renders show "this Reduit account is bound to that
	// Proton user".
	ProtonUserID string
	// Stage tracks where the wizard is in its lifecycle.
	Stage WizardStage
	// TOTPAttempts counts failed TOTP submissions for the abort-
	// after-3 rule.
	TOTPAttempts int
	// IdleAt is updated on every store.Touch; the janitor drops the
	// session when now - IdleAt > TTL.
	IdleAt time.Time
}

// WizardSessionStore is the process-scoped registry. Safe for
// concurrent use.
type WizardSessionStore struct {
	mu       sync.Mutex
	sessions map[string]*WizardSession
	ttl      time.Duration
	now      func() time.Time

	stopOnce sync.Once
	stopCh   chan struct{}
}

// NewWizardSessionStore returns a store with a TTL/4 janitor running.
// ttl == 0 falls back to DefaultWizardIdleTimeout.
func NewWizardSessionStore(ttl time.Duration) *WizardSessionStore {
	if ttl <= 0 {
		ttl = DefaultWizardIdleTimeout
	}
	s := &WizardSessionStore{
		sessions: make(map[string]*WizardSession),
		ttl:      ttl,
		now:      time.Now,
		stopCh:   make(chan struct{}),
	}
	go s.janitor()
	return s
}

// Stop halts the janitor goroutine. Safe to call multiple times. The
// underlying map is left intact -- callers that want to flush should
// iterate Drop themselves before Stop.
func (s *WizardSessionStore) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// janitor sweeps expired sessions every TTL/4. We do NOT call Logout
// on swept sessions: the upstream Proton access token expires on its
// own (~30min), and calling Logout here would race against any in-
// flight handler still holding the per-session lock.
func (s *WizardSessionStore) janitor() {
	tick := time.NewTicker(s.ttl / 4)
	defer tick.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-tick.C:
			s.sweep()
		}
	}
}

func (s *WizardSessionStore) sweep() {
	cutoff := s.now().Add(-s.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.IdleAt.Before(cutoff) {
			delete(s.sessions, id)
		}
	}
}

// Put stores or replaces a session. The IdleAt timestamp is set to
// now so the caller doesn't have to remember.
func (s *WizardSessionStore) Put(sess *WizardSession) {
	if sess == nil || sess.AccountID == "" {
		return
	}
	sess.IdleAt = s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.AccountID] = sess
}

// Get returns the session for accountID and refreshes its IdleAt so
// the lookup itself counts as activity. Returns (nil, false) when no
// session exists or the existing session has expired (in which case
// the expired entry is dropped in passing).
func (s *WizardSessionStore) Get(accountID string) (*WizardSession, bool) {
	if accountID == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[accountID]
	if !ok {
		return nil, false
	}
	if s.now().Sub(sess.IdleAt) > s.ttl {
		delete(s.sessions, accountID)
		return nil, false
	}
	sess.IdleAt = s.now()
	return sess, true
}

// Drop removes the session for accountID from the store. Pure map
// operation — does NOT call Logout on the held client. Callers that
// want to revoke the upstream Proton session MUST call sess.Client
// .Logout themselves, ideally while holding the per-session lock so
// they cannot race against another goroutine still using sess.Client.
// Safe to call when no session exists.
func (s *WizardSessionStore) Drop(accountID string) {
	if accountID == "" {
		return
	}
	s.mu.Lock()
	delete(s.sessions, accountID)
	s.mu.Unlock()
}
