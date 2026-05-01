package imapserver

import (
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"
)

// TestRateLimiterTTLScalesWithBackoff confirms an entry currently in
// a long backoff window stays in the map across the base evictAfter
// (otherwise the gc would silently reset attacker counters mid-attack).
func TestRateLimiterTTLScalesWithBackoff(t *testing.T) {
	t.Parallel()
	limiter := newAuthRateLimiter()
	now := time.Unix(0, 0)
	limiter.now = func() time.Time { return now }
	limiter.sleep = func(time.Duration) {}
	// Disable rate-limited GC so each RecordFailure call below actually
	// runs the sweep (the test is exercising the per-entry TTL logic,
	// not the gcInterval rate-limiting).
	limiter.gcInterval = 0

	// Push the entry well past the free-attempt budget so gc's TTL
	// scaling kicks in.
	for i := 0; i < limiter.free+5; i++ {
		now = now.Add(1 * time.Second)
		limiter.RecordFailure("attacker")
	}
	failures := limiter.entries["attacker"].failures
	if failures != limiter.free+5 {
		t.Fatalf("failures = %d, want %d", failures, limiter.free+5)
	}

	// Advance to evictAfter + 1 minute. Without TTL scaling, gc would
	// drop the entry; with scaling, the entry survives because the
	// backoff window for `failures = free+5` is far longer than the
	// base evictAfter.
	now = now.Add(limiter.evictAfter + 1*time.Minute)
	limiter.RecordFailure("other") // triggers gcLocked
	if _, present := limiter.entries["attacker"]; !present {
		t.Errorf("high-failure entry should survive base TTL because backoff window is longer")
	}
}

// TestRateLimiterEntryCap exercises the LRU-eviction path in
// authRateLimiter.RecordFailure. Adding maxEntries+1 distinct keys
// must not grow the map past maxEntries; the oldest (least-recently-
// seen) entry is evicted to make room. This bounds memory under
// IPv6 /64 rotation attacks.
func TestRateLimiterEntryCap(t *testing.T) {
	t.Parallel()
	limiter := newAuthRateLimiter()
	limiter.maxEntries = 4 // shrink for the test
	// Use a controllable clock so eviction order is deterministic.
	now := time.Unix(0, 0)
	limiter.now = func() time.Time { return now }
	limiter.sleep = func(time.Duration) {}

	for i := 0; i < 4; i++ {
		now = time.Unix(int64(i), 0)
		limiter.RecordFailure(fmt.Sprintf("ip-%d", i))
	}
	if got := len(limiter.entries); got != 4 {
		t.Fatalf("at cap: len = %d, want 4", got)
	}

	// Insert a fifth distinct key. ip-0 (oldest lastSeen) must be
	// evicted to make room.
	now = time.Unix(100, 0)
	limiter.RecordFailure("ip-4")
	if got := len(limiter.entries); got != 4 {
		t.Errorf("after eviction: len = %d, want 4 (cap)", got)
	}
	if _, present := limiter.entries["ip-0"]; present {
		t.Errorf("ip-0 should have been evicted as the oldest entry")
	}
	if _, present := limiter.entries["ip-4"]; !present {
		t.Errorf("ip-4 should be present after insertion")
	}
}

// TestNonPlainSASLRecordsRateLimitFailure ensures that an
// AUTHENTICATE GSSAPI / CRAM-MD5 attempt records a per-IP failure for
// rate-limiting purposes, not just a log line. Credential stuffing is
// not picky about mechanism names; without this, an attacker spamming
// non-PLAIN mechanisms would get unlimited retry plus log churn.
//
// The path is verified at the unit level: we construct a Backend
// directly, drive its Authenticate hook with a non-PLAIN mechanism,
// and assert the failure was recorded in the rate limiter. Black-box
// driving via the network would tip into the exponential back-off
// after the 5-attempt free budget, ballooning the test wall time.
func TestNonPlainSASLRecordsRateLimitFailure(t *testing.T) {
	t.Parallel()
	stub := newStubAccounts()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend, err := NewBackend(stub, NewSessions(), logger)
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	sess := &session{
		backend: backend,
		remote:  "192.0.2.1:1234",
		rateKey: "192.0.2.1",
		logger:  logger,
	}

	// Pre-condition: limiter has zero failures for our key.
	if got := backend.rateLimit.entries[sess.rateKey]; got != nil {
		t.Fatalf("limiter pre-state: entry exists, want none")
	}

	// Drive Authenticate with a banned mechanism. The expected return
	// is (nil, ErrAuthFailed) and the limiter must show one failure.
	srv, err := sess.Authenticate("GSSAPI")
	if srv != nil || err != ErrAuthFailed {
		t.Errorf("Authenticate(GSSAPI) = (%v, %v), want (nil, ErrAuthFailed)", srv, err)
	}
	entry := backend.rateLimit.entries[sess.rateKey]
	if entry == nil {
		t.Fatalf("limiter post-state: no entry for %q — RecordFailure was not called", sess.rateKey)
	}
	if entry.failures != 1 {
		t.Errorf("limiter failures = %d, want 1", entry.failures)
	}

	// A second non-PLAIN attempt must increment the counter.
	_, _ = sess.Authenticate("CRAM-MD5")
	if got := backend.rateLimit.entries[sess.rateKey].failures; got != 2 {
		t.Errorf("limiter failures after second attempt = %d, want 2", got)
	}
}
