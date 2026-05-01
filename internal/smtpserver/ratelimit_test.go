package smtpserver

import (
	"fmt"
	"testing"
	"time"
)

// TestRateLimiterTTLScalesWithBackoff confirms an entry currently in
// a long backoff window stays in the map across the base evictAfter.
func TestRateLimiterTTLScalesWithBackoff(t *testing.T) {
	t.Parallel()
	limiter := newAuthRateLimiter()
	now := time.Unix(0, 0)
	limiter.now = func() time.Time { return now }
	limiter.sleep = func(time.Duration) {}
	limiter.gcInterval = 0

	for i := 0; i < limiter.free+5; i++ {
		now = now.Add(1 * time.Second)
		limiter.RecordFailure("attacker")
	}
	failures := limiter.entries["attacker"].failures
	if failures != limiter.free+5 {
		t.Fatalf("failures = %d, want %d", failures, limiter.free+5)
	}

	now = now.Add(limiter.evictAfter + 1*time.Minute)
	limiter.RecordFailure("other")
	if _, present := limiter.entries["attacker"]; !present {
		t.Errorf("high-failure entry should survive base TTL because backoff window is longer")
	}
}

// TestRateLimiterEntryCap exercises the LRU-eviction path.
func TestRateLimiterEntryCap(t *testing.T) {
	t.Parallel()
	limiter := newAuthRateLimiter()
	limiter.maxEntries = 4
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
