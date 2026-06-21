// Per-IP exponential-backoff rate limiter for failed authentications.
//
// This is a placeholder for the v0.5 rate-limit subsystem. The full
// design (sliding-window per-account + per-IP, persisted across
// restarts, configurable thresholds) is out of scope for v0.2. What
// lives here is just enough to make trivial credential-stuffing
// noticeably slow without persisting any state.
//
// Algorithm: keep a per-IP counter of consecutive failed auth
// attempts. After N (=5) failures the next attempt is delayed by
// `base * 2^(failures-N)` capped at maxDelay. A successful auth
// resets the counter; entries idle for longer than evictAfter (which
// itself scales with the current backoff window) are garbage-collected
// on the next failure observation so the map cannot grow unbounded.
//
// Bounded memory: an attacker controlling an IPv6 /64 has 2^64 source
// addresses and could otherwise spray the map full of singleton entries.
// We cap the live entry count at rateLimitMaxEntries and evict the
// least-recently-seen entry when the cap is hit. Eviction is O(N) but
// only fires at the cap boundary, and the scan happens under the
// limiter lock — acceptable at the v0.2 scale; the v0.5 rewrite will
// move to a sharded LRU.
//
// Defensive hardening for SPEC-0003 REQ "SASL PLAIN Authentication
// With user@host Identity": rate-limiting repeated failed
// authentications slows credential stuffing without leaking which
// failure mode occurred (the spec's "Authentication failure returns
// NO with no detail" scenario). SPEC-0003 does not itself mandate a
// rate limiter; the full rate-limit subsystem lands in v0.5 and this
// is the placeholder.

package imapserver

import (
	"sync"
	"time"
)

const (
	rateLimitFreeAttempts = 5               // first N failures incur no delay
	rateLimitBase         = 1 * time.Second // delay after the first throttled failure
	rateLimitMax          = 60 * time.Second
	rateLimitEvictAfter   = 10 * time.Minute
	// rateLimitMaxEntries caps the live map size. Picked to bound memory
	// at ~1MB even with the per-entry struct + map overhead (~80 bytes
	// per entry × 10k = 800KB). When the cap is hit, the
	// least-recently-seen entry is evicted to make room for the new one.
	rateLimitMaxEntries = 10_000
)

type rateLimiterEntry struct {
	failures int
	lastSeen time.Time
}

// authRateLimiter is the in-memory failure counter. Safe for
// concurrent use. Construct with newAuthRateLimiter.
type authRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rateLimiterEntry
	now     func() time.Time
	sleep   func(time.Duration)
	lastGC  time.Time

	// Tunables exposed for tests.
	free       int
	base       time.Duration
	maxDelay   time.Duration
	evictAfter time.Duration
	maxEntries int
	gcInterval time.Duration
}

func newAuthRateLimiter() *authRateLimiter {
	return &authRateLimiter{
		entries:    make(map[string]*rateLimiterEntry),
		now:        time.Now,
		sleep:      time.Sleep,
		free:       rateLimitFreeAttempts,
		base:       rateLimitBase,
		maxDelay:   rateLimitMax,
		evictAfter: rateLimitEvictAfter,
		maxEntries: rateLimitMaxEntries,
		// gcInterval bounds how often the O(N) sweep runs. Without
		// this, every Throttle / RecordFailure call would scan the
		// whole map under the global lock — a perf cliff under
		// attack. 30s is short enough that an evictable entry never
		// lingers more than 30s past its window, while keeping
		// per-call cost amortised at O(1) under load.
		gcInterval: 30 * time.Second,
	}
}

// Throttle blocks for the per-key cooldown duration if the key has
// exceeded the free-attempt budget. Returns the delay actually
// applied (zero when no throttling). It is safe to call from any
// goroutine.
func (l *authRateLimiter) Throttle(key string) time.Duration {
	l.mu.Lock()
	now := l.now()
	l.gcLocked(now)
	e, ok := l.entries[key]
	if !ok {
		l.mu.Unlock()
		return 0
	}
	delay := l.delayLocked(e.failures)
	l.mu.Unlock()
	if delay > 0 {
		l.sleep(delay)
	}
	return delay
}

// RecordFailure increments the failure counter for the key. If the
// live-entry cap is hit, the least-recently-seen entry is evicted to
// make room. This bounds memory under sustained scanning from large
// IP-address ranges (notably IPv6 /64 rotation).
func (l *authRateLimiter) RecordFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.gcLocked(now)
	e, ok := l.entries[key]
	if !ok {
		// New entry: enforce the hard cap before allocating.
		if len(l.entries) >= l.maxEntries {
			l.evictOldestLocked()
		}
		e = &rateLimiterEntry{}
		l.entries[key] = e
	}
	e.failures++
	e.lastSeen = now
}

// RecordSuccess clears the failure counter for the key.
func (l *authRateLimiter) RecordSuccess(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

func (l *authRateLimiter) delayLocked(failures int) time.Duration {
	if failures <= l.free {
		return 0
	}
	exp := failures - l.free
	if exp > 16 { // 2^16 seconds is well past maxDelay; clamp to avoid overflow
		exp = 16
	}
	d := l.base << (exp - 1)
	if d <= 0 || d > l.maxDelay {
		return l.maxDelay
	}
	return d
}

// gcLocked drops entries whose backoff window has long since lapsed.
// Per-entry TTL = evictAfter × 2^(failures-free-1) so an entry that
// is currently in a 60-second backoff stays around for at least one
// full cycle before eviction. This stops a high-failure-count entry
// from being silently evicted between Throttle calls.
//
// The full sweep is rate-limited via gcInterval — without that, every
// Throttle call would be O(N) under the global lock, which becomes a
// perf cliff at the maxEntries cap.
func (l *authRateLimiter) gcLocked(now time.Time) {
	if l.gcInterval > 0 && now.Sub(l.lastGC) < l.gcInterval {
		return
	}
	l.lastGC = now
	for k, e := range l.entries {
		ttl := l.evictAfter
		if e.failures > l.free {
			scale := e.failures - l.free
			if scale > 16 {
				scale = 16
			}
			scaled := l.evictAfter << (scale - 1)
			if scaled > ttl {
				ttl = scaled
			}
		}
		if now.Sub(e.lastSeen) > ttl {
			delete(l.entries, k)
		}
	}
}

// evictOldestLocked deletes the single entry with the oldest lastSeen
// timestamp. Called when the live map is at maxEntries and a new key
// needs to be inserted. O(N) but only fires at the cap boundary.
func (l *authRateLimiter) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, e := range l.entries {
		if first || e.lastSeen.Before(oldest) {
			oldestKey = k
			oldest = e.lastSeen
			first = false
		}
	}
	if oldestKey != "" {
		delete(l.entries, oldestKey)
	}
}
