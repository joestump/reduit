// Per-IP exponential-backoff rate limiter for failed authentications.
// Mirrors internal/imapserver/ratelimit.go — see that file for the
// full design rationale (bounded map + LRU + scaled TTL).
//
// Mirroring rather than extracting is deliberate at the v0.2 surface:
// two callers, ~150 lines, and a hostile reviewer flagging "over-
// abstraction for a 2-caller surface" would be correct. The v0.5
// rate-limit subsystem will do a sharded LRU rewrite that absorbs
// both packages.
//
// Governing: SPEC-0004 Security checklist (rate limiting on auth
// attempts — full rate limit lands in v0.5; this is the placeholder).

package smtpserver

import (
	"sync"
	"time"
)

const (
	rateLimitFreeAttempts = 5               // first N failures incur no delay
	rateLimitBase         = 1 * time.Second // delay after the first throttled failure
	rateLimitMax          = 60 * time.Second
	rateLimitEvictAfter   = 10 * time.Minute
	// rateLimitMaxEntries caps the live map size. ~1MB even with the
	// per-entry struct + map overhead (~80 bytes per entry × 10k =
	// 800KB). At the cap, the least-recently-seen entry is evicted to
	// make room for the new one — bounds memory under sustained
	// scanning from large IP-address ranges (notably IPv6 /64 rotation).
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
// make room.
func (l *authRateLimiter) RecordFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.gcLocked(now)
	e, ok := l.entries[key]
	if !ok {
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
// full cycle before eviction.
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
// timestamp. O(N) but only fires at the cap boundary.
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
