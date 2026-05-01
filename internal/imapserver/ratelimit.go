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
// resets the counter; entries idle for longer than evictAfter are
// garbage-collected on the next failure observation so the map cannot
// grow unbounded under sustained scanning.
//
// Governing: SPEC-0003 Security checklist (rate limiting on auth
// attempts — full rate limit lands in v0.5; this is the placeholder).

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

	// Tunables exposed for tests.
	free       int
	base       time.Duration
	maxDelay   time.Duration
	evictAfter time.Duration
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

// RecordFailure increments the failure counter for the key.
func (l *authRateLimiter) RecordFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e, ok := l.entries[key]
	if !ok {
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

func (l *authRateLimiter) gcLocked(now time.Time) {
	for k, e := range l.entries {
		if now.Sub(e.lastSeen) > l.evictAfter {
			delete(l.entries, k)
		}
	}
}
