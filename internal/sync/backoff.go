// Governing: SPEC-0002 REQ "Backoff on Failure".

package sync

import (
	"context"
	"math/rand/v2"
	"time"
)

// Default backoff tunables. Per SPEC-0002 REQ "Backoff on Failure":
//
//	delay = uniform(0, min(maxDelay, baseDelay * 2^attempt))
//
// The values match the spec verbatim. Operators MAY override via
// Config.Backoff* fields on the supervisor.
const (
	// DefaultBackoffBase is the lower envelope of the exponential
	// curve. The first failure (attempt 0) draws a delay from
	// `[0, base)` = `[0, 1s)`, the second from `[0, 2s)`, etc.
	DefaultBackoffBase = 1 * time.Second

	// DefaultBackoffMax is the cap. Without a cap, attempt 13 would
	// already exceed an hour. SPEC-0002 fixes this at 5min.
	DefaultBackoffMax = 5 * time.Minute

	// maxBackoffShift bounds 2^attempt before we cap. Without it, a
	// pathologically high attempt counter could overflow int64 inside
	// the int64(base) << attempt computation. 30 is safe for any
	// base <= 5min (5min << 30 ≈ 170 years; well past int64 limits
	// only beyond shift 32+, but we cap conservatively to 30 so the
	// math stays trivially correct under any base operators might
	// configure).
	maxBackoffShift = 30
)

// backoff tracks the consecutive-failure counter for one worker and
// computes the next sleep duration on demand. It is single-goroutine
// (the worker.run loop is the only caller); no synchronisation.
//
// The randomness source is parameterised so tests can pin a seed and
// assert exact durations. The clock is parameterised for the same
// reason — Sleep blocks on a real timer in production but tests can
// inject a deterministic sleeper.
//
// Governing: SPEC-0002 REQ "Backoff on Failure" — full-jitter
// exponential backoff with reset-on-success.
type backoff struct {
	base    time.Duration
	max     time.Duration
	attempt int

	// rand returns a uniform float64 in [0,1). Tests inject a
	// deterministic source; production uses math/rand/v2's global
	// generator.
	rand func() float64
}

// newBackoff constructs a backoff with the supplied base and max. A
// non-positive base or max falls back to the package defaults so a
// zero-valued Config still produces a usable backoff.
func newBackoff(base, max time.Duration, randFn func() float64) *backoff {
	if base <= 0 {
		base = DefaultBackoffBase
	}
	if max <= 0 {
		max = DefaultBackoffMax
	}
	if max < base {
		// Pathological config: an operator who set max < base would
		// otherwise observe attempt-1 delays clipped to max while the
		// curve was supposed to start there. Snap max up to base so
		// the spec's "delay <= max" invariant holds without surprising
		// the caller with a "you misconfigured me" panic.
		max = base
	}
	if randFn == nil {
		randFn = rand.Float64
	}
	return &backoff{
		base: base,
		max:  max,
		rand: randFn,
	}
}

// next returns the duration to wait before the next retry, then
// advances the attempt counter. Delay distribution matches SPEC-0002:
//
//	delay = uniform(0, min(max, base * 2^attempt))
//
// The first call (attempt=0) draws from [0, base) = [0, 1s).
// Subsequent calls double the upper bound until it hits max.
//
// `attempt` is incremented BEFORE returning so a caller that does
// "compute, sleep, retry, on-fail-recompute" sees a strictly
// non-decreasing curve (modulo jitter) across consecutive failures.
func (b *backoff) next() time.Duration {
	shift := b.attempt
	if shift > maxBackoffShift {
		shift = maxBackoffShift
	}
	upper := time.Duration(int64(b.base) << shift)
	if upper <= 0 || upper > b.max {
		// Either we overflowed (shift was too aggressive for this
		// base) or we exceeded the configured cap. Either way: cap.
		upper = b.max
	}
	// upper is the EXCLUSIVE upper bound per the spec's
	// uniform(0, X) notation. rand.Float64() returns [0, 1) so
	// jitter * upper is in [0, upper).
	delay := time.Duration(b.rand() * float64(upper))
	b.attempt++
	return delay
}

// reset clears the consecutive-failure counter. The worker calls
// this after a successful processOnce so the curve restarts from
// `base` on the next failure rather than continuing to climb.
//
// Governing: SPEC-0002 REQ "Backoff on Failure" — "Failure counter
// resets on success".
func (b *backoff) reset() {
	b.attempt = 0
}

// attempts returns the current consecutive-failure count. Exposed for
// tests; production code does not introspect.
func (b *backoff) attempts() int { return b.attempt }

// sleepCtx blocks for d, returning early if ctx is cancelled. Returns
// ctx.Err() on early exit and nil on a clean wake. A non-positive d
// returns immediately without consulting ctx — a zero-jitter draw is a
// valid spec outcome (when rand draws 0) and we don't want to mask it
// behind a context check that would otherwise burn an extra select.
//
// The helper exists so the worker's transient-failure path can express
// the backoff sleep as a single cancel-aware line rather than
// open-coding the timer + select at every call site (worker.tick's
// retry sleep and the detached permanent-transition retry loop both
// use it).
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
