package mcpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
)

// Default per-account concurrency cap and queue depth. The cap is
// configurable via MCP_PER_ACCOUNT_CONCURRENCY at server boot; the
// queue depth is fixed at 16 per SPEC-0006 REQ "Per-Account
// Concurrency Limit".
const (
	DefaultPerAccountConcurrency = 4
	DefaultQueueDepth            = 16

	// EnvPerAccountConcurrency is the environment variable Reduit
	// reads at boot to override the default cap. Per-account, NOT
	// global -- a deployment with N accounts allows up to N*cap
	// concurrent invocations.
	EnvPerAccountConcurrency = "MCP_PER_ACCOUNT_CONCURRENCY"
)

// retryAfterSeconds is the value of the Retry-After header on an
// overflow 503. Per SPEC-0006 REQ "Per-Account Concurrency Limit"
// scenario the server returns 503 with a Retry-After header; we use
// "5" seconds as a conservative default that matches design.md's
// example. The unit is seconds (HTTP-date is the alternative; integer
// is simpler and unambiguous).
const retryAfterSeconds = 5

// errOverflow is the sentinel returned by Limiter.Acquire when the
// queue depth is already saturated. Callers translate this into a 503
// + Retry-After response rather than a context-cancellation 5xx.
var errOverflow = errors.New("mcpserver: per-account queue overflow")

// Limiter caps in-flight tool invocations per account. Acquire blocks
// until a slot is free OR the queue overflows; when it overflows it
// returns errOverflow without ever holding a slot. The returned
// release func MUST be invoked exactly once on the success path.
//
// The interface lets tests inject a NoLimiter() that bypasses the cap
// entirely without polluting production code paths with `if limiter
// != nil` guards.
//
// Governing: SPEC-0006 REQ "Per-Account Concurrency Limit".
type Limiter interface {
	Acquire(ctx context.Context, accountID string) (release func(), err error)
}

// concurrencyLimiter implements Limiter with one buffered channel per
// account_id, holding `inFlightCap` "slot" tokens, plus a separate
// reservation channel of capacity `queueDepth` that gates entry to the
// slot wait. The reservation channel implements the queue: a request
// arriving when the reservation channel is full sees errOverflow and
// returns 503 immediately; a request that gets a reservation but
// can't yet take a slot blocks on slot acquisition.
//
// This composition keeps the in-flight-cap and queue-depth invariants
// explicit and decoupled. A single channel of capacity
// inFlightCap+queueDepth would also work but conflates two distinct
// limits and makes the overflow signal harder to read.
type concurrencyLimiter struct {
	inFlightCap int
	queueDepth  int

	mu    sync.Mutex
	slots map[string]*accountSlots
}

// accountSlots is the per-account state held by concurrencyLimiter.
// Two channels are used so the in-flight cap and the queue depth are
// independently observable and testable.
type accountSlots struct {
	inFlight    chan struct{} // capacity = inFlightCap
	reservation chan struct{} // capacity = inFlightCap + queueDepth
}

// NewConcurrencyLimiter constructs a Limiter with the given cap and
// queue depth. Both must be positive. Sensible callers pass
// DefaultPerAccountConcurrency / DefaultQueueDepth or values derived
// from env-var overrides at boot.
func NewConcurrencyLimiter(inFlightCap, queueDepth int) Limiter {
	if inFlightCap <= 0 {
		inFlightCap = DefaultPerAccountConcurrency
	}
	if queueDepth <= 0 {
		queueDepth = DefaultQueueDepth
	}
	return &concurrencyLimiter{
		inFlightCap: inFlightCap,
		queueDepth:  queueDepth,
		slots:       make(map[string]*accountSlots),
	}
}

// PerAccountConcurrencyFromEnv reads MCP_PER_ACCOUNT_CONCURRENCY from
// the supplied lookup func and returns a usable cap. Invalid or
// unset values fall back to DefaultPerAccountConcurrency. The lookup
// is parameterised so tests don't have to clobber the real os.Getenv;
// production callers pass os.Getenv directly.
//
// Governing: SPEC-0006 REQ "Per-Account Concurrency Limit"
// (configurable cap via MCP_PER_ACCOUNT_CONCURRENCY).
func PerAccountConcurrencyFromEnv(lookup func(string) string) int {
	if lookup == nil {
		return DefaultPerAccountConcurrency
	}
	raw := lookup(EnvPerAccountConcurrency)
	if raw == "" {
		return DefaultPerAccountConcurrency
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return DefaultPerAccountConcurrency
	}
	return n
}

// Acquire implements Limiter.
//
// Two-phase acquisition: a non-blocking "reservation" send enforces
// the queue-depth cap (capacity = inFlightCap + queueDepth so up to
// inFlightCap can be in flight while up to queueDepth more wait).
// Reservation success means we may proceed to wait for a slot; the
// blocking "slot" send enforces the in-flight cap.
//
// On overflow (reservation full) the function returns errOverflow
// without consuming any reservation -- the caller turns this into a
// 503. On context cancellation while waiting for a slot we release
// the reservation and propagate ctx.Err() so the caller can return a
// 5xx, NOT 503 (the caller hung up; that's not a backpressure signal).
func (l *concurrencyLimiter) Acquire(ctx context.Context, accountID string) (func(), error) {
	if accountID == "" {
		return nil, errors.New("mcpserver: Acquire with empty account_id")
	}
	s := l.getOrCreate(accountID)

	// Phase 1: reservation. Non-blocking; full means overflow.
	select {
	case s.reservation <- struct{}{}:
	default:
		return nil, errOverflow
	}

	// Phase 2: slot. Block until a slot frees, or ctx cancels.
	select {
	case s.inFlight <- struct{}{}:
		// release returns the reservation AND the slot in one call.
		// Both are buffered channels with non-blocking <-: receives
		// from a buffered channel with a known item are always ready.
		var once sync.Once
		return func() {
			once.Do(func() {
				<-s.inFlight
				<-s.reservation
			})
		}, nil
	case <-ctx.Done():
		// Caller cancelled before we got a slot; give back the
		// reservation so a future caller isn't penalised.
		<-s.reservation
		return nil, ctx.Err()
	}
}

func (l *concurrencyLimiter) getOrCreate(accountID string) *accountSlots {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s, ok := l.slots[accountID]; ok {
		return s
	}
	s := &accountSlots{
		inFlight:    make(chan struct{}, l.inFlightCap),
		reservation: make(chan struct{}, l.inFlightCap+l.queueDepth),
	}
	l.slots[accountID] = s
	return s
}

// reservationCount returns the number of reservations currently held
// by the supplied account_id. Returns 0 if the account has never
// been seen. Test-only inspection helper -- production callers MUST
// NOT depend on this; the value is racy by definition.
func (l *concurrencyLimiter) reservationCount(accountID string) int {
	l.mu.Lock()
	s, ok := l.slots[accountID]
	l.mu.Unlock()
	if !ok {
		return 0
	}
	return len(s.reservation)
}

// noLimiter is the test-only Limiter that bypasses every gate.
type noLimiter struct{}

// Acquire implements Limiter.Acquire by always granting an immediate
// slot. Used by tests that don't care about concurrency assertions
// and don't want to plumb a real limiter through.
func (noLimiter) Acquire(_ context.Context, _ string) (func(), error) {
	return func() {}, nil
}

// NoLimiter returns a Limiter that grants every request immediately.
// Tests that don't exercise the concurrency cap should use this; do
// NOT use it in production -- the SPEC-0006 cap is mandatory.
func NoLimiter() Limiter { return noLimiter{} }

// requireConcurrencySlot is the per-account gate middleware. It runs
// AFTER bearer auth, so the account on the request context is
// guaranteed non-nil.
//
// On overflow the response is 503 with Retry-After: 5 -- the wire
// shape SPEC-0006 specifies. Server-side log lines record the
// account_id so operators can correlate a noisy account with its
// upstream cause.
//
// Governing: SPEC-0006 REQ "Per-Account Concurrency Limit".
func requireConcurrencySlot(limiter Limiter, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acct := AccountFromContext(r.Context())
		if acct == nil {
			// Defense in depth -- if the auth middleware ever
			// short-circuits past this gate without setting an
			// account, fail closed with a 401-shaped response.
			respondUnauthenticated(w, "")
			return
		}

		release, err := limiter.Acquire(r.Context(), acct.ID)
		switch {
		case err == nil:
			defer release()
			next.ServeHTTP(w, r)

		case errors.Is(err, errOverflow):
			logger.WarnContext(r.Context(),
				"mcpserver: per-account queue overflow",
				slog.String("account_id", acct.ID))
			respondQueueOverflow(w)

		default:
			// Context cancellation or some other Acquire-time error.
			// Cancellation surfaces as a 5xx -- the caller hung up
			// or upstream timed out, neither of which is a
			// retryable backpressure signal.
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				logger.InfoContext(r.Context(),
					"mcpserver: request cancelled awaiting concurrency slot",
					slog.String("account_id", acct.ID))
				http.Error(w, "request cancelled", http.StatusGatewayTimeout)
				return
			}
			logger.ErrorContext(r.Context(),
				"mcpserver: limiter Acquire failed",
				slog.String("account_id", acct.ID),
				slog.String("error", err.Error()))
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	})
}

// respondQueueOverflow emits 503 + Retry-After: 5 + a JSON body. Per
// SPEC-0006: queue overflow SHALL return 503 Service Unavailable
// with a Retry-After header.
func respondQueueOverflow(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(`{"error":"queue_overflow"}`))
}
