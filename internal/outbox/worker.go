// Per-account outbox worker. Owns a per-account semaphore (cap default
// 4) so a single account cannot saturate the global Proton call budget,
// and bounds each Submit by the configured submission timeout.
//
// Lifecycle: workers are created lazily on first Submit per account by
// Manager.workerFor and torn down when Manager.Shutdown drains the
// supervisor.
//
// Governing: SPEC-0004 REQ "Per-Account Outbox Concurrency Limit",
// SPEC-0004 REQ "Outbox Handoff and Synchronous Confirmation".

package outbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/joestump/reduit/internal/proton"
)

// worker is the per-account submission engine.
type worker struct {
	accountID string
	mgr       *Manager

	// sem is the per-account concurrency cap. Cap=4 by default (config
	// override via REDUIT_OUTBOX_PER_ACCOUNT_CAP) prevents one rogue
	// authenticated client from holding up every Proton-call slot for
	// an account.
	sem chan struct{}

	// closed flips on Shutdown so subsequent Submit calls return
	// ErrAccountClosed without acquiring the semaphore.
	closeMu sync.RWMutex
	closed  bool

	// inflight tracks the per-Submit child goroutines (semaphore
	// holders) so Manager.Shutdown can wait for them to drain.
	inflight sync.WaitGroup
}

func newWorker(mgr *Manager, accountID string) *worker {
	capacity := mgr.cfg.PerAccountCap
	if capacity <= 0 {
		capacity = DefaultPerAccountCap
	}
	return &worker{
		accountID: accountID,
		mgr:       mgr,
		sem:       make(chan struct{}, capacity),
	}
}

// Submit performs a synchronous send: classify recipients, call
// proton.Client.SendDraft (via the resolver-supplied client), and
// return the result inside the configured submission deadline.
//
// On deadline expiry the synchronous return is ErrSubmissionTimedOut.
// The in-flight upstream child goroutine is left to unwind on its own
// (its next ctx-aware call observes the cancelled subCtx and returns)
// and the per-account semaphore slot is released by the child's defer.
// We do NOT spin up a Reduit-side retry loop: the canonical
// recovery path is the sender's MTA re-attempting the SMTP submission
// per RFC 5321, which lands as a fresh Submit on a clean ctx. A
// Reduit-side retry would be a meaningful chunk of work that bloats
// this story; it is tracked separately.
//
// Submit is safe for concurrent use across goroutines.
func (w *worker) Submit(ctx context.Context, sub Submission) Result {
	if err := validateSubmission(sub); err != nil {
		return Result{Err: err}
	}

	w.closeMu.RLock()
	if w.closed {
		w.closeMu.RUnlock()
		return Result{Err: ErrAccountClosed}
	}
	w.closeMu.RUnlock()

	timeout := w.mgr.cfg.SubmitTimeout
	if timeout <= 0 {
		timeout = DefaultSubmitTimeout
	}

	// One synchronous deadline covers BOTH the semaphore wait AND the
	// upstream submission. If the queue is saturated for >timeout the
	// SMTP server still returns within timeout, just with a 451 instead
	// of waiting forever (RFC 5321 §4.5.3.2.6 caps client patience at
	// ~10 min but most consumer clients close at ~1m).
	subCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Acquire one slot of the per-account semaphore.
	select {
	case w.sem <- struct{}{}:
	case <-subCtx.Done():
		// Either the parent ctx canceled (client disconnected) or the
		// submission deadline elapsed waiting for a slot. The SMTP
		// layer maps a deadline to 451; a parent cancel maps to 451
		// too (the connection is gone, so the response goes nowhere
		// useful, but the SMTP server's caller still sees a return
		// value).
		if errors.Is(subCtx.Err(), context.DeadlineExceeded) {
			return Result{Err: ErrSubmissionTimedOut}
		}
		return Result{Err: subCtx.Err()}
	}

	// Track this slot holder so Shutdown can wait for it.
	w.inflight.Add(1)

	// Run the actual submission on a child goroutine so the parent
	// (this Submit call) can race the subCtx deadline against
	// completion. resultCh is buffered (cap 1) so the child can send
	// its outcome and exit even if the parent has already returned
	// the timeout to the SMTP layer — no Reduit-side consumer is
	// required.
	resultCh := make(chan Result, 1)
	go func() {
		defer func() {
			// Slot release happens here, NOT in the parent. If the
			// parent timed out and the child is still unwinding, the
			// slot remains held until the upstream call observes the
			// cancelled subCtx and returns — otherwise a slow Proton
			// call would let an extra send through the cap on its way
			// out.
			<-w.sem
			w.inflight.Done()
		}()
		// Recover panics inside w.run (e.g. the fail-loud empty-DraftID
		// guard) so a misconfigured Builder surfaces as a typed error
		// rather than crashing the process. The panic is converted to
		// *ErrProtonReject (SMTP 550) — a permanent reject is the right
		// signal for "the operator wired the outbox wrong"; the sender
		// shouldn't retry.
		defer func() {
			if r := recover(); r != nil {
				err := errors.New("outbox: worker panic: " + panicString(r))
				w.mgr.cfg.Logger.LogAttrs(context.Background(), slog.LevelError,
					"outbox: worker panic recovered",
					slog.String("event", "outbox_worker_panic"),
					slog.String("account_id", sub.AccountID),
					slog.Any("panic", r),
				)
				resultCh <- Result{Err: &ErrProtonReject{Cause: err}}
			}
		}()
		resultCh <- w.run(subCtx, sub)
	}()

	select {
	case r := <-resultCh:
		return r
	case <-subCtx.Done():
		// Synchronous waiter abandons the in-flight call. The child
		// goroutine above will observe subCtx.Done() on its next
		// ctx-aware call (GetPublicKeys / SendDraft), drop its result
		// into the buffered resultCh, and exit — releasing the slot in
		// the deferred sem read. Best-effort audit: record that the
		// SMTP-visible outcome was a timeout. The sender's MTA retries
		// the SMTP submission per RFC 5321, which is the canonical
		// recovery path; Reduit does not attempt its own retry.
		//
		// Governing: SPEC-0004 REQ "Outbox Handoff and Synchronous
		// Confirmation" — synchronous-first, no Reduit-side retry.
		if errors.Is(subCtx.Err(), context.DeadlineExceeded) {
			// Fire-and-forget the audit row; PendingStore writes are
			// best-effort and the worker should not block returning
			// the 451 on a SQLite write.
			w.recordTimeout(sub, ErrSubmissionTimedOut)
			return Result{Err: ErrSubmissionTimedOut}
		}
		return Result{Err: subCtx.Err()}
	}
}

// recordTimeout writes a best-effort audit row for the timeout-
// abandoned submission. Errors are intentionally swallowed: the audit
// table is operator-visible context, not a delivery guarantee.
func (w *worker) recordTimeout(sub Submission, cause error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.mgr.cfg.PendingStore.RecordTimeout(ctx, sub, cause); err != nil {
		w.mgr.cfg.Logger.LogAttrs(context.Background(), slog.LevelWarn,
			"outbox: pending-store write failed",
			slog.String("event", "outbox_pending_store_failed"),
			slog.String("account_id", sub.AccountID),
			slog.Any("err", err),
		)
	}
}

// run is the actual upstream call sequence. Splits the
// classification (SelectMode) from the submission so an encryption-
// mode error can short-circuit before any SendDraft round-trip.
func (w *worker) run(ctx context.Context, sub Submission) Result {
	client, err := w.mgr.cfg.Resolver.ResolveClient(sub.AccountID)
	if err != nil {
		return Result{Err: classifyClientError(err)}
	}

	modes, err := SelectMode(ctx, client, sub.Recipients)
	if err != nil {
		// SelectMode already returns the typed *ErrKeyLookup. The SMTP
		// layer maps this to 451 (transient — sender retries) so a
		// flaky Proton key endpoint doesn't manifest as a hard 5xx.
		w.logEncryptionDecision(sub, nil, err)
		return Result{Err: err}
	}

	w.logEncryptionDecision(sub, modes, nil)

	// Builder constructs the per-recipient encryption packet set and
	// returns the Proton DraftID to submit against. Production builders
	// MUST return a non-empty DraftID; the test-only Skip flag is the
	// only legitimate way to bypass the SendDraft call.
	req, err := w.mgr.cfg.Builder.Build(ctx, sub, modes, client)
	if err != nil {
		return Result{Modes: modes, Err: classifyBuilderError(err)}
	}

	// Test-only skip: a recording builder exercises the encryption
	// pipeline without round-tripping to a real Proton. Any production
	// Builder that sets Skip=true is a bug (it would surface as a fake
	// 250 OK with no message ever sent), but the responsibility for
	// that boundary is the composition root's, not the worker's.
	if req.Skip {
		return Result{Modes: modes}
	}

	// Fail-loud guard: an empty DraftID with Skip=false is a programming
	// error (a Builder that forgot to call CreateDraft, or a test
	// builder that should have set Skip=true). Panicking here surfaces
	// the misconfiguration immediately rather than letting a silent
	// success ship to the SMTP layer as 250 OK.
	//
	// Governing: SPEC-0004 REQ "Outbox Handoff and Synchronous
	// Confirmation" — silent-success is the worst failure mode; fail
	// loud at the worker boundary.
	if req.DraftID == "" {
		panic("outbox: Builder returned empty DraftID with Skip=false; refusing to fake-send")
	}

	if _, err := client.SendDraft(ctx, req.DraftID, req.Req); err != nil {
		return Result{Modes: modes, Err: classifySendDraftError(err)}
	}
	return Result{Modes: modes}
}

// logEncryptionDecision emits a structured INFO record per submission
// summarising the per-recipient encryption-mode decision. Hashed
// recipient addresses (not raw) so a log scraper does not see the
// recipient list verbatim — that is PII per the SPEC-0004 security
// checklist "No body content in logs (high-bit on PII; log only
// metadata)".
func (w *worker) logEncryptionDecision(sub Submission, modes map[string]EncryptionMode, err error) {
	attrs := []slog.Attr{
		slog.String("event", "outbox_encryption_decision"),
		slog.String("account_id", sub.AccountID),
		slog.Int("recipients", len(sub.Recipients)),
	}
	if err != nil {
		attrs = append(attrs,
			slog.Bool("ok", false),
			slog.String("err", err.Error()),
		)
	} else {
		// Aggregate counts by mode so a multi-recipient decision is
		// one log line, not N. The hostile reviewer would (rightly)
		// flag a per-recipient log line as a PII funnel.
		counts := map[EncryptionMode]int{}
		for _, m := range modes {
			counts[m]++
		}
		attrs = append(attrs,
			slog.Bool("ok", true),
			slog.Int("proton_e2e", counts[ModeProtonE2E]),
			slog.Int("external_e2e", counts[ModeExternalE2E]),
			slog.Int("cleartext", counts[ModeCleartext]),
		)
	}
	w.mgr.cfg.Logger.LogAttrs(context.Background(), slog.LevelInfo,
		"outbox encryption decision", attrs...)
}

// shutdown drains every in-flight submission and rejects subsequent
// Submit calls with ErrAccountClosed. Bounded by the supplied ctx; if
// the deadline expires the function returns ctx.Err and any still-
// running goroutines exit when their upstream call eventually returns.
func (w *worker) shutdown(ctx context.Context) error {
	w.closeMu.Lock()
	if w.closed {
		w.closeMu.Unlock()
		return nil
	}
	w.closed = true
	w.closeMu.Unlock()

	doneCh := make(chan struct{})
	go func() {
		w.inflight.Wait()
		close(doneCh)
	}()
	select {
	case <-doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// validateSubmission returns ErrSubmissionEnvelope if the submission is
// malformed. The SMTP server's MAIL FROM / RCPT TO / DATA handlers all
// reject these cases before producing a Submission, so this is purely
// defence in depth.
func validateSubmission(sub Submission) error {
	if sub.AccountID == "" || sub.MailFrom == "" || len(sub.Recipients) == 0 || len(sub.Body) == 0 {
		return ErrSubmissionEnvelope
	}
	return nil
}

// classifyClientError categorises an error returned by
// ProtonClientResolver.ResolveClient. A resolver that returns
// ErrAccountClosed (e.g. account suspended after auth) is honoured
// verbatim; anything else is treated as a transient server error.
func classifyClientError(err error) error {
	if errors.Is(err, ErrAccountClosed) {
		return err
	}
	if errors.Is(err, proton.ErrNotAuthenticated) {
		return &ErrProtonAuth{Cause: err}
	}
	return &ErrProtonServer{Cause: err}
}

// classifyBuilderError categorises an error from the per-message
// Builder. Builders run pure-Go encryption / package construction code
// so failure modes are predominantly programmer errors (missing key,
// MIME parse failure). Map them to a permanent rejection so the SMTP
// client does not retry.
func classifyBuilderError(err error) error {
	return &ErrProtonReject{Cause: err}
}

// classifySendDraftError maps a /mail/v4/messages/{id} POST failure to
// the Reduit error vocabulary the SMTP layer understands. We reach into
// proton.APIError so a 401 is an auth failure, a 429 is rate-limited,
// 4xx is a permanent reject, and anything else is a transient server
// error worth retrying.
//
// IMPORTANT: target is *proton.APIError (pointer), NOT proton.APIError
// (value). go-proton-api wraps its errors as *APIError via fmt.Errorf
// with %w (see upstream response.go around line 110), so an
// errors.As(err, &valueTarget) where valueTarget is of value type would
// silently miss the wrapped pointer in the chain — falling through to
// *ErrProtonServer (451) for every documented status code. The hostile
// review (B1) verified this against the vendored module. Always target
// the pointer.
//
// Mapping rules:
//
//	401 / 403          → ErrProtonAuth (SMTP 535)
//	408 / 429 / 503    → ErrProtonRateLimit (SMTP 421)
//	413 / 422 / 4xx    → ErrProtonReject (SMTP 550)
//	5xx and net errs   → ErrProtonServer (SMTP 451)
func classifySendDraftError(err error) error {
	var apiErr *proton.APIError
	if errors.As(err, &apiErr) && apiErr != nil {
		switch {
		case apiErr.Status == 401 || apiErr.Status == 403:
			return &ErrProtonAuth{Cause: err}
		case apiErr.Status == 408 || apiErr.Status == 429 || apiErr.Status == 503:
			return &ErrProtonRateLimit{Cause: err}
		case apiErr.Status >= 400 && apiErr.Status < 500:
			return &ErrProtonReject{Cause: err}
		}
	}
	return &ErrProtonServer{Cause: err}
}

// panicString renders a recovered panic value into a single line for
// the wrapped error. Strings pass through; everything else gets the
// fmt %v form.
func panicString(r any) string {
	if s, ok := r.(string); ok {
		return s
	}
	if e, ok := r.(error); ok {
		return e.Error()
	}
	return fmt.Sprintf("%v", r)
}

// DefaultPerAccountCap is the SPEC-0004 default per-account
// concurrency cap. Configurable via REDUIT_OUTBOX_PER_ACCOUNT_CAP at
// the composition-root layer.
const DefaultPerAccountCap = 4

// DefaultSubmitTimeout matches smtpserver.DefaultSubmitTimeout. We
// duplicate the constant here so the outbox package can be linked
// without the smtpserver package (handy for cmd-line tools and tests).
const DefaultSubmitTimeout = 60 * time.Second
