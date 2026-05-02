// Manager owns the per-account worker registry and per-process
// configuration (timeout, semaphore cap, resolver, builder, pending-
// store). Submit is the public entry point; the SMTP server holds a
// reference and calls into it from the DATA handler.
//
// Workers are minted lazily on first Submit per account and torn down
// by Manager.Shutdown.
//
// Governing: SPEC-0004 REQ "Outbox Handoff and Synchronous Confirmation",
// SPEC-0004 REQ "Per-Account Outbox Concurrency Limit".

package outbox

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"
)

// EnvPerAccountCap is the env-var override for the per-account
// semaphore size. An operator can set this without editing the config
// file. The composition-root New() consults this when Config.PerAccountCap
// is zero.
//
// Governing: SPEC-0004 REQ "Per-Account Outbox Concurrency Limit" —
// the cap is operator-tunable; documenting the env var here keeps the
// promise the PR body makes honest.
const EnvPerAccountCap = "REDUIT_OUTBOX_PER_ACCOUNT_CAP"

// Config bundles the construction-time knobs for Manager.
type Config struct {
	// SubmitTimeout caps both semaphore-acquire wait and the upstream
	// Proton call. Zero means DefaultSubmitTimeout (60s).
	SubmitTimeout time.Duration

	// PerAccountCap is the per-account semaphore size. Zero means
	// DefaultPerAccountCap (4).
	PerAccountCap int

	// Resolver hands back a session-bearing proton.Client for the
	// supplied account ID. Required.
	Resolver ProtonClientResolver

	// Builder constructs the per-message Proton SendDraftReq from a
	// classified Submission. REQUIRED — outbox.New rejects nil.
	// Production callers wire a real Builder (CreateDraft + per-mode
	// MessagePackage assembly) at the composition root; the only
	// permitted test-only escape is BuildResult{Skip: true}, which
	// bypasses SendDraft. There is no production-linkable NoopBuilder
	// — silent-success was the worst failure mode.
	Builder Builder

	// PendingStore persists best-effort audit rows for submissions
	// whose synchronous timeout fired (Reduit returned 451 4.4.7).
	// Required; tests may pass DiscardPendingStore. Reduit does NOT
	// run a Reduit-side retry loop after a timeout — recovery is the
	// sender's MTA re-attempting the SMTP submission.
	PendingStore PendingStore

	// Logger is the slog.Logger used for outbox events. Nil falls back
	// to slog.Default().
	Logger *slog.Logger
}

// Manager is the singleton outbox engine.
type Manager struct {
	cfg Config

	mu      sync.Mutex
	workers map[string]*worker
	closed  bool

	shutdownCh chan struct{}
}

// New constructs a Manager. Required Config fields: Resolver, Builder,
// PendingStore.
func New(cfg Config) (*Manager, error) {
	if cfg.Resolver == nil {
		return nil, errors.New("outbox: Resolver is required")
	}
	if cfg.Builder == nil {
		return nil, errors.New("outbox: Builder is required")
	}
	if cfg.PendingStore == nil {
		return nil, errors.New("outbox: PendingStore is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.SubmitTimeout <= 0 {
		cfg.SubmitTimeout = DefaultSubmitTimeout
	}
	if cfg.PerAccountCap <= 0 {
		// Honour REDUIT_OUTBOX_PER_ACCOUNT_CAP before falling back to
		// the package default. The PR body and the worker's package
		// comment promised this env var; previously it was vapor —
		// see spec-compliance review (#42 round 1).
		cfg.PerAccountCap = resolvePerAccountCap()
	}
	return &Manager{
		cfg:        cfg,
		workers:    make(map[string]*worker),
		shutdownCh: make(chan struct{}),
	}, nil
}

// Submit hands a submission to the per-account worker (creating the
// worker on demand) and returns the result of the synchronous send.
// The SMTP server's DATA handler calls this directly; the returned
// Result.Err is mapped to an SMTP reply code by the SMTP layer.
func (m *Manager) Submit(ctx context.Context, sub Submission) Result {
	w, err := m.workerFor(sub.AccountID)
	if err != nil {
		return Result{Err: err}
	}
	return w.Submit(ctx, sub)
}

// workerFor returns the per-account worker, creating it lazily on
// first call. After Shutdown it returns ErrAccountClosed without
// creating a new worker — otherwise a Submit racing Shutdown could
// resurrect an already-drained account.
func (m *Manager) workerFor(accountID string) (*worker, error) {
	if accountID == "" {
		return nil, ErrSubmissionEnvelope
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrAccountClosed
	}
	w, ok := m.workers[accountID]
	if !ok {
		w = newWorker(m, accountID)
		m.workers[accountID] = w
	}
	return w, nil
}

// Shutdown drains every worker. Bounded by the supplied ctx; on
// deadline, in-flight goroutines continue running (they are best-
// effort by design — see Submit's detached-background path) and the
// function returns ctx.Err.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	close(m.shutdownCh)
	workers := make([]*worker, 0, len(m.workers))
	for _, w := range m.workers {
		workers = append(workers, w)
	}
	m.mu.Unlock()

	var firstErr error
	for _, w := range workers {
		if err := w.shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// resolvePerAccountCap returns the env-var override for the per-account
// semaphore size, or DefaultPerAccountCap if unset / malformed. Negative
// or zero env values fall back to the default.
func resolvePerAccountCap() int {
	if env := os.Getenv(EnvPerAccountCap); env != "" {
		if n, err := strconv.Atoi(env); err == nil && n > 0 {
			return n
		}
	}
	return DefaultPerAccountCap
}

// activeWorkerCount returns the number of currently registered
// workers. Test-only helper used by the cross-account concurrency
// test to confirm a per-account-cap holds even when many accounts are
// in flight.
func (m *Manager) activeWorkerCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.workers)
}
