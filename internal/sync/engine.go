// Package syncengine is the per-mailbox sync orchestration for reduit
// (SPEC-0002): the layer that pulls mail from Proton's event stream into the
// local SQLite cache. Each active mailbox syncs independently — first sync
// backfills a bounded window of history, every run after that tails the event
// stream and applies the delta — advancing its own persisted Proton event
// cursor. Bodies are decrypted in the pipeline with the mailbox passphrase from
// the OS keychain, so what lands in the cache is plaintext ready to index.
//
// The package name is syncengine, not sync, so it does not shadow the stdlib
// sync package the engine itself uses for concurrency.
//
// This layer is the ENGINE the `reduit sync` CLI verb (the next layer,
// SPEC-0002 "Triggered Execution") calls: New builds an Engine from its
// dependencies expressed as interfaces (a Dialer, the store, the keychain), and
// SyncAll / SyncMailbox drive one bootstrap-then-tail routine per mailbox with
// bounded concurrency and strict per-mailbox failure isolation.
//
// Governing: SPEC-0002 (Sync & Local Cache), ADR-0014 (sync-and-cache),
// ADR-0006 (SQLite store), ADR-0013 (secrets in OS keychain), SPEC-0001
// (Mailbox Model).
package syncengine

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/joestump/reduit/internal/keychain"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/store"
)

// Dialer reconstructs an authenticated Proton client for a mailbox from its
// stored session state. It is the single network seam the engine depends on,
// expressed as an interface so the whole engine runs offline in tests against a
// Fake-backed dialer. The production implementation is *proton.GPADialer, whose
// Resume already satisfies this signature; tests supply a dialer that returns a
// *proton.Fake. The engine intentionally does NOT depend on Dialer.NewClient —
// sync never runs the interactive login, only Resume from stored secrets.
type Dialer interface {
	// Resume reconstructs an authenticated (not yet unlocked) client by reusing a
	// stored session — its UID, access token, and refresh token. Reusing the
	// cached access token preserves the 2FA-elevated scope key/salt access needs
	// (SPEC-0007 "Cross-Process Session Resume"). See proton.Dialer.Resume.
	Resume(ctx context.Context, protonUserID, sessionUID, accessToken, refreshToken string) (proton.Client, error)
}

// Deps are the engine's collaborators, all interfaces or concrete seams so the
// engine is testable offline.
type Deps struct {
	// Store is the local cache the engine writes into.
	Store *store.Store
	// Keychain holds each mailbox's refresh token and passphrase (ADR-0013).
	Keychain keychain.Store
	// Dialer resumes an authenticated Proton client per mailbox.
	Dialer Dialer
	// Logger receives structured progress and per-message failure logs. A nil
	// Logger is replaced with a discarding logger in New.
	Logger *slog.Logger
	// Config tunes the backfill window and concurrency (SPEC-0002).
	Config Config
	// Progress receives typed progress events for a presentation layer to
	// render (SPEC-0012). A nil Progress is a no-op — the engine emits nothing
	// and behaves exactly as before this seam existed. Its methods MUST be
	// non-blocking; see ProgressReporter's contract.
	Progress ProgressReporter
}

// Config tunes sync behavior. It mirrors config.SyncConfig; the CLI layer maps
// the loaded config onto it.
type Config struct {
	// BackfillWindow bounds a mailbox's first-sync backfill: only messages at
	// or after (now - BackfillWindow) are imported. A zero window backfills the
	// full mailbox (SPEC-0002 "First sync backfills a bounded window").
	BackfillWindow time.Duration
	// Concurrency caps how many mailboxes sync in parallel in SyncAll,
	// bounding in-flight Proton requests (SPEC-0002 "Bounded concurrency"). A
	// value < 1 is treated as 1.
	Concurrency int
}

// Engine orchestrates per-mailbox sync. Construct it with New; it is safe for
// its own SyncAll to fan out across mailboxes concurrently.
type Engine struct {
	store    *store.Store
	keychain keychain.Store
	dialer   Dialer
	log      *slog.Logger
	cfg      Config
	progress ProgressReporter

	// now and sleep are injected so tests can control time and make backoff
	// instantaneous. Production uses time.Now and time.Sleep.
	now   func() time.Time
	sleep func(context.Context, time.Duration)
}

// New builds an Engine from its dependencies. A nil Logger is replaced with a
// no-op logger and Concurrency < 1 is normalized to 1, so callers can pass a
// zero Config for a single-threaded run.
func New(deps Deps) *Engine {
	log := deps.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	cfg := deps.Config
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	return &Engine{
		store:    deps.Store,
		keychain: deps.Keychain,
		dialer:   deps.Dialer,
		log:      log,
		cfg:      cfg,
		progress: deps.Progress,
		now:      time.Now,
		sleep:    sleepCtx,
	}
}

// RunSummary is the outcome of one mailbox's sync run. It mirrors the persisted
// store.SyncRun counts and carries the failure cause when the run failed. On a
// clean run Err is nil; on a failure the counts reflect whatever was durably
// applied before the failure (nothing is rolled back across the whole run —
// each committed unit stays committed per SPEC-0002 crash-safety).
type RunSummary struct {
	MailboxID   string
	Address     string
	Added       int
	Updated     int
	Deleted     int
	Attachments int
	// Errors is the count of per-message failures the run absorbed and skipped
	// while continuing (SPEC-0002 "Decrypt failure does not poison the cache").
	Errors int
	// Err is the fatal cause that ended the run (auth failure, network failure
	// after retries, panic). nil on a successful run. It is recorded to the
	// mailbox's sync_run regardless, so observability does not depend on the
	// caller inspecting this field.
	Err error
}

// SyncAll syncs every ACTIVE mailbox with bounded concurrency (Config.
// Concurrency). A crash, panic, or auth failure in one mailbox is isolated to
// that mailbox: it is recorded against that mailbox's run and the others still
// complete (SPEC-0002 "Per-Mailbox Sync Isolation"). The returned error is
// non-nil only when the mailbox set itself could not be enumerated; per-mailbox
// failures live in each RunSummary.Err, and the summaries are returned in
// mailbox order regardless of individual outcomes.
func (e *Engine) SyncAll(ctx context.Context) ([]RunSummary, error) {
	mboxes, err := e.store.ListMailboxes(ctx)
	if err != nil {
		return nil, fmt.Errorf("syncengine: list mailboxes: %w", err)
	}

	// Only active mailboxes sync; pending_auth / needs_reauth cannot resume.
	active := make([]store.Mailbox, 0, len(mboxes))
	for _, m := range mboxes {
		if m.State == store.MailboxStateActive {
			active = append(active, m)
		}
	}

	summaries := make([]RunSummary, len(active))
	sem := make(chan struct{}, e.cfg.Concurrency)
	var wg sync.WaitGroup
	for i, m := range active {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, m store.Mailbox) {
			defer wg.Done()
			defer func() { <-sem }()
			summaries[i] = e.runIsolated(ctx, m)
		}(i, m)
	}
	wg.Wait()
	return summaries, nil
}

// SyncMailbox syncs exactly one mailbox by its id, leaving every other
// mailbox's sync_state untouched (SPEC-0002 "Mailbox selection"). It returns the
// run summary and, for a single-mailbox caller's convenience, the run's fatal
// cause as the error (nil on a clean run); the cause is also persisted to the
// mailbox's sync_run either way.
func (e *Engine) SyncMailbox(ctx context.Context, mailboxID string) (RunSummary, error) {
	m, err := e.store.GetMailbox(ctx, mailboxID)
	if err != nil {
		return RunSummary{MailboxID: mailboxID}, fmt.Errorf("syncengine: load mailbox: %w", err)
	}
	s := e.runIsolated(ctx, m)
	return s, s.Err
}

// runIsolated runs one mailbox's sync under a panic recover so a panic in one
// mailbox's routine cannot take down a sibling or the process (SPEC-0002
// "Failure in one mailbox does not stall others"). Whatever the outcome, it
// records a sync_run row for the mailbox so every run is observable.
func (e *Engine) runIsolated(ctx context.Context, m store.Mailbox) (summary RunSummary) {
	started := e.now().UTC()
	summary.MailboxID = m.ID
	summary.Address = m.Address

	defer func() {
		if p := recover(); p != nil {
			e.log.Error("sync panicked; mailbox isolated",
				"mailbox_id", m.ID, "address", m.Address, "panic", p,
				"stack", string(debug.Stack()))
			summary.Err = fmt.Errorf("syncengine: panic: %v", p)
		}
		e.recordRun(ctx, started, &summary)
		// Emit the terminal progress event with the FINAL summary (after any
		// panic recover and bookkeeping), so the consumer marks this mailbox
		// complete exactly once whatever the outcome (SPEC-0012 "Events carry
		// the run's shape", "mailbox complete").
		e.emitMailboxDone(MailboxDone{MailboxID: m.ID, Summary: summary})
	}()

	e.syncMailbox(ctx, m, &summary)
	return summary
}

// recordRun persists the run summary and, on a clean run, stamps last_sync_at.
// A failed record is logged, not propagated: bookkeeping must not itself become
// the thing that fails a run (the cache writes already committed).
func (e *Engine) recordRun(ctx context.Context, started time.Time, s *RunSummary) {
	var lastErr *string
	if s.Err != nil {
		msg := s.Err.Error()
		lastErr = &msg
	}
	run := store.SyncRun{
		MailboxID:   s.MailboxID,
		StartedAt:   started,
		FinishedAt:  e.now().UTC(),
		Added:       s.Added,
		Updated:     s.Updated,
		Deleted:     s.Deleted,
		Attachments: s.Attachments,
		Errors:      s.Errors,
		LastError:   lastErr,
	}
	if err := e.store.RecordSyncRun(ctx, run); err != nil {
		e.log.Error("record sync run failed", "mailbox_id", s.MailboxID, "error", err)
	}
	if s.Err == nil {
		if err := e.store.SetLastSyncAt(ctx, s.MailboxID, run.FinishedAt); err != nil {
			e.log.Error("set last_sync_at failed", "mailbox_id", s.MailboxID, "error", err)
		}
	}
}

// sleepCtx sleeps for d or until ctx is done, whichever comes first. It is the
// production backoff sleeper; tests inject a no-op.
func sleepCtx(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
