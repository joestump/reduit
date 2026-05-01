// Governing: SPEC-0002 REQ "Event Cursor Persistence",
//             SPEC-0002 REQ "Concurrency Limits".

package sync

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/proton"
)

// fakeProtonClient is a programmable proton.Client used by the
// event-processor tests. It satisfies the full Client interface but
// only the GetEvent and GetLatestEventID methods are exercised; the
// rest panic on call so an unexpected access shows up as a test
// failure instead of a silent zero-value return.
type fakeProtonClient struct {
	mu          sync.Mutex
	getEventLog []string // cursors GetEvent was called with, in order
	getEventFn  func(cursor string) ([]proton.Event, bool, error)
	latest      string
	latestErr   error
	latestCalls int32
}

func (f *fakeProtonClient) AuthInfo(context.Context, proton.AuthInfoReq) (proton.AuthInfo, error) {
	panic("AuthInfo: unexpected call")
}
func (f *fakeProtonClient) AuthTOTP(context.Context, string) error {
	panic("AuthTOTP: unexpected call")
}
func (f *fakeProtonClient) AuthFIDO2(context.Context, proton.FIDO2Req) error {
	panic("AuthFIDO2: unexpected call")
}
func (f *fakeProtonClient) KeySalts(context.Context) (proton.Salts, error) {
	panic("KeySalts: unexpected call")
}
func (f *fakeProtonClient) Unlock(proton.User, []proton.Address, []byte) (*proton.KeyRing, map[string]*proton.KeyRing, error) {
	panic("Unlock: unexpected call")
}
func (f *fakeProtonClient) GetEvent(_ context.Context, cursor string) ([]proton.Event, bool, error) {
	f.mu.Lock()
	f.getEventLog = append(f.getEventLog, cursor)
	fn := f.getEventFn
	f.mu.Unlock()
	if fn == nil {
		return nil, false, nil
	}
	return fn(cursor)
}
func (f *fakeProtonClient) GetLatestEventID(context.Context) (string, error) {
	atomic.AddInt32(&f.latestCalls, 1)
	return f.latest, f.latestErr
}
func (f *fakeProtonClient) GetMessage(context.Context, string) (proton.Message, error) {
	panic("GetMessage: unexpected call")
}
func (f *fakeProtonClient) ListMessages(context.Context, proton.MessageFilter) ([]proton.MessageMetadata, error) {
	panic("ListMessages: unexpected call")
}
func (f *fakeProtonClient) SendDraft(context.Context, string, proton.SendDraftReq) (proton.Message, error) {
	panic("SendDraft: unexpected call")
}
func (f *fakeProtonClient) GetAttachment(context.Context, string) ([]byte, error) {
	panic("GetAttachment: unexpected call")
}
func (f *fakeProtonClient) Logout(context.Context) error { return nil }

func (f *fakeProtonClient) cursorsCalled() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.getEventLog))
	copy(out, f.getEventLog)
	return out
}

// nopLogger returns a slog.Logger that swallows everything. Avoids
// cluttering test output with the Debug/Error logs the worker emits.
func nopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// TestEventProcessorBootstrapFromLatestOnFirstBoot pins SPEC-0002's
// "Resume on startup uses persisted cursor" scenario in its negative
// case: when no cursor exists yet, the processor MUST call
// GetLatestEventID rather than passing the empty string to GetEvent
// (which would replay the entire account history — explicitly out of
// scope for v0.1 per SPEC-0002 "Out of Scope").
func TestEventProcessorBootstrapFromLatestOnFirstBoot(t *testing.T) {
	t.Parallel()
	svc := newTestAccountService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, account.CreateParams{OIDCSubject: "sub-bootstrap"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	fc := &fakeProtonClient{latest: "evt-current"}
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger())
	if err != nil {
		t.Fatalf("newEventProcessor: %v", err)
	}
	if proc.cursor != "evt-current" {
		t.Errorf("cursor = %q, want evt-current (from GetLatestEventID)", proc.cursor)
	}
	if got := atomic.LoadInt32(&fc.latestCalls); got != 1 {
		t.Errorf("GetLatestEventID call count = %d, want 1", got)
	}

	// CRITICAL: bootstrap MUST NOT have persisted the cursor — only a
	// successful processOnce should write to sync_state. Otherwise a
	// worker that bootstraps and then exits before its first poll
	// leaves an "I synced everything up to T0" lie behind that the
	// next boot would treat as ground truth.
	if _, err := svc.GetSyncState(ctx, a.ID); !errors.Is(err, account.ErrNoSyncState) {
		t.Errorf("GetSyncState after bootstrap = %v, want ErrNoSyncState (no row should be written yet)", err)
	}
}

// TestEventProcessorResumesFromPersistedCursor pins SPEC-0002's
// positive Resume scenario: a worker started against an account that
// already has a sync_state row MUST pass that cursor to GetEvent
// (NOT call GetLatestEventID).
func TestEventProcessorResumesFromPersistedCursor(t *testing.T) {
	t.Parallel()
	svc := newTestAccountService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, account.CreateParams{OIDCSubject: "sub-resume"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := svc.SetSyncState(ctx, a.ID, "evt-persisted"); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}

	fc := &fakeProtonClient{latest: "evt-fresh-should-not-be-used"}
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger())
	if err != nil {
		t.Fatalf("newEventProcessor: %v", err)
	}
	if proc.cursor != "evt-persisted" {
		t.Errorf("cursor = %q, want evt-persisted", proc.cursor)
	}
	if got := atomic.LoadInt32(&fc.latestCalls); got != 0 {
		t.Errorf("GetLatestEventID called %d times; persisted cursor MUST short-circuit it", got)
	}

	// First processOnce MUST use the persisted cursor.
	fc.getEventFn = func(cursor string) ([]proton.Event, bool, error) {
		if cursor != "evt-persisted" {
			t.Errorf("GetEvent cursor = %q, want evt-persisted", cursor)
		}
		return []proton.Event{{EventID: "evt-after-persisted"}}, false, nil
	}
	if _, err := proc.processOnce(ctx); err != nil {
		t.Fatalf("processOnce: %v", err)
	}
}

// TestEventProcessorAdvancesCursorAfterBatch is the load-bearing
// SPEC-0002 acceptance criterion from issue #16: insert events into
// the fake Proton, assert all events commit + cursor advances exactly
// once per batch.
func TestEventProcessorAdvancesCursorAfterBatch(t *testing.T) {
	t.Parallel()
	svc := newTestAccountService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, account.CreateParams{OIDCSubject: "sub-advance"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	fc := &fakeProtonClient{latest: "evt-0"}
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger())
	if err != nil {
		t.Fatalf("newEventProcessor: %v", err)
	}

	// Three-event batch — the issue's AC says "test inserts 3 mock
	// events into httptest Proton, asserts all 3 commit + cursor
	// advances exactly once per batch".
	fc.getEventFn = func(cursor string) ([]proton.Event, bool, error) {
		if cursor != "evt-0" {
			t.Errorf("first GetEvent cursor = %q, want evt-0", cursor)
		}
		return []proton.Event{
			{EventID: "evt-1"},
			{EventID: "evt-2"},
			{EventID: "evt-3"},
		}, false, nil
	}
	more, err := proc.processOnce(ctx)
	if err != nil {
		t.Fatalf("processOnce: %v", err)
	}
	if more {
		t.Error("processOnce reported more=true; fake set false")
	}

	// Cursor MUST be the LAST event's ID (Proton's monotonic ordering
	// guarantee). And it MUST be persisted — restart-resume reads
	// from sync_state, not from the in-process cursor field.
	if proc.cursor != "evt-3" {
		t.Errorf("in-memory cursor = %q, want evt-3", proc.cursor)
	}
	state, err := svc.GetSyncState(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetSyncState after processOnce: %v", err)
	}
	if state.LastEventID != "evt-3" {
		t.Errorf("persisted cursor = %q, want evt-3", state.LastEventID)
	}
}

// TestEventProcessorEmptyBatchKeepsCursor pins the idempotent-read
// invariant: two consecutive empty batches MUST leave the cursor
// pointing at the same value. (last_synced_at advances; that's the
// admin-UI hint.)
func TestEventProcessorEmptyBatchKeepsCursor(t *testing.T) {
	t.Parallel()
	svc := newTestAccountService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, account.CreateParams{OIDCSubject: "sub-empty"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := svc.SetSyncState(ctx, a.ID, "evt-stable"); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}

	fc := &fakeProtonClient{
		getEventFn: func(cursor string) ([]proton.Event, bool, error) {
			if cursor != "evt-stable" {
				t.Errorf("GetEvent cursor = %q, want evt-stable", cursor)
			}
			return nil, false, nil
		},
	}
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger())
	if err != nil {
		t.Fatalf("newEventProcessor: %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, err := proc.processOnce(ctx); err != nil {
			t.Fatalf("processOnce iter %d: %v", i, err)
		}
		if proc.cursor != "evt-stable" {
			t.Fatalf("iter %d: in-memory cursor = %q, want evt-stable", i, proc.cursor)
		}
		state, err := svc.GetSyncState(ctx, a.ID)
		if err != nil {
			t.Fatalf("GetSyncState iter %d: %v", i, err)
		}
		if state.LastEventID != "evt-stable" {
			t.Fatalf("iter %d: persisted cursor = %q, want evt-stable", i, state.LastEventID)
		}
	}

	// Three calls into GetEvent, all with the same cursor.
	got := fc.cursorsCalled()
	if len(got) != 3 {
		t.Fatalf("GetEvent call count = %d, want 3", len(got))
	}
	for i, c := range got {
		if c != "evt-stable" {
			t.Errorf("call %d cursor = %q, want evt-stable", i, c)
		}
	}
}

// TestEventProcessorRestartResumesFromPersistedCursor simulates the
// full restart cycle the SPEC-0002 "Resume on startup uses persisted
// cursor" scenario describes: process A advances the cursor and
// exits; process B comes up against the same DB and MUST resume from
// where A left off.
func TestEventProcessorRestartResumesFromPersistedCursor(t *testing.T) {
	t.Parallel()
	svc := newTestAccountService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, account.CreateParams{OIDCSubject: "sub-restart"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Process A: bootstrap, ingest one batch, advance cursor.
	fcA := &fakeProtonClient{
		latest: "evt-A0",
		getEventFn: func(cursor string) ([]proton.Event, bool, error) {
			return []proton.Event{{EventID: "evt-A1"}}, false, nil
		},
	}
	procA, err := newEventProcessor(ctx, a.ID, svc, fcA, nopLogger())
	if err != nil {
		t.Fatalf("Process A bootstrap: %v", err)
	}
	if _, err := procA.processOnce(ctx); err != nil {
		t.Fatalf("Process A processOnce: %v", err)
	}
	// Process A is gone.

	// Process B: fresh fake client. The "latest" value MUST NOT be
	// consulted because a persisted cursor exists.
	fcB := &fakeProtonClient{
		latest: "evt-WRONG-should-not-be-used",
		getEventFn: func(cursor string) ([]proton.Event, bool, error) {
			if cursor != "evt-A1" {
				t.Errorf("Process B first GetEvent cursor = %q, want evt-A1 (the cursor A persisted)", cursor)
			}
			return nil, false, nil
		},
	}
	procB, err := newEventProcessor(ctx, a.ID, svc, fcB, nopLogger())
	if err != nil {
		t.Fatalf("Process B bootstrap: %v", err)
	}
	if procB.cursor != "evt-A1" {
		t.Errorf("Process B cursor = %q, want evt-A1", procB.cursor)
	}
	if _, err := procB.processOnce(ctx); err != nil {
		t.Fatalf("Process B processOnce: %v", err)
	}
	if got := atomic.LoadInt32(&fcB.latestCalls); got != 0 {
		t.Errorf("Process B called GetLatestEventID %d times; resume MUST short-circuit it", got)
	}
}

// TestEventProcessorPropagatesGetEventError confirms that a Proton
// failure surfaces as the processor's error and does NOT advance the
// cursor — the next tick will retry the same cursor. This is the
// at-least-once-delivery pin for SPEC-0002 REQ "Event Cursor
// Persistence".
func TestEventProcessorPropagatesGetEventError(t *testing.T) {
	t.Parallel()
	svc := newTestAccountService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, account.CreateParams{OIDCSubject: "sub-err"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := svc.SetSyncState(ctx, a.ID, "evt-stuck"); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}

	wantErr := errors.New("proton 502 bad gateway")
	fc := &fakeProtonClient{
		getEventFn: func(cursor string) ([]proton.Event, bool, error) {
			return nil, false, wantErr
		},
	}
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger())
	if err != nil {
		t.Fatalf("newEventProcessor: %v", err)
	}
	if _, err := proc.processOnce(ctx); !errors.Is(err, wantErr) {
		t.Fatalf("processOnce error = %v, want wraps %v", err, wantErr)
	}
	if proc.cursor != "evt-stuck" {
		t.Errorf("cursor advanced despite GetEvent error: got %q, want evt-stuck", proc.cursor)
	}
	state, err := svc.GetSyncState(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetSyncState: %v", err)
	}
	if state.LastEventID != "evt-stuck" {
		t.Errorf("persisted cursor advanced despite error: got %q, want evt-stuck", state.LastEventID)
	}
}

// TestWorkerTickInvokesEventProcessor is the worker-level integration:
// the supervisor starts a worker against an active account, the
// worker resolves a fake proton.Client via the configured factory,
// and the cursor advances after a single tick. This is the end-to-end
// "tick → GetEvent → cursor persist" round-trip the SPEC-0002 REQ
// "Event Cursor Persistence" scenarios describe.
func TestWorkerTickInvokesEventProcessor(t *testing.T) {
	t.Parallel()
	svc := newTestAccountService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, account.CreateParams{OIDCSubject: "sub-worker-tick"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	fc := &fakeProtonClient{
		latest: "evt-now",
		getEventFn: func(cursor string) ([]proton.Event, bool, error) {
			return []proton.Event{{EventID: "evt-after-tick"}}, false, nil
		},
	}

	cfg := fastConfig()
	cfg.ClientFactory = func(_ context.Context, accountID string) (proton.Client, error) {
		if accountID != a.ID {
			t.Errorf("ClientFactory accountID = %q, want %q", accountID, a.ID)
		}
		return fc, nil
	}
	sup := New(svc, cfg)
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = sup.Stop() })

	if _, err := svc.Transition(ctx, a.ID, account.StateActive); err != nil {
		t.Fatalf("Transition: %v", err)
	}

	if !waitFor(t, 2*time.Second, func() bool {
		state, err := svc.GetSyncState(ctx, a.ID)
		return err == nil && state.LastEventID == "evt-after-tick"
	}) {
		state, _ := svc.GetSyncState(ctx, a.ID)
		t.Fatalf("cursor never advanced to evt-after-tick; final=%+v", state)
	}
}

// TestWorkerTickHonoursMaxConsecutiveTicks pins the burst-cap
// invariant: even if Proton claims more=true forever, a single tick
// MUST yield to the ticker after MaxConsecutiveTicks calls so a slow
// shutdown isn't starved by a runaway burst.
func TestWorkerTickHonoursMaxConsecutiveTicks(t *testing.T) {
	t.Parallel()
	svc := newTestAccountService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, account.CreateParams{OIDCSubject: "sub-burst"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var calls int32
	fc := &fakeProtonClient{
		latest: "evt-bootstrap",
		// Always claim more=true — without the cap this would loop
		// forever inside one tick().
		getEventFn: func(cursor string) ([]proton.Event, bool, error) {
			n := atomic.AddInt32(&calls, 1)
			return []proton.Event{{EventID: "evt-burst-" + string(rune('0'+n))}}, true, nil
		},
	}

	cfg := fastConfig()
	cfg.MaxConsecutiveTicks = 5
	// Long poll interval so we definitely only see ONE tick in the
	// observation window — the burst cap is what bounds calls, not
	// the ticker firing twice.
	cfg.PollInterval = time.Hour
	cfg.ClientFactory = func(context.Context, string) (proton.Client, error) {
		return fc, nil
	}
	sup := New(svc, cfg)
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = sup.Stop() })

	if _, err := svc.Transition(ctx, a.ID, account.StateActive); err != nil {
		t.Fatalf("Transition: %v", err)
	}

	// Wait for the burst to settle. The first tick fires immediately
	// on worker.run() entry; we expect exactly MaxConsecutiveTicks
	// calls and then a yield.
	if !waitFor(t, 2*time.Second, func() bool {
		return atomic.LoadInt32(&calls) >= 5
	}) {
		t.Fatalf("burst never reached cap; calls=%d", atomic.LoadInt32(&calls))
	}

	// Give a generous window for any (incorrect) extra calls to land.
	time.Sleep(100 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 5 {
		t.Errorf("GetEvent call count = %d, want exactly 5 (the burst cap); long PollInterval should prevent a second tick", got)
	}
}

// Compile-time assertion that fakeProtonClient still satisfies the
// proton.Client interface as that interface evolves. Catches breakages
// in CI rather than at first use.
var _ proton.Client = (*fakeProtonClient)(nil)
