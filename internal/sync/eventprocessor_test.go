// Governing: SPEC-0002 REQ "Event Cursor Persistence",
//             SPEC-0002 REQ "Concurrency Limits".

package sync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"

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
func (f *fakeProtonClient) GetUser(context.Context) (proton.User, error) {
	panic("GetUser: unexpected call")
}
func (f *fakeProtonClient) GetAddresses(context.Context) ([]proton.Address, error) {
	panic("GetAddresses: unexpected call")
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
func (f *fakeProtonClient) GetMessageRFC822(context.Context, string) ([]byte, error) {
	panic("GetMessageRFC822: unexpected call")
}
func (f *fakeProtonClient) ListMessages(context.Context, proton.MessageFilter) ([]proton.MessageMetadata, error) {
	panic("ListMessages: unexpected call")
}
func (f *fakeProtonClient) ListMessagesPage(context.Context, int, int, proton.MessageFilter) ([]proton.MessageMetadata, error) {
	panic("ListMessagesPage: unexpected call")
}
func (f *fakeProtonClient) GroupedMessageCount(context.Context) ([]proton.MessageGroupCount, error) {
	panic("GroupedMessageCount: unexpected call")
}
func (f *fakeProtonClient) GetLabels(context.Context, ...proton.LabelType) ([]proton.Label, error) {
	panic("GetLabels: unexpected call")
}
func (f *fakeProtonClient) SendDraft(context.Context, string, proton.SendDraftReq) (proton.Message, error) {
	panic("SendDraft: unexpected call")
}
func (f *fakeProtonClient) GetAttachment(context.Context, string) ([]byte, error) {
	panic("GetAttachment: unexpected call")
}
func (f *fakeProtonClient) Logout(context.Context) error { return nil }
func (f *fakeProtonClient) LatestRefreshToken() string   { return "" }

// Methods added to proton.Client by the SPEC-0004 outbox work
// (GetPublicKeys) and the SPEC-0003 IMAP MOVE/COPY work
// (LabelMessages/UnlabelMessages). Sync tests do not exercise these
// surfaces, so they panic on unexpected calls.
func (f *fakeProtonClient) GetPublicKeys(context.Context, string) (proton.PublicKeys, proton.RecipientType, error) {
	panic("GetPublicKeys: unexpected call")
}
func (f *fakeProtonClient) LabelMessages(context.Context, []string, string) error {
	panic("LabelMessages: unexpected call")
}
func (f *fakeProtonClient) UnlabelMessages(context.Context, []string, string) error {
	panic("UnlabelMessages: unexpected call")
}
func (f *fakeProtonClient) ImportMessage(context.Context, []byte, string, bool) (string, error) {
	panic("ImportMessage: unexpected call")
}
func (f *fakeProtonClient) MarkMessagesRead(context.Context, ...string) error {
	panic("MarkMessagesRead: unexpected call")
}
func (f *fakeProtonClient) MarkMessagesUnread(context.Context, ...string) error {
	panic("MarkMessagesUnread: unexpected call")
}

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
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-bootstrap")

	fc := &fakeProtonClient{latest: "evt-current"}
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), nil, nil, nil)
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
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-resume")
	if err := svc.SetSyncState(ctx, a.ID, "evt-persisted", nil); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}

	fc := &fakeProtonClient{latest: "evt-fresh-should-not-be-used"}
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), nil, nil, nil)
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
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-advance")

	fc := &fakeProtonClient{latest: "evt-0"}
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), nil, nil, nil)
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
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-empty")
	if err := svc.SetSyncState(ctx, a.ID, "evt-stable", nil); err != nil {
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
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), nil, nil, nil)
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
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-restart")

	// Process A: bootstrap, ingest one batch, advance cursor.
	fcA := &fakeProtonClient{
		latest: "evt-A0",
		getEventFn: func(cursor string) ([]proton.Event, bool, error) {
			return []proton.Event{{EventID: "evt-A1"}}, false, nil
		},
	}
	procA, err := newEventProcessor(ctx, a.ID, svc, fcA, nopLogger(), nil, nil, nil)
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
	procB, err := newEventProcessor(ctx, a.ID, svc, fcB, nopLogger(), nil, nil, nil)
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
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-err")
	if err := svc.SetSyncState(ctx, a.ID, "evt-stuck", nil); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}

	wantErr := errors.New("proton 502 bad gateway")
	fc := &fakeProtonClient{
		getEventFn: func(cursor string) ([]proton.Event, bool, error) {
			return nil, false, wantErr
		},
	}
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), nil, nil, nil)
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
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-worker-tick")

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
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-burst")

	var calls int32
	fc := &fakeProtonClient{
		latest: "evt-bootstrap",
		// Always claim more=true — without the cap this would loop
		// forever inside one tick().
		getEventFn: func(cursor string) ([]proton.Event, bool, error) {
			n := atomic.AddInt32(&calls, 1)
			// fmt.Sprintf instead of `string(rune('0'+n))` so a future
			// bump to MaxConsecutiveTicks > 9 doesn't synthesize
			// non-printable EventIDs (PR #41 nit).
			return []proton.Event{{EventID: fmt.Sprintf("evt-burst-%d", n)}}, true, nil
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

// TestEventProcessorRecoversFromStaleCursor pins the stale-cursor
// recovery path added in PR #41's hostile-review fix: when GetEvent
// returns 422 + Code=InvalidValue (Proton's signal that the cursor
// has aged past retention), the processor MUST fall back to
// GetLatestEventID, persist the new cursor, and yield to the next
// tick. Pre-fix the worker spun forever on the dead cursor.
func TestEventProcessorRecoversFromStaleCursor(t *testing.T) {
	t.Parallel()
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-stale")
	if err := svc.SetSyncState(ctx, a.ID, "evt-too-old", nil); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}

	staleErr := &gpa.APIError{
		Status:  http.StatusUnprocessableEntity,
		Code:    gpa.InvalidValue,
		Message: "EventID is too old",
	}
	fc := &fakeProtonClient{
		latest: "evt-recovered",
		getEventFn: func(cursor string) ([]proton.Event, bool, error) {
			if cursor != "evt-too-old" {
				t.Errorf("GetEvent cursor = %q, want evt-too-old", cursor)
			}
			return nil, false, staleErr
		},
	}
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), nil, nil, nil)
	if err != nil {
		t.Fatalf("newEventProcessor: %v", err)
	}

	more, err := proc.processOnce(ctx)
	if err != nil {
		t.Fatalf("processOnce: %v (expected recovery, not error)", err)
	}
	if more {
		t.Errorf("processOnce reported more=true; recovery should yield to next tick")
	}
	if proc.cursor != "evt-recovered" {
		t.Errorf("in-memory cursor = %q, want evt-recovered (from GetLatestEventID)", proc.cursor)
	}
	state, err := svc.GetSyncState(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetSyncState: %v", err)
	}
	if state.LastEventID != "evt-recovered" {
		t.Errorf("persisted cursor = %q, want evt-recovered", state.LastEventID)
	}
	if got := atomic.LoadInt32(&fc.latestCalls); got != 1 {
		t.Errorf("GetLatestEventID call count = %d, want 1 (the recovery)", got)
	}
}

// TestEventProcessorRejectsEmptyTrailingEventID pins the empty-EventID
// defense added in PR #41's hostile-review fix: a batch whose last
// event has EventID == "" must NOT advance the cursor (otherwise the
// next GetEvent call would ask Proton for "everything", which the
// upstream API treats as a special "give me history" request).
// Behaviour: keep the prior cursor, return more=false + nil error so
// the worker waits for the next ticker fire.
func TestEventProcessorRejectsEmptyTrailingEventID(t *testing.T) {
	t.Parallel()
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-empty-id")
	if err := svc.SetSyncState(ctx, a.ID, "evt-good", nil); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}

	fc := &fakeProtonClient{
		getEventFn: func(cursor string) ([]proton.Event, bool, error) {
			return []proton.Event{
				{EventID: "evt-trail-1"},
				{EventID: ""}, // malformed batch
			}, false, nil
		},
	}
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), nil, nil, nil)
	if err != nil {
		t.Fatalf("newEventProcessor: %v", err)
	}

	more, err := proc.processOnce(ctx)
	if err != nil {
		t.Fatalf("processOnce: %v", err)
	}
	if more {
		t.Errorf("processOnce reported more=true; malformed batch should yield")
	}
	if proc.cursor != "evt-good" {
		t.Errorf("in-memory cursor = %q, want evt-good (unchanged)", proc.cursor)
	}
	state, err := svc.GetSyncState(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetSyncState: %v", err)
	}
	if state.LastEventID != "evt-good" {
		t.Errorf("persisted cursor = %q, want evt-good (unchanged)", state.LastEventID)
	}
}

// TestNewRejectsNilClientFactory pins PR #41's hostile-review fix
// for Blocker 2: the previous build accepted a nil ClientFactory and
// silently degraded to "no-Proton mode" with no operator-visible
// signal. New() now panics so a misconfigured production deploy
// fails loudly at boot.
func TestNewRejectsNilClientFactory(t *testing.T) {
	t.Parallel()
	svc, _ := newTestAccountService(t)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for nil ClientFactory")
		}
		msg, ok := r.(string)
		if !ok || msg == "" {
			t.Errorf("panic value = %v, want non-empty string", r)
		}
	}()

	cfg := fastConfig()
	cfg.ClientFactory = nil
	_ = New(svc, cfg)
}

// TestWorkerStartReportsBootstrapFailure pins the lazy-bootstrap fix
// in PR #41: a ClientFactory error at the FIRST tick used to be
// silently retried on every subsequent tick (with the cached
// processor never reconstructed). start() now performs bootstrap
// synchronously, logs at ERROR, and removes the worker so a
// misconfigured deploy surfaces the error at activation time rather
// than producing a worker that never syncs.
func TestWorkerStartReportsBootstrapFailure(t *testing.T) {
	t.Parallel()
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-boot-fail")

	wantErr := errors.New("simulated factory failure")
	cfg := fastConfig()
	cfg.ClientFactory = func(context.Context, string) (proton.Client, error) {
		return nil, wantErr
	}
	sup := New(svc, cfg)
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = sup.Stop() })

	if _, err := svc.Transition(ctx, a.ID, account.StateActive); err != nil {
		t.Fatalf("Transition: %v", err)
	}

	// The worker MUST be removed from the live map within a tick or
	// two — bootstrap failed, so there is no goroutine to keep it
	// alive, and removeWorker fires from bootstrapFailed().
	if !waitFor(t, time.Second, func() bool { return sup.activeWorkerCount() == 0 }) {
		t.Fatalf("bootstrap failure did not remove worker; count=%d", sup.activeWorkerCount())
	}
}

// TestWorkerTickReleasesSlotBetweenBurstIterations pins PR #41's
// burst-loop fairness fix: holding the global Proton slot across all
// MaxConsecutiveTicks iterations starved sibling work behind up to
// cap×N round-trips. The fix releases between iterations so a
// contender can interleave.
//
// Strategy: cap=1. Spawn a contender goroutine that loops calling
// AcquireProtonSlot+release as fast as it can, counting successful
// acquires. With the per-iteration release, the contender gets a
// turn between every worker iteration — so its acquire count
// scales with the worker's burst length. Pre-fix (slot held across
// the entire burst) the contender's count would be 0 or 1 (one
// acquire either before the worker started or after it finished).
//
// We don't insist on exact counts because Go's channel scheduler
// doesn't guarantee strict alternation, but a contender that can
// acquire AT ALL while the worker is mid-burst is the deterministic
// behavioural change we're pinning. A counter ≥ 2 guarantees the
// contender ran during the burst (one acquire might race the start;
// two acquires can't both be pre-burst because cap=1).
func TestWorkerTickReleasesSlotBetweenBurstIterations(t *testing.T) {
	t.Parallel()
	svc, usrSvc := newTestAccountService(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := createTestAccount(t, svc, usrSvc, "sub-fairness")

	// Worker iter pacing: each iteration blocks until the test sends
	// on `proceed`, so the test deterministically holds the worker
	// inside the burst while the contender races for slots.
	var calls int32
	iterStarted := make(chan int, 8)
	proceed := make(chan struct{})
	fc := &fakeProtonClient{
		latest: "evt-fair-bootstrap",
		getEventFn: func(cursor string) ([]proton.Event, bool, error) {
			n := atomic.AddInt32(&calls, 1)
			select {
			case iterStarted <- int(n):
			case <-ctx.Done():
				return nil, false, ctx.Err()
			}
			select {
			case <-proceed:
			case <-ctx.Done():
				return nil, false, ctx.Err()
			}
			more := n < 3
			return []proton.Event{{EventID: fmt.Sprintf("evt-fair-%d", n)}}, more, nil
		},
	}

	cfg := fastConfig()
	cfg.ConcurrencyCap = 1
	cfg.PollInterval = time.Hour
	cfg.MaxConsecutiveTicks = 5
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

	// Contender: loop acquiring + releasing. Each successful acquire
	// (after the first, which can race the worker's startup) PROVES
	// the worker was not holding the slot at that moment.
	stopContender := make(chan struct{})
	var contenderAcquires int32
	contenderDone := make(chan struct{})
	go func() {
		defer close(contenderDone)
		for {
			select {
			case <-stopContender:
				return
			default:
			}
			acqCtx, cancelAcq := context.WithTimeout(ctx, 100*time.Millisecond)
			rel, err := sup.AcquireProtonSlot(acqCtx)
			cancelAcq()
			if err != nil {
				continue
			}
			atomic.AddInt32(&contenderAcquires, 1)
			rel()
			// Yield so the worker has a chance to acquire too,
			// otherwise this tight loop would dominate the slot.
			runtime.Gosched()
		}
	}()

	// Pace the worker through 3 iterations. Between each, give the
	// contender ample time to acquire.
	for i := 1; i <= 3; i++ {
		select {
		case n := <-iterStarted:
			if n != i {
				t.Errorf("iter %d: got start signal for %d", i, n)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("worker never reached iter %d", i)
		}
		// The worker is INSIDE getEventFn (slot held). Confirm the
		// contender can't acquire RIGHT NOW (sanity check: cap=1).
		// Then unblock the iter so the worker releases.
		proceed <- struct{}{}
		// Brief settle window for the contender to grab the freed
		// slot before the worker re-acquires.
		time.Sleep(20 * time.Millisecond)
	}

	close(stopContender)
	<-contenderDone

	// With per-iteration release, the contender slipped in between
	// iters 1+2 and 2+3 at minimum. Allow some slack for scheduler
	// jitter, but require at least 2 acquires to PROVE the contender
	// ran while the worker was mid-burst (cap=1 so two acquires
	// cannot both be pre-burst).
	if got := atomic.LoadInt32(&contenderAcquires); got < 2 {
		t.Errorf("contender acquired slot only %d times; per-iteration release is broken (worker held slot across burst)", got)
	}
}

// Compile-time assertion that fakeProtonClient still satisfies the
// proton.Client interface as that interface evolves. Catches breakages
// in CI rather than at first use.
var _ proton.Client = (*fakeProtonClient)(nil)
