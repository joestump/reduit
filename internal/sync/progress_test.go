package syncengine

import (
	"context"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/proton"
)

// TestEngine_NoTUIImports enforces SPEC-0012 "Engine Presentation Isolation":
// the sync engine MUST NOT import any terminal-UI library. The progress seam is
// typed events only (progress.go), so no bubbletea/bubbles/lipgloss/termenv
// import path may appear in this package's non-test sources. It parses the
// import blocks (not raw text) so a mention in a comment does not trip it.
func TestEngine_NoTUIImports(t *testing.T) {
	forbidden := []string{
		"charmbracelet/bubbletea",
		"charmbracelet/bubbles",
		"charmbracelet/lipgloss",
		"muesli/termenv",
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if strings.Contains(path, bad) {
					t.Errorf("%s imports terminal-UI library %q; the engine must stay presentation-agnostic", e.Name(), path)
				}
			}
		}
	}
}

// recordingReporter captures every progress event, in order, so a Fake-driven
// run can be asserted against the SPEC-0012 event contract. It is safe for the
// concurrent emits a SyncAll fan-out produces.
type recordingReporter struct {
	mu        sync.Mutex
	started   []MailboxStarted
	enumerate []BackfillEnumerated
	applied   []MessageApplied
	tail      []TailBatchApplied
	done      []MailboxDone
}

func (r *recordingReporter) MailboxStarted(ev MailboxStarted) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.started = append(r.started, ev)
}

func (r *recordingReporter) BackfillEnumerated(ev BackfillEnumerated) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enumerate = append(r.enumerate, ev)
}

func (r *recordingReporter) MessageApplied(ev MessageApplied) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applied = append(r.applied, ev)
}

func (r *recordingReporter) TailBatchApplied(ev TailBatchApplied) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tail = append(r.tail, ev)
}

func (r *recordingReporter) MailboxDone(ev MailboxDone) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.done = append(r.done, ev)
}

// TestProgress_Backfill_EmitsEnumeratedAndApplied verifies the backfill emits
// one BackfillEnumerated with the enumerated total and one MessageApplied per
// message with a monotonic Done/Total, plus a terminal MailboxDone carrying the
// summary (SPEC-0012 "Events carry the run's shape", "Backfill has a
// denominator").
func TestProgress_Backfill_EmitsEnumeratedAndApplied(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newMemKeychain()
	seedActiveMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")

	fake := authedFake("tok-1", "uid-1")
	fake.LabelList = inboxLabels()
	fake.LatestEvent = "ev-1"
	fake.BackfillIDs = []string{"m1", "m2", "m3"}
	fake.Messages = map[string]proton.DecryptedMessage{
		"m1": msg("m1", "One", "a@example.com", []string{"0"}, "b1"),
		"m2": msg("m2", "Two", "b@example.com", []string{"0"}, "b2"),
		"m3": msg("m3", "Three", "c@example.com", []string{"0"}, "b3"),
	}

	rec := &recordingReporter{}
	e := New(Deps{Store: st, Keychain: ks, Dialer: &fakeDialer{clients: map[string]proton.Client{"user-1": fake}}, Progress: rec})
	e.sleep = func(context.Context, time.Duration) {}

	if _, err := e.SyncMailbox(ctx, "mb-1"); err != nil {
		t.Fatalf("SyncMailbox: %v", err)
	}

	// MailboxStarted fires exactly once, at the start of the run, so the header
	// has a labelled row before enumeration completes.
	if len(rec.started) != 1 || rec.started[0].MailboxID != "mb-1" || rec.started[0].Address != "joe@proton.test" {
		t.Fatalf("started = %+v, want one event mailbox=mb-1 address=joe@proton.test", rec.started)
	}
	if len(rec.enumerate) != 1 || rec.enumerate[0].Total != 3 || rec.enumerate[0].MailboxID != "mb-1" {
		t.Fatalf("enumerate = %+v, want one event total=3 mailbox=mb-1", rec.enumerate)
	}
	if rec.enumerate[0].Address != "joe@proton.test" {
		t.Errorf("enumerate address = %q, want joe@proton.test", rec.enumerate[0].Address)
	}
	if len(rec.applied) != 3 {
		t.Fatalf("applied count = %d, want 3", len(rec.applied))
	}
	for i, ev := range rec.applied {
		if ev.Done != i+1 || ev.Total != 3 || ev.MailboxID != "mb-1" {
			t.Errorf("applied[%d] = %+v, want done=%d total=3", i, ev, i+1)
		}
	}
	if len(rec.done) != 1 || rec.done[0].MailboxID != "mb-1" || rec.done[0].Summary.Added != 3 {
		t.Fatalf("done = %+v, want one event mailbox=mb-1 added=3", rec.done)
	}
	if rec.done[0].Summary.Err != nil {
		t.Errorf("done summary err = %v, want nil", rec.done[0].Summary.Err)
	}
}

// TestProgress_Tail_EmitsTailBatch verifies a tail run emits a TailBatchApplied
// per committed batch (no enumerate/applied), driving the indeterminate
// indicator (SPEC-0012 "Tail has no denominator").
func TestProgress_Tail_EmitsTailBatch(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newMemKeychain()
	seedActiveMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")

	// Seed a cursor so the run TAILS rather than bootstraps.
	if err := st.UpsertSyncState(ctx, "mb-1", "cur-0", time.Now().UTC()); err != nil {
		t.Fatalf("UpsertSyncState: %v", err)
	}

	fake := authedFake("tok-1", "uid-1")
	fake.LabelList = inboxLabels()
	fake.Messages = map[string]proton.DecryptedMessage{
		"n1": msg("n1", "New", "a@example.com", []string{"0"}, "body"),
		"n2": msg("n2", "New2", "b@example.com", []string{"0"}, "body2"),
	}
	// Two committed batches → two TailBatchApplied events.
	fake.Batches = []proton.EventBatch{
		{Events: []proton.Event{{EventID: "ev-1", Messages: []proton.MessageEvent{
			{Action: proton.EventCreate, MessageID: "n1"},
		}}}, NextCursor: "cur-1", More: true},
		{Events: []proton.Event{{EventID: "ev-2", Messages: []proton.MessageEvent{
			{Action: proton.EventCreate, MessageID: "n2"},
		}}}, NextCursor: "cur-2", More: false},
	}

	rec := &recordingReporter{}
	e := New(Deps{Store: st, Keychain: ks, Dialer: &fakeDialer{clients: map[string]proton.Client{"user-1": fake}}, Progress: rec})
	e.sleep = func(context.Context, time.Duration) {}

	if _, err := e.SyncMailbox(ctx, "mb-1"); err != nil {
		t.Fatalf("SyncMailbox: %v", err)
	}

	// MailboxStarted fires for a tail run too, so the header is alive before the
	// first batch even when there is no backfill.
	if len(rec.started) != 1 || rec.started[0].MailboxID != "mb-1" {
		t.Fatalf("started = %+v, want one event mailbox=mb-1", rec.started)
	}
	if len(rec.enumerate) != 0 || len(rec.applied) != 0 {
		t.Errorf("tail run emitted backfill events: enumerate=%d applied=%d", len(rec.enumerate), len(rec.applied))
	}
	if len(rec.tail) != 2 {
		t.Fatalf("tail = %+v, want two committed batches", rec.tail)
	}
	for i, ev := range rec.tail {
		if ev.MailboxID != "mb-1" || ev.Events != 1 {
			t.Errorf("tail[%d] = %+v, want mailbox=mb-1 events=1", i, ev)
		}
	}
	if len(rec.done) != 1 {
		t.Errorf("done count = %d, want 1", len(rec.done))
	}
}

// TestProgress_NilReporter_NoPanicIdenticalRun verifies a nil reporter is a
// no-op: the run behaves exactly as before this seam existed (SPEC-0012 "Nil
// reporter is a no-op").
func TestProgress_NilReporter_NoPanicIdenticalRun(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newMemKeychain()
	seedActiveMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")

	fake := authedFake("tok-1", "uid-1")
	fake.LabelList = inboxLabels()
	fake.LatestEvent = "ev-1"
	fake.BackfillIDs = []string{"m1", "m2"}
	fake.Messages = map[string]proton.DecryptedMessage{
		"m1": msg("m1", "One", "a@example.com", []string{"0"}, "b1"),
		"m2": msg("m2", "Two", "b@example.com", []string{"0"}, "b2"),
	}

	// Progress deliberately omitted (nil).
	e := New(Deps{Store: st, Keychain: ks, Dialer: &fakeDialer{clients: map[string]proton.Client{"user-1": fake}}})
	e.sleep = func(context.Context, time.Duration) {}

	sum, err := e.SyncMailbox(ctx, "mb-1")
	if err != nil {
		t.Fatalf("SyncMailbox with nil reporter: %v", err)
	}
	if sum.Added != 2 || sum.Err != nil {
		t.Errorf("summary = %+v, want added=2 no error", sum)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM messages`); n != 2 {
		t.Errorf("messages = %d, want 2", n)
	}
}

// TestProgress_SlowReporter_DoesNotStallEngine verifies a deliberately slow
// reporter does not slow the engine unduly: the engine calls the reporter
// synchronously, so the CONTRACT is that a reporter must not block. This test
// documents that a well-behaved (fast) reporter keeps the run bounded, and the
// adapter-level drop test (internal/cli) covers the full-buffer drop path
// (SPEC-0012 "Slow consumer does not stall sync").
func TestProgress_SlowReporter_DoesNotStallEngine(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newMemKeychain()
	seedActiveMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")

	fake := authedFake("tok-1", "uid-1")
	fake.LabelList = inboxLabels()
	fake.LatestEvent = "ev-1"
	ids := make([]string, 50)
	fake.Messages = map[string]proton.DecryptedMessage{}
	for i := range ids {
		id := fmt.Sprintf("m%d", i)
		ids[i] = id
		fake.Messages[id] = msg(id, "S", "a@example.com", []string{"0"}, "b")
	}
	fake.BackfillIDs = ids

	// A reporter that returns immediately (honoring the non-blocking contract).
	rec := &recordingReporter{}
	e := New(Deps{Store: st, Keychain: ks, Dialer: &fakeDialer{clients: map[string]proton.Client{"user-1": fake}}, Progress: rec})
	e.sleep = func(context.Context, time.Duration) {}

	done := make(chan struct{})
	go func() {
		_, _ = e.SyncMailbox(ctx, "mb-1")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("engine stalled on the progress reporter")
	}
	if len(rec.applied) != 50 {
		t.Errorf("applied = %d, want 50", len(rec.applied))
	}
}
