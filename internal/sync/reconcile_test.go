package sync

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/joestump/reduit/internal/mailbox"
	"github.com/joestump/reduit/internal/proton"
)

// stubUnlabelStore is an in-memory PendingUnlabelStore. It records which
// rows were resolved (deleted) vs. failed (attempt-bumped) so the
// reconciler test can assert the convergence behaviour.
type stubUnlabelStore struct {
	mu       sync.Mutex
	rows     []*mailbox.PendingUnlabel
	resolved []int64
	failed   []int64
	listErr  error
}

func (s *stubUnlabelStore) ListPendingUnlabels(_ context.Context, _ string, limit, maxAttempts int) ([]*mailbox.PendingUnlabel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listErr != nil {
		return nil, s.listErr
	}
	out := make([]*mailbox.PendingUnlabel, 0, len(s.rows))
	for _, r := range s.rows {
		// Mirror the SQL `attempts < maxAttempts` filter so parked rows
		// stop being listed once they cross the ceiling.
		if maxAttempts > 0 && r.Attempts >= maxAttempts {
			continue
		}
		if limit > 0 && len(out) >= limit {
			break
		}
		// Return a copy so the reconciler cannot mutate our stored row
		// out from under us between passes.
		cp := *r
		out = append(out, &cp)
	}
	return out, nil
}

func (s *stubUnlabelStore) ResolvePendingUnlabel(_ context.Context, _ string, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resolved = append(s.resolved, id)
	for i, r := range s.rows {
		if r.ID == id {
			s.rows = append(s.rows[:i], s.rows[i+1:]...)
			break
		}
	}
	return nil
}

func (s *stubUnlabelStore) FailPendingUnlabel(_ context.Context, _ string, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed = append(s.failed, id)
	for _, r := range s.rows {
		if r.ID == id {
			r.Attempts++
			break
		}
	}
	return nil
}

// recordingUnlabelClient is a minimal proton.Client that records (and
// optionally fails) UnlabelMessages calls. Every other method panics —
// the reconciler only ever calls UnlabelMessages.
type recordingUnlabelClient struct {
	proton.Client
	mu     sync.Mutex
	calls  []unlabelCall
	failOn map[string]bool // proton message IDs that should fail
}

type unlabelCall struct {
	ids   []string
	label string
}

func (c *recordingUnlabelClient) UnlabelMessages(_ context.Context, ids []string, label string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, unlabelCall{ids: ids, label: label})
	for _, id := range ids {
		if c.failOn[id] {
			return errors.New("simulated unlabel failure")
		}
	}
	return nil
}

// TestReconcileResolvesPendingUnlabels confirms the reconciler retries
// the recorded unlabels against Proton and deletes the rows that
// succeed.
//
// Governing: SPEC-0003 REQ "Moving between system folders changes Proton
// system flag".
func TestReconcileResolvesPendingUnlabels(t *testing.T) {
	t.Parallel()
	store := &stubUnlabelStore{
		rows: []*mailbox.PendingUnlabel{
			{ID: 1, AccountID: "acct", ProtonMessageID: "m1", ProtonLabelID: "0"},
			{ID: 2, AccountID: "acct", ProtonMessageID: "m2", ProtonLabelID: "6"},
		},
	}
	client := &recordingUnlabelClient{failOn: map[string]bool{}}
	rc := NewMoveReconciler(store, nopLogger())

	resolved, err := rc.Reconcile(context.Background(), "acct", client)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if resolved != 2 {
		t.Errorf("resolved = %d, want 2", resolved)
	}
	if len(client.calls) != 2 {
		t.Errorf("UnlabelMessages calls = %d, want 2", len(client.calls))
	}
	if len(store.resolved) != 2 {
		t.Errorf("resolved rows = %v, want [1 2]", store.resolved)
	}
	if len(store.failed) != 0 {
		t.Errorf("failed rows = %v, want none", store.failed)
	}
}

// TestReconcileLeavesFailedRows confirms a row whose Proton unlabel
// retry fails is NOT deleted (so a later pass retries it) and its
// attempt counter is bumped.
func TestReconcileLeavesFailedRows(t *testing.T) {
	t.Parallel()
	store := &stubUnlabelStore{
		rows: []*mailbox.PendingUnlabel{
			{ID: 1, AccountID: "acct", ProtonMessageID: "good", ProtonLabelID: "0"},
			{ID: 2, AccountID: "acct", ProtonMessageID: "bad", ProtonLabelID: "0"},
		},
	}
	client := &recordingUnlabelClient{failOn: map[string]bool{"bad": true}}
	rc := NewMoveReconciler(store, nopLogger())

	resolved, err := rc.Reconcile(context.Background(), "acct", client)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if resolved != 1 {
		t.Errorf("resolved = %d, want 1 (only the good row)", resolved)
	}
	if len(store.resolved) != 1 || store.resolved[0] != 1 {
		t.Errorf("resolved rows = %v, want [1]", store.resolved)
	}
	if len(store.failed) != 1 || store.failed[0] != 2 {
		t.Errorf("failed rows = %v, want [2]", store.failed)
	}
}

// TestReconcileParksPermanentlyFailingRow confirms the unbounded-retry
// fix: a row whose unlabel keeps failing is retried at most
// maxReconcileAttempts times across passes, then parked (no longer
// listed, no longer issuing Proton calls). Without the ceiling this would
// be one Proton round-trip per tick forever.
func TestReconcileParksPermanentlyFailingRow(t *testing.T) {
	t.Parallel()
	store := &stubUnlabelStore{
		rows: []*mailbox.PendingUnlabel{
			{ID: 1, AccountID: "acct", ProtonMessageID: "stuck", ProtonLabelID: "0"},
		},
	}
	client := &recordingUnlabelClient{failOn: map[string]bool{"stuck": true}}
	rc := NewMoveReconciler(store, nopLogger())

	// Run far more passes than the ceiling. The row must stop being
	// retried once it is parked.
	for i := 0; i < maxReconcileAttempts*3; i++ {
		if _, err := rc.Reconcile(context.Background(), "acct", client); err != nil {
			t.Fatalf("Reconcile pass %d: %v", i, err)
		}
	}

	client.mu.Lock()
	calls := len(client.calls)
	client.mu.Unlock()
	if calls != maxReconcileAttempts {
		t.Errorf("UnlabelMessages calls = %d, want exactly maxReconcileAttempts (%d) — row must be parked after the ceiling",
			calls, maxReconcileAttempts)
	}

	// The row is parked, not deleted: a no-limit list still sees it, but
	// the reconciler's ceiling-filtered list does not.
	store.mu.Lock()
	rowsLeft := len(store.rows)
	parkedAttempts := store.rows[0].Attempts
	store.mu.Unlock()
	if rowsLeft != 1 {
		t.Errorf("parked row count = %d, want 1 (parked, not deleted)", rowsLeft)
	}
	if parkedAttempts < maxReconcileAttempts {
		t.Errorf("parked row attempts = %d, want >= %d", parkedAttempts, maxReconcileAttempts)
	}
}

// TestReconcileNilSafe confirms a nil reconciler / nil store / nil
// client is a no-op rather than a panic, so the worker can call it
// unconditionally.
func TestReconcileNilSafe(t *testing.T) {
	t.Parallel()
	var nilRC *MoveReconciler
	if n, err := nilRC.Reconcile(context.Background(), "acct", &recordingUnlabelClient{}); n != 0 || err != nil {
		t.Errorf("nil reconciler Reconcile = (%d, %v), want (0, nil)", n, err)
	}
	rc := NewMoveReconciler(nil, nopLogger())
	if n, err := rc.Reconcile(context.Background(), "acct", &recordingUnlabelClient{}); n != 0 || err != nil {
		t.Errorf("nil-store Reconcile = (%d, %v), want (0, nil)", n, err)
	}
	rc2 := NewMoveReconciler(&stubUnlabelStore{}, nopLogger())
	if n, err := rc2.Reconcile(context.Background(), "acct", nil); n != 0 || err != nil {
		t.Errorf("nil-client Reconcile = (%d, %v), want (0, nil)", n, err)
	}
}

// TestReconcileSurfacesListError confirms a store read error propagates
// (the worker logs it but does not abort the tick).
func TestReconcileSurfacesListError(t *testing.T) {
	t.Parallel()
	store := &stubUnlabelStore{listErr: errors.New("db down")}
	rc := NewMoveReconciler(store, nopLogger())
	if _, err := rc.Reconcile(context.Background(), "acct", &recordingUnlabelClient{}); err == nil {
		t.Fatal("Reconcile swallowed list error; want it surfaced")
	}
}

// reconcilingProtonClient is a fakeProtonClient whose UnlabelMessages is
// wired (instead of panicking) so the processOnce-integration test can
// observe the reconciler firing inside the event-processing path.
type reconcilingProtonClient struct {
	*fakeProtonClient
	unlabelClient *recordingUnlabelClient
}

func (c *reconcilingProtonClient) UnlabelMessages(ctx context.Context, ids []string, label string) error {
	return c.unlabelClient.UnlabelMessages(ctx, ids, label)
}

// TestProcessOnceRunsReconciler confirms the event processor invokes the
// MOVE reconciler after a successful event batch, draining pending
// unlabels that the IMAP server recorded.
//
// Governing: SPEC-0003 REQ "Moving between system folders changes Proton
// system flag".
func TestProcessOnceRunsReconciler(t *testing.T) {
	t.Parallel()
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()
	a := createTestAccount(t, svc, usrSvc, "sub-reconcile")

	store := &stubUnlabelStore{
		rows: []*mailbox.PendingUnlabel{
			{ID: 1, AccountID: a.ID, ProtonMessageID: "stuck", ProtonLabelID: "0"},
		},
	}
	rec := &recordingUnlabelClient{failOn: map[string]bool{}}
	fc := &fakeProtonClient{latest: "evt-0"}
	client := &reconcilingProtonClient{fakeProtonClient: fc, unlabelClient: rec}

	reconciler := NewMoveReconciler(store, nopLogger())
	proc, err := newEventProcessor(ctx, a.ID, svc, client, nopLogger(), nil, reconciler)
	if err != nil {
		t.Fatalf("newEventProcessor: %v", err)
	}

	// Empty batch: processOnce still commits the cursor and then runs the
	// reconciler. We pass the client through reconcilingProtonClient so
	// the reconciler's UnlabelMessages call is recorded rather than
	// panicking.
	fc.getEventFn = func(string) ([]proton.Event, bool, error) {
		return nil, false, nil
	}
	if _, err := proc.processOnce(ctx); err != nil {
		t.Fatalf("processOnce: %v", err)
	}

	if len(rec.calls) != 1 {
		t.Errorf("reconciler UnlabelMessages calls = %d, want 1", len(rec.calls))
	}
	if len(store.resolved) != 1 || store.resolved[0] != 1 {
		t.Errorf("resolved rows = %v, want [1]", store.resolved)
	}
}
