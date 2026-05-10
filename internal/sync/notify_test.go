// Governing: SPEC-0002 REQ "IMAP Update Notification",
//             SPEC-0002 REQ "Backoff on Failure"
//             (refresh-token-revoked permanent-failure path).

package sync

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/pubsub"
)

// recordingPublisher captures every Publish call so tests can assert
// the (key, kind, message_id) triples a batch produced. The order of
// captured entries matches the order of MessageEvent encounters in the
// batch, then in-order over each MessageEvent's LabelIDs.
type recordingPublisher struct {
	mu      sync.Mutex
	entries []recordedPublish
}

type recordedPublish struct {
	key string
	u   pubsub.Update
}

func (r *recordingPublisher) Publish(key string, u pubsub.Update) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, recordedPublish{key: key, u: u})
}

func (r *recordingPublisher) snapshot() []recordedPublish {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedPublish, len(r.entries))
	copy(out, r.entries)
	return out
}

// TestEventProcessorPublishesMessageAdded pins the SPEC-0002 REQ
// "IMAP Update Notification" scenario "Worker pushes EXISTS update on
// new message": a Proton EventCreate fans into a pubsub Publish with
// kind MessageAdded keyed `<account_id>:<label_id>` for every label
// the new message belongs to.
func TestEventProcessorPublishesMessageAdded(t *testing.T) {
	t.Parallel()
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-publish-added")
	if err := svc.SetSyncState(ctx, a.ID, "evt-pre", nil); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}

	rec := &recordingPublisher{}
	fc := &fakeProtonClient{
		getEventFn: func(string) ([]proton.Event, bool, error) {
			return []proton.Event{{
				EventID: "evt-1",
				Messages: []gpa.MessageEvent{{
					EventItem: gpa.EventItem{ID: "msg-1", Action: gpa.EventCreate},
					Message:   gpa.MessageMetadata{ID: "msg-1", LabelIDs: []string{"0", "5"}},
				}},
			}}, false, nil
		},
	}
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), rec)
	if err != nil {
		t.Fatalf("newEventProcessor: %v", err)
	}

	if _, err := proc.processOnce(ctx); err != nil {
		t.Fatalf("processOnce: %v", err)
	}

	got := rec.snapshot()
	if len(got) != 2 {
		t.Fatalf("publishes = %d, want 2 (one per LabelID)", len(got))
	}
	wantKeys := map[string]bool{a.ID + ":0": false, a.ID + ":5": false}
	for _, e := range got {
		if e.u.Kind != pubsub.MessageAdded {
			t.Errorf("Kind = %s, want MessageAdded", e.u.Kind)
		}
		if e.u.MessageID != "msg-1" {
			t.Errorf("MessageID = %q, want msg-1", e.u.MessageID)
		}
		if _, ok := wantKeys[e.key]; !ok {
			t.Errorf("unexpected key %q", e.key)
		}
		wantKeys[e.key] = true
	}
	for k, seen := range wantKeys {
		if !seen {
			t.Errorf("missing publish for key %q", k)
		}
	}
}

// TestEventProcessorPublishesMessageRemoved pins the SPEC-0002
// "Worker pushes EXPUNGE update on deletion" scenario. EventDelete
// has no Message body (no LabelIDs) so the publisher fans an
// account-wide notification (mailbox_id="") that an IDLE session
// uses as a RESYNC trigger.
func TestEventProcessorPublishesMessageRemoved(t *testing.T) {
	t.Parallel()
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-publish-removed")
	if err := svc.SetSyncState(ctx, a.ID, "evt-pre", nil); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}

	rec := &recordingPublisher{}
	fc := &fakeProtonClient{
		getEventFn: func(string) ([]proton.Event, bool, error) {
			return []proton.Event{{
				EventID: "evt-1",
				Messages: []gpa.MessageEvent{{
					EventItem: gpa.EventItem{ID: "msg-gone", Action: gpa.EventDelete},
				}},
			}}, false, nil
		},
	}
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), rec)
	if err != nil {
		t.Fatalf("newEventProcessor: %v", err)
	}
	if _, err := proc.processOnce(ctx); err != nil {
		t.Fatalf("processOnce: %v", err)
	}

	got := rec.snapshot()
	if len(got) != 1 {
		t.Fatalf("publishes = %d, want 1 (account-wide)", len(got))
	}
	if got[0].key != a.ID+":" {
		t.Errorf("key = %q, want %q (account-wide)", got[0].key, a.ID+":")
	}
	if got[0].u.Kind != pubsub.MessageRemoved {
		t.Errorf("Kind = %s, want MessageRemoved", got[0].u.Kind)
	}
	if got[0].u.MessageID != "msg-gone" {
		t.Errorf("MessageID = %q, want msg-gone", got[0].u.MessageID)
	}
}

// TestEventProcessorPublishesMessageFlagChanged pins the SPEC-0002
// "Flag changes emit FETCH" scenario. EventUpdate and EventUpdateFlags
// both surface as MessageFlagChanged.
func TestEventProcessorPublishesMessageFlagChanged(t *testing.T) {
	t.Parallel()
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-publish-flag")
	if err := svc.SetSyncState(ctx, a.ID, "evt-pre", nil); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}

	rec := &recordingPublisher{}
	fc := &fakeProtonClient{
		getEventFn: func(string) ([]proton.Event, bool, error) {
			return []proton.Event{{
				EventID: "evt-1",
				Messages: []gpa.MessageEvent{
					{
						EventItem: gpa.EventItem{ID: "msg-flagged", Action: gpa.EventUpdateFlags},
						Message:   gpa.MessageMetadata{ID: "msg-flagged", LabelIDs: []string{"7"}},
					},
					{
						EventItem: gpa.EventItem{ID: "msg-updated", Action: gpa.EventUpdate},
						Message:   gpa.MessageMetadata{ID: "msg-updated", LabelIDs: []string{"7"}},
					},
				},
			}}, false, nil
		},
	}
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), rec)
	if err != nil {
		t.Fatalf("newEventProcessor: %v", err)
	}
	if _, err := proc.processOnce(ctx); err != nil {
		t.Fatalf("processOnce: %v", err)
	}

	got := rec.snapshot()
	if len(got) != 2 {
		t.Fatalf("publishes = %d, want 2", len(got))
	}
	for i, e := range got {
		if e.u.Kind != pubsub.MessageFlagChanged {
			t.Errorf("publish[%d] Kind = %s, want MessageFlagChanged", i, e.u.Kind)
		}
		if e.key != a.ID+":7" {
			t.Errorf("publish[%d] key = %q, want %q", i, e.key, a.ID+":7")
		}
	}
}

// TestEventProcessorDoesNotPublishOnFailedCommit confirms that when
// SetSyncState fails (the cursor commit), no pubsub publishes fire —
// IDLE consumers MUST NOT see "MessageAdded" for a state change that
// did not actually commit. This is the "publish AFTER commit"
// invariant the spec design pins.
func TestEventProcessorDoesNotPublishOnFailedCommit(t *testing.T) {
	t.Parallel()
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-publish-failed-commit")

	// Wrap the real svc so SetSyncState always errors.
	failing := &failingSetSyncState{Service: svc}
	rec := &recordingPublisher{}
	fc := &fakeProtonClient{
		latest: "evt-bootstrap",
		getEventFn: func(string) ([]proton.Event, bool, error) {
			return []proton.Event{{
				EventID: "evt-1",
				Messages: []gpa.MessageEvent{{
					EventItem: gpa.EventItem{ID: "msg-1", Action: gpa.EventCreate},
					Message:   gpa.MessageMetadata{ID: "msg-1", LabelIDs: []string{"0"}},
				}},
			}}, false, nil
		},
	}
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), rec)
	if err != nil {
		t.Fatalf("newEventProcessor: %v", err)
	}
	// Swap the service after construction so the bootstrap path uses
	// the real one but processOnce hits the failing one.
	proc.svc = failing

	if _, err := proc.processOnce(ctx); err == nil {
		t.Fatal("processOnce: expected commit error, got nil")
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Errorf("got %d publishes after failed commit; want 0", len(got))
	}
}

// failingSetSyncState wraps an account.Service and forces SetSyncState
// to return a non-nil error. Every other method delegates.
type failingSetSyncState struct {
	account.Service
}

func (f *failingSetSyncState) SetSyncState(context.Context, string, string, account.SyncStateTxWork) error {
	return errors.New("simulated commit failure")
}

// TestWorkerExitsOnRefreshTokenRevoked is the end-to-end test for the
// SPEC-0002 REQ "Backoff on Failure" permanent-failure path: when
// Proton's GetEvent surfaces an AuthRefreshTokenInvalid (10013) error,
// the worker MUST transition the account back to pending_proton_setup
// and exit, rather than walking the backoff curve.
func TestWorkerExitsOnRefreshTokenRevoked(t *testing.T) {
	t.Parallel()
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-refresh-revoked")

	revokedErr := &gpa.APIError{
		Status:  http.StatusUnauthorized,
		Code:    gpa.AuthRefreshTokenInvalid,
		Message: "refresh token has been revoked",
	}
	fc := &fakeProtonClient{
		latest: "evt-bootstrap",
		getEventFn: func(string) ([]proton.Event, bool, error) {
			return nil, false, revokedErr
		},
	}

	cfg := fastConfig()
	cfg.PollInterval = 5 * time.Millisecond
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

	// The worker MUST observe the revoked error, transition the
	// account to pending_proton_setup, and exit (drop out of the
	// supervisor's live map).
	if !waitFor(t, 2*time.Second, func() bool {
		got, err := svc.GetByID(ctx, a.ID)
		if err != nil {
			return false
		}
		return got.State == account.StatePendingProtonSetup
	}) {
		got, _ := svc.GetByID(ctx, a.ID)
		t.Fatalf("account state never returned to pending; got=%+v", got)
	}
	if !waitFor(t, time.Second, func() bool { return sup.activeWorkerCount() == 0 }) {
		t.Fatalf("worker still in live map after refresh-token-revoked; count=%d", sup.activeWorkerCount())
	}

	// Crashed flag MUST NOT be set — refresh-token-revoked is a
	// recoverable credential failure, not a panic.
	got, err := svc.GetByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Crashed {
		t.Error("crashed flag set on refresh-token-revoked path; that flag is for panics only")
	}
}

// TestIsRefreshTokenRevokedError unit-tests the predicate so the
// permanent-failure classification is locked down independently of
// the worker integration. We accept the upstream's typed code AND the
// defensive HTTP-401 fallback, so both shapes need pinning.
func TestIsRefreshTokenRevokedError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "typed code",
			err:  &gpa.APIError{Status: 422, Code: gpa.AuthRefreshTokenInvalid},
			want: true,
		},
		{
			name: "http 401 fallback",
			err:  &gpa.APIError{Status: http.StatusUnauthorized, Code: 0},
			want: true,
		},
		{
			name: "5xx is not revoked",
			err:  &gpa.APIError{Status: http.StatusBadGateway, Code: 0},
			want: false,
		},
		{
			name: "stale cursor (422 + InvalidValue) is not revoked",
			err:  &gpa.APIError{Status: 422, Code: gpa.InvalidValue},
			want: false,
		},
		{
			name: "plain network error",
			err:  errors.New("dial tcp: i/o timeout"),
			want: false,
		},
		{
			name: "nil",
			err:  nil,
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRefreshTokenRevokedError(tc.err); got != tc.want {
				t.Errorf("isRefreshTokenRevokedError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestEventProcessorPublishesViaRealBus pins the integration with the
// real pubsub.Bus (not just the recordingPublisher stub). A subscriber
// on the right key MUST receive the Update within a tick.
func TestEventProcessorPublishesViaRealBus(t *testing.T) {
	t.Parallel()
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-real-bus")
	if err := svc.SetSyncState(ctx, a.ID, "evt-pre", nil); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}

	bus := pubsub.New()
	t.Cleanup(bus.Close)

	ch, unsub := bus.Subscribe(a.ID+":0", 0)
	t.Cleanup(unsub)

	fc := &fakeProtonClient{
		getEventFn: func(string) ([]proton.Event, bool, error) {
			return []proton.Event{{
				EventID: "evt-1",
				Messages: []gpa.MessageEvent{{
					EventItem: gpa.EventItem{ID: "msg-real", Action: gpa.EventCreate},
					Message:   gpa.MessageMetadata{ID: "msg-real", LabelIDs: []string{"0"}},
				}},
			}}, false, nil
		},
	}
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), bus)
	if err != nil {
		t.Fatalf("newEventProcessor: %v", err)
	}
	if _, err := proc.processOnce(ctx); err != nil {
		t.Fatalf("processOnce: %v", err)
	}

	select {
	case got := <-ch:
		if got.Kind != pubsub.MessageAdded {
			t.Errorf("Kind = %s, want MessageAdded", got.Kind)
		}
		if got.MessageID != "msg-real" {
			t.Errorf("MessageID = %q, want msg-real", got.MessageID)
		}
	case <-time.After(time.Second):
		t.Fatal("no Update received from pubsub.Bus within 1s")
	}
}
