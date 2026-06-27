// Governing: SPEC-0002 REQ "IMAP Update Notification",
//             SPEC-0002 REQ "Backoff on Failure"
//             (refresh-token-revoked permanent-failure path).

package sync

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/notify"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/pubsub"
)

// recordingNotifier captures every admin notification a worker emits so
// tests can assert the (kind, message) pairs the crash / auto-revert
// paths produce. Satisfies the sync.Notifier interface.
//
// Governing: SPEC-0002 REQ "Panic Isolation", REQ "Backoff on Failure".
type recordingNotifier struct {
	mu      sync.Mutex
	entries []recordedNotification
}

type recordedNotification struct {
	accountID string
	kind      notify.Kind
	message   string
	detail    string
}

func (r *recordingNotifier) Record(_ context.Context, accountID string, kind notify.Kind, message, detail string) (*notify.Notification, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, recordedNotification{
		accountID: accountID, kind: kind, message: message, detail: detail,
	})
	return &notify.Notification{ID: "rec", AccountID: accountID, Kind: kind}, nil
}

func (r *recordingNotifier) snapshot() []recordedNotification {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedNotification, len(r.entries))
	copy(out, r.entries)
	return out
}

func (r *recordingNotifier) countOf(kind notify.Kind) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.entries {
		if e.kind == kind {
			n++
		}
	}
	return n
}

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
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), rec, nil, nil)
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
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), rec, nil, nil)
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
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), rec, nil, nil)
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
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), rec, nil, nil)
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

	rn := &recordingNotifier{}
	cfg := fastConfig()
	cfg.PollInterval = 5 * time.Millisecond
	cfg.Notifier = rn
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

	// The auto-revert MUST surface an admin notification (and exactly
	// one — the worker emits it on the single GetEvent failure that
	// classifies as permanent, then exits, so a flaky double-tick must
	// not double-notify). Governing: SPEC-0002 REQ "Backoff on Failure".
	if !waitFor(t, time.Second, func() bool {
		return rn.countOf(notify.KindAutoReverted) >= 1
	}) {
		t.Fatal("no auto-revert admin notification emitted on refresh-token-revoked")
	}
	if n := rn.countOf(notify.KindAutoReverted); n != 1 {
		t.Errorf("auto-revert notifications = %d, want exactly 1 (no double-notify)", n)
	}
	if rn.countOf(notify.KindWorkerCrashed) != 0 {
		t.Error("worker-crashed notification emitted on a non-panic path")
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
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), bus, nil, nil)
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

// TestWorkerRevertsToPendingOnUnrecoverableAuth is the end-to-end test
// for the SPEC-0002 REQ "Backoff on Failure" non-token permanent path:
// when Proton's GetEvent surfaces an HTTP 403 (the session is forbidden
// from the events endpoint -- account locked, scope insufficient,
// needs re-unlock, or disabled), the worker MUST stop retrying and
// revert the account to pending_proton_setup so the admin re-runs the
// wizard, rather than walking the backoff curve forever.
//
// We route 403 to pending (recoverable), NOT suspended: a 403 is often
// recoverable and the upstream gives no account-deleted signal that
// would justify a permanent suspension of a possibly-healthy account.
//
// Governing: SPEC-0002 REQ "Backoff on Failure" — "Permanent errors do
// not retry indefinitely".
func TestWorkerRevertsToPendingOnUnrecoverableAuth(t *testing.T) {
	t.Parallel()
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-unrecoverable-auth")

	authErr := &gpa.APIError{
		Status:  http.StatusForbidden,
		Message: "forbidden from events endpoint",
	}
	var calls int32
	fc := &fakeProtonClient{
		latest: "evt-bootstrap",
		getEventFn: func(string) ([]proton.Event, bool, error) {
			atomic.AddInt32(&calls, 1)
			return nil, false, authErr
		},
	}

	rn := &recordingNotifier{}
	cfg := fastConfig()
	cfg.PollInterval = 5 * time.Millisecond
	cfg.Notifier = rn
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

	// The worker MUST revert the account to pending_proton_setup and
	// drop out of the live map.
	if !waitFor(t, 2*time.Second, func() bool {
		got, err := svc.GetByID(ctx, a.ID)
		if err != nil {
			return false
		}
		return got.State == account.StatePendingProtonSetup
	}) {
		got, _ := svc.GetByID(ctx, a.ID)
		t.Fatalf("account state never reverted to pending; got=%+v", got)
	}
	if !waitFor(t, time.Second, func() bool { return sup.activeWorkerCount() == 0 }) {
		t.Fatalf("worker still in live map after unrecoverable auth; count=%d", sup.activeWorkerCount())
	}

	// MUST NOT suspend (the BLOCKER fix: an ambiguous 403 cannot
	// permanently halt a possibly-healthy account).
	got, err := svc.GetByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.State == account.StateSuspended {
		t.Fatal("account was suspended on a 403; an ambiguous 403 must route to pending, not suspended")
	}
	// crashed flag MUST NOT be set on a clean revert — the transition
	// succeeded, so this is not a stuck/needs-reset state.
	if got.Crashed {
		t.Error("crashed flag set on clean revert-to-pending; flag is for stuck states only")
	}

	// No infinite retry: once reverted, the worker has exited, so the
	// GetEvent call count must stop climbing. Capture, wait, re-check.
	settled := atomic.LoadInt32(&calls)
	time.Sleep(100 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != settled {
		t.Errorf("GetEvent kept being called after revert (%d -> %d); worker did not stop retrying", settled, got)
	}

	// The 403 auto-revert MUST surface exactly one admin notification.
	// Governing: SPEC-0002 REQ "Backoff on Failure".
	if n := rn.countOf(notify.KindAutoReverted); n != 1 {
		t.Errorf("auto-revert notifications = %d, want exactly 1", n)
	}
}

// TestIsUnrecoverableProtonError unit-tests the predicate so the
// non-token permanent classification is locked down independently of
// the worker integration. Only HTTP 403 trips it; token-revoked,
// stale-cursor, 5xx (NOT retried by the upstream transport) and 429
// are handled elsewhere and MUST NOT trip this predicate.
//
// Governing: SPEC-0002 REQ "Backoff on Failure".
func TestIsUnrecoverableProtonError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "http 403 forbidden",
			err:  &gpa.APIError{Status: http.StatusForbidden},
			want: true,
		},
		{
			name: "refresh-token-revoked (401) is not classified here",
			err:  &gpa.APIError{Status: http.StatusUnauthorized, Code: gpa.AuthRefreshTokenInvalid},
			want: false,
		},
		{
			name: "stale cursor (422 + InvalidValue) is not unrecoverable",
			err:  &gpa.APIError{Status: 422, Code: gpa.InvalidValue},
			want: false,
		},
		{
			name: "5xx walks the worker backoff curve, not this path",
			err:  &gpa.APIError{Status: http.StatusBadGateway},
			want: false,
		},
		{
			name: "429 rate limit is transient (upstream retries it)",
			err:  &gpa.APIError{Status: http.StatusTooManyRequests},
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
			if got := isUnrecoverableProtonError(tc.err); got != tc.want {
				t.Errorf("isUnrecoverableProtonError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// failingTransition wraps an account.Service and forces Transition to
// return a fixed error, while recording whether MarkCrashed was called.
// `marked` is closed the first time MarkCrashed fires so tests can wait
// on a signal rather than poll, and assert the NEGATIVE (crash never
// fired) by selecting on the channel with a timeout. Every other method
// delegates.
type failingTransition struct {
	account.Service
	mu            sync.Mutex
	markedCrash   bool
	marked        chan struct{}
	transitionErr error
}

func newFailingTransition(svc account.Service, transitionErr error) *failingTransition {
	return &failingTransition{Service: svc, marked: make(chan struct{}), transitionErr: transitionErr}
}

func (f *failingTransition) Transition(_ context.Context, _ string, _ account.State) (*account.Account, error) {
	return nil, f.transitionErr
}

func (f *failingTransition) MarkCrashed(context.Context, string) error {
	f.mu.Lock()
	first := !f.markedCrash
	f.markedCrash = true
	f.mu.Unlock()
	if first {
		close(f.marked)
	}
	return nil
}

func (f *failingTransition) RewrapEnvelopes(context.Context, cryptenv.MasterKey) (int, error) {
	panic("not implemented")
}

// TestPermanentTransitionFailureMarksCrashed pins the fire-and-forget
// fix: the permanent-failure transition is NO LONGER lost on failure.
// When the account.Transition that processOnce dispatches keeps failing
// (a real DB/lock failure, not an already-left-active no-op), the
// worker MUST mark the account crashed so it does not silently appear
// active-and-healthy with no worker behind it. This drives processOnce'
// permanent-failure path with a service whose Transition always fails
// for a non-ErrInvalidTransition reason and asserts the crashed
// fallback fires.
//
// Governing: SPEC-0002 REQ "Backoff on Failure" (permanent-failure
// transition must not be lost), SPEC-0002 REQ "Panic Isolation"
// (crashed flag is the operator-visible signal).
func TestPermanentTransitionFailureMarksCrashed(t *testing.T) {
	t.Parallel()
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-transition-fails")

	authErr := &gpa.APIError{Status: http.StatusForbidden, Message: "forbidden"}
	fc := &fakeProtonClient{
		latest: "evt-bootstrap",
		getEventFn: func(string) ([]proton.Event, bool, error) {
			return nil, false, authErr
		},
	}
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), nil, nil, nil)
	if err != nil {
		t.Fatalf("newEventProcessor: %v", err)
	}
	// Swap in a service whose Transition always fails (non-recoverable,
	// not ErrInvalidTransition) so dispatchPermanentTransition exhausts
	// its retries and falls back to MarkCrashed. lifetimeCtx is left as
	// the live (uncancelled) background ctx so the retry loop runs to
	// exhaustion rather than abandoning on shutdown.
	failing := newFailingTransition(svc, errors.New("simulated transition failure"))
	proc.svc = failing

	if _, err := proc.processOnce(ctx); !errors.Is(err, errUnrecoverableAuth) {
		t.Fatalf("processOnce error = %v, want errUnrecoverableAuth", err)
	}

	// dispatchPermanentTransition runs in a detached goroutine that
	// retries permanentTransitionRetries times with a short delay, then
	// marks crashed. Wait on the signal channel (generous slack over the
	// retry budget).
	select {
	case <-failing.marked:
	case <-time.After(3 * time.Second):
		t.Fatal("MarkCrashed was never called after the permanent-failure transition kept failing; account would be left looking active")
	}
}

// TestPermanentTransitionAlreadyLeftActiveSkipsCrash pins the inverse:
// if the account has already moved out of active by the time the
// detached transition runs (e.g. an admin suspended it concurrently),
// Transition returns ErrInvalidTransition, which is NOT a failure to
// recover from — the worker-stop intent is already satisfied, so
// MarkCrashed MUST NOT fire. Asserting the negative via the `marked`
// channel + a bounded wait is less fragile than a fixed sleep.
//
// Governing: SPEC-0002 REQ "Backoff on Failure".
func TestPermanentTransitionAlreadyLeftActiveSkipsCrash(t *testing.T) {
	t.Parallel()
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-already-left")

	authErr := &gpa.APIError{Status: http.StatusForbidden, Message: "forbidden"}
	fc := &fakeProtonClient{
		latest: "evt-bootstrap",
		getEventFn: func(string) ([]proton.Event, bool, error) {
			return nil, false, authErr
		},
	}
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), nil, nil, nil)
	if err != nil {
		t.Fatalf("newEventProcessor: %v", err)
	}
	failing := newFailingTransition(svc, account.ErrInvalidTransition)
	proc.svc = failing

	if _, err := proc.processOnce(ctx); !errors.Is(err, errUnrecoverableAuth) {
		t.Fatalf("processOnce error = %v, want errUnrecoverableAuth", err)
	}

	// The detached goroutine should return on the FIRST attempt (no
	// retries, no crash) because ErrInvalidTransition is terminal-OK.
	// MarkCrashed must never fire.
	select {
	case <-failing.marked:
		t.Error("MarkCrashed fired on ErrInvalidTransition; an already-left-active account is not a stuck state")
	case <-time.After(500 * time.Millisecond):
		// Expected: no crash signal.
	}
}

// TestPermanentTransitionAbandonsQuietlyOnShutdown pins the
// shutdown-aware retry path: when the supervisor-lifetime context is
// cancelled (process shutting down) and the transition keeps failing,
// the detached goroutine MUST abandon without marking the account
// crashed -- a transition failure against a closing DB is benign and
// must not emit a scary "account may remain active" ERROR or flip the
// crashed flag on every clean stop.
//
// Governing: SPEC-0002 REQ "Graceful Shutdown".
func TestPermanentTransitionAbandonsQuietlyOnShutdown(t *testing.T) {
	t.Parallel()
	svc, usrSvc := newTestAccountService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, usrSvc, "sub-shutdown-abandon")

	authErr := &gpa.APIError{Status: http.StatusForbidden, Message: "forbidden"}
	fc := &fakeProtonClient{
		latest: "evt-bootstrap",
		getEventFn: func(string) ([]proton.Event, bool, error) {
			return nil, false, authErr
		},
	}
	proc, err := newEventProcessor(ctx, a.ID, svc, fc, nopLogger(), nil, nil, nil)
	if err != nil {
		t.Fatalf("newEventProcessor: %v", err)
	}
	// Pre-cancelled lifetime context simulates a supervisor already
	// shutting down: the detached retry loop must bail at the first
	// cancel-aware sleep without ever reaching MarkCrashed.
	lifeCtx, cancel := context.WithCancel(context.Background())
	cancel()
	proc.lifetimeCtx = lifeCtx
	failing := newFailingTransition(svc, errors.New("simulated transition failure during shutdown"))
	proc.svc = failing

	if _, err := proc.processOnce(ctx); !errors.Is(err, errUnrecoverableAuth) {
		t.Fatalf("processOnce error = %v, want errUnrecoverableAuth", err)
	}

	select {
	case <-failing.marked:
		t.Error("MarkCrashed fired during shutdown; a transition failure against a closing DB must be abandoned quietly")
	case <-time.After(500 * time.Millisecond):
		// Expected: abandoned quietly, no crash flag.
	}
}
