package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/keychain"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/store"
	syncengine "github.com/joestump/reduit/internal/sync"
)

// --- sync test doubles ------------------------------------------------------

// syncTestDialer resumes a per-Proton-user client (keyed by proton_user_id) or a
// scripted per-user error, so a multi-mailbox sync runs entirely offline and one
// mailbox's Resume can be failed in isolation. It satisfies syncengine.Dialer.
type syncTestDialer struct {
	clients map[string]proton.Client
	errs    map[string]error
}

func (d *syncTestDialer) Resume(_ context.Context, protonUserID, _, _ string) (proton.Client, error) {
	if err := d.errs[protonUserID]; err != nil {
		return nil, err
	}
	c, ok := d.clients[protonUserID]
	if !ok {
		return nil, errors.New("syncTestDialer: no client for " + protonUserID)
	}
	return c, nil
}

// authedSyncFake returns a *proton.Fake already marked authenticated (as a real
// Resume leaves it), pre-scripted to bootstrap the given messages.
func authedSyncFake(token, uid, latestEvent string, backfill []string, msgs map[string]proton.DecryptedMessage) *proton.Fake {
	f := proton.NewFake()
	f.Token = token
	f.UID = uid
	_ = f.Refresh(context.Background()) // marks authed like a cold resume
	f.LabelList = []proton.Label{{ID: "0", Name: "Inbox", Type: proton.LabelTypeSystem}}
	f.LatestEvent = latestEvent
	f.BackfillIDs = backfill
	f.Messages = msgs
	return f
}

func syncMsg(id, subject string) proton.DecryptedMessage {
	return proton.DecryptedMessage{
		MessageID: id,
		Subject:   subject,
		Sender:    proton.Address{Name: "Sender", Email: "sender@example.com"},
		To:        []proton.Address{{Name: "Recip", Email: "recip@example.com"}},
		Date:      time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		MIMEType:  "text/plain",
		Body:      []byte("hello " + id),
		LabelIDs:  []string{"0"},
	}
}

// seedActiveSyncMailbox inserts an active mailbox with its secrets, matching how
// the auth layer leaves a freshly-added mailbox.
func seedActiveSyncMailbox(t *testing.T, st *store.Store, ks keychain.Store, id, address, userID, uid, token, pass string) {
	t.Helper()
	ctx := context.Background()
	if err := st.InsertMailbox(ctx, id, address); err != nil {
		t.Fatalf("insert mailbox: %v", err)
	}
	if err := st.SetProtonUserID(ctx, id, userID); err != nil { // also sets state=active
		t.Fatalf("set proton_user_id: %v", err)
	}
	if err := st.SetSessionUID(ctx, id, uid); err != nil {
		t.Fatalf("set session_uid: %v", err)
	}
	if err := ks.Set(id, keychain.RefreshToken, token); err != nil {
		t.Fatalf("set refresh token: %v", err)
	}
	if err := ks.Set(id, keychain.MailboxPassphrase, pass); err != nil {
		t.Fatalf("set passphrase: %v", err)
	}
}

func newTestSyncEngine(st *store.Store, ks keychain.Store, d syncengine.Dialer) *syncengine.Engine {
	return syncengine.New(syncengine.Deps{Store: st, Keychain: ks, Dialer: d})
}

// --- one-shot SyncAll -------------------------------------------------------

func TestRunSync_OneShot_SyncAll_PrintsSummaryExitsZero(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)
	seedActiveSyncMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")

	fake := authedSyncFake("tok-1", "uid-1", "ev-1", []string{"m1", "m2"}, map[string]proton.DecryptedMessage{
		"m1": syncMsg("m1", "Hello"),
		"m2": syncMsg("m2", "World"),
	})
	eng := newTestSyncEngine(st, ks, &syncTestDialer{clients: map[string]proton.Client{"user-1": fake}})

	var out bytes.Buffer
	if err := runSync(ctx, st, eng, syncOptions{}, &out); err != nil {
		t.Fatalf("runSync: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "joe@proton.test") {
		t.Errorf("summary missing address: %q", got)
	}
	if !strings.Contains(got, "TOTAL (1)") {
		t.Errorf("summary missing total line: %q", got)
	}
	// Cursor was persisted at the bootstrap head — the run really synced.
	ss, err := st.GetSyncState(ctx, "mb-1")
	if err != nil {
		t.Fatalf("GetSyncState: %v", err)
	}
	if ss.EventCursor == nil || *ss.EventCursor != "ev-1" {
		t.Errorf("cursor = %v, want ev-1", ss.EventCursor)
	}
}

func TestRunSync_NoMailboxes_PrintsHint(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)
	eng := newTestSyncEngine(st, ks, &syncTestDialer{})

	var out bytes.Buffer
	if err := runSync(ctx, st, eng, syncOptions{}, &out); err != nil {
		t.Fatalf("runSync: %v", err)
	}
	if !strings.Contains(out.String(), "No active mailboxes") {
		t.Errorf("want no-mailbox hint, got %q", out.String())
	}
}

// --- mailbox selection ------------------------------------------------------

func TestRunSync_Mailbox_SelectsOne_OthersUntouched(t *testing.T) {
	ks := newTestKeychain(t)

	for _, tc := range []struct {
		name string
		sel  func(a, b store.Mailbox) string // returns the --mailbox selector for A
	}{
		{"by address", func(a, _ store.Mailbox) string { return a.Address }},
		{"by id", func(a, _ store.Mailbox) string { return a.ID }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st := newTestStore(t)
			seedActiveSyncMailbox(t, st, ks, "mb-a", "a@proton.test", "user-a", "uid-a", "tok-a", "pass-a")
			seedActiveSyncMailbox(t, st, ks, "mb-b", "b@proton.test", "user-b", "uid-b", "tok-b", "pass-b")

			fakeA := authedSyncFake("tok-a", "uid-a", "ev-a", []string{"a1"}, map[string]proton.DecryptedMessage{"a1": syncMsg("a1", "A")})
			fakeB := authedSyncFake("tok-b", "uid-b", "ev-b", []string{"b1"}, map[string]proton.DecryptedMessage{"b1": syncMsg("b1", "B")})
			eng := newTestSyncEngine(st, ks, &syncTestDialer{clients: map[string]proton.Client{"user-a": fakeA, "user-b": fakeB}})

			a, err := st.GetMailbox(ctx, "mb-a")
			if err != nil {
				t.Fatalf("GetMailbox: %v", err)
			}
			var out bytes.Buffer
			if err := runSync(ctx, st, eng, syncOptions{mailbox: tc.sel(a, store.Mailbox{})}, &out); err != nil {
				t.Fatalf("runSync: %v", err)
			}

			// A synced (cursor set); B untouched (no cursor).
			ssA, _ := st.GetSyncState(ctx, "mb-a")
			if ssA.EventCursor == nil || *ssA.EventCursor != "ev-a" {
				t.Errorf("A cursor = %v, want ev-a", ssA.EventCursor)
			}
			ssB, _ := st.GetSyncState(ctx, "mb-b")
			if ssB.EventCursor != nil {
				t.Errorf("B cursor = %v, want nil (untouched)", ssB.EventCursor)
			}
			if strings.Contains(out.String(), "b@proton.test") {
				t.Errorf("summary should not mention mailbox B: %q", out.String())
			}
		})
	}
}

func TestRunSync_Mailbox_Unknown_Errors(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)
	eng := newTestSyncEngine(st, ks, &syncTestDialer{})

	var out bytes.Buffer
	err := runSync(ctx, st, eng, syncOptions{mailbox: "nope@proton.test"}, &out)
	if err == nil || !strings.Contains(err.Error(), "no mailbox configured matching") {
		t.Fatalf("err = %v, want no-match error", err)
	}
}

// --- full rescan resets the cursor -----------------------------------------

func TestRunSync_Full_ResetsCursor_ReBootstraps(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)
	seedActiveSyncMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")

	// Seed a stale cursor so a normal run would TAIL (no scripted events → no
	// work) rather than bootstrap. --full must clear it and re-bootstrap.
	if err := st.UpsertSyncState(ctx, "mb-1", "seeded-cursor", time.Now().UTC()); err != nil {
		t.Fatalf("UpsertSyncState: %v", err)
	}

	fake := authedSyncFake("tok-1", "uid-1", "ev-1", []string{"m1", "m2"}, map[string]proton.DecryptedMessage{
		"m1": syncMsg("m1", "Hello"),
		"m2": syncMsg("m2", "World"),
	})
	eng := newTestSyncEngine(st, ks, &syncTestDialer{clients: map[string]proton.Client{"user-1": fake}})

	// Sanity: without --full it tails from the seeded cursor and imports nothing.
	var out bytes.Buffer
	if err := runSync(ctx, st, eng, syncOptions{mailbox: "mb-1"}, &out); err != nil {
		t.Fatalf("tail run: %v", err)
	}
	if n := countMessages(t, st); n != 0 {
		t.Fatalf("tail imported %d messages, want 0", n)
	}

	// With --full the cursor is reset → bootstrap → backfill imports both.
	out.Reset()
	if err := runSync(ctx, st, eng, syncOptions{mailbox: "mb-1", full: true}, &out); err != nil {
		t.Fatalf("full run: %v", err)
	}
	if n := countMessages(t, st); n != 2 {
		t.Errorf("full run imported %d messages, want 2 (re-bootstrap)", n)
	}
	// The re-bootstrap advanced the cursor to the fresh head.
	ss, _ := st.GetSyncState(ctx, "mb-1")
	if ss.EventCursor == nil || *ss.EventCursor != "ev-1" {
		t.Errorf("cursor after full = %v, want ev-1", ss.EventCursor)
	}
}

// --- a mailbox failure is a non-zero exit -----------------------------------

func TestRunSync_MailboxErr_NonZeroExit(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)
	seedActiveSyncMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")

	// Resume fails for this mailbox → the run records RunSummary.Err.
	resumeErr := errors.New("invalid refresh token")
	eng := newTestSyncEngine(st, ks, &syncTestDialer{errs: map[string]error{"user-1": resumeErr}})

	var out bytes.Buffer
	err := runSync(ctx, st, eng, syncOptions{}, &out)
	if err == nil {
		t.Fatal("runSync returned nil, want a non-nil error (non-zero exit)")
	}
	if !strings.Contains(err.Error(), "failed to sync") {
		t.Errorf("err = %v, want failure summary", err)
	}
	// The cause is printed in the per-mailbox summary.
	if !strings.Contains(out.String(), "invalid refresh token") {
		t.Errorf("summary missing failure cause: %q", out.String())
	}
}

// --- watch loop stops on a cancelled context --------------------------------

// countingRunner records how many times a sync pass ran and cancels the loop's
// context on the first pass, so the watch loop stops deterministically after one
// iteration with no real sleeps.
type countingRunner struct {
	cancel context.CancelFunc
	calls  int
}

func (r *countingRunner) SyncAll(context.Context) ([]syncengine.RunSummary, error) {
	r.calls++
	r.cancel() // signal "stop" the way SIGINT would
	return nil, nil
}

func (r *countingRunner) SyncMailbox(context.Context, string) (syncengine.RunSummary, error) {
	return syncengine.RunSummary{}, nil
}

func TestRunSync_Watch_RunsOnceThenStopsOnCancel(t *testing.T) {
	st := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runner := &countingRunner{cancel: cancel}
	var out bytes.Buffer
	// A long interval proves the loop exits via ctx cancellation, not the timer.
	if err := runSync(ctx, st, runner, syncOptions{watch: time.Hour}, &out); err != nil {
		t.Fatalf("runSync watch: %v", err)
	}
	if runner.calls != 1 {
		t.Errorf("watch ran %d times, want exactly 1 before cancel", runner.calls)
	}
}

func countMessages(t *testing.T, st *store.Store) int {
	t.Helper()
	var n int
	if err := st.DB.GetContext(context.Background(), &n, "SELECT COUNT(*) FROM messages"); err != nil {
		t.Fatalf("count messages: %v", err)
	}
	return n
}
