package syncengine

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/keychain"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/store"
)

// --- test doubles -----------------------------------------------------------

// memKeychain is an in-memory keychain.Store. Unlike the OS keyring mock the CLI
// tests use, it is per-instance so these tests stay isolated and parallel-safe.
type memKeychain struct {
	mu sync.Mutex
	m  map[string]string
}

func newMemKeychain() *memKeychain { return &memKeychain{m: map[string]string{}} }

func (k *memKeychain) key(id string, kind keychain.Kind) string { return id + "/" + string(kind) }

func (k *memKeychain) Set(id string, kind keychain.Kind, secret string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.m[k.key(id, kind)] = secret
	return nil
}

func (k *memKeychain) Get(id string, kind keychain.Kind) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.m[k.key(id, kind)]
	if !ok {
		return "", keychain.ErrNotFound
	}
	return v, nil
}

func (k *memKeychain) Delete(id string, kind keychain.Kind) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	key := k.key(id, kind)
	if _, ok := k.m[key]; !ok {
		return keychain.ErrNotFound
	}
	delete(k.m, key)
	return nil
}

func (k *memKeychain) DeleteAll(id string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, kind := range []keychain.Kind{keychain.RefreshToken, keychain.AccessToken, keychain.MailboxPassphrase, keychain.SaltedKeyPass} {
		delete(k.m, k.key(id, kind))
	}
	return nil
}

// fakeDialer resumes a per-Proton-user client (keyed by proton_user_id) or a
// scripted per-user error, so a multi-mailbox run can be driven entirely offline
// and one mailbox's Resume can be failed in isolation.
type fakeDialer struct {
	clients map[string]proton.Client
	errs    map[string]error
}

func (d *fakeDialer) Resume(_ context.Context, protonUserID, _, _, _ string) (proton.Client, error) {
	if err := d.errs[protonUserID]; err != nil {
		return nil, err
	}
	c, ok := d.clients[protonUserID]
	if !ok {
		return nil, errors.New("fakeDialer: no client for " + protonUserID)
	}
	return c, nil
}

// flakyClient wraps a *proton.Fake to inject a GetEvents failure on a chosen
// call, so the cursor/delta atomicity and resumability paths are testable.
type flakyClient struct {
	*proton.Fake
	getEventsErrOn int // 1-based call index to fail on; 0 = never
	getEventsErr   error
	calls          int
}

func (c *flakyClient) GetEvents(ctx context.Context, since string) (proton.EventBatch, error) {
	c.calls++
	if c.getEventsErrOn != 0 && c.calls == c.getEventsErrOn {
		return proton.EventBatch{}, c.getEventsErr
	}
	return c.Fake.GetEvents(ctx, since)
}

// panicClient wraps a *proton.Fake and panics from Labels, modeling a mailbox
// whose sync blows up mid-routine.
type panicClient struct {
	*proton.Fake
}

func (panicClient) Labels(context.Context) ([]proton.Label, error) { panic("boom in labels") }

// decryptNetClient wraps a *proton.Fake and returns proton.ErrNetwork from
// DecryptMessage for the ids in failIDs, modeling a TRANSIENT decrypt failure
// that outlives the engine's retries. Clearing an id (delete from failIDs) lets
// a subsequent run decrypt it normally — the "network restored" case.
type decryptNetClient struct {
	*proton.Fake
	failIDs map[string]bool
}

func (c *decryptNetClient) DecryptMessage(ctx context.Context, id string) (proton.DecryptedMessage, error) {
	if c.failIDs[id] {
		return proton.DecryptedMessage{}, proton.ErrNetwork
	}
	return c.Fake.DecryptMessage(ctx, id)
}

// eventScriptClient models Proton's real cursor-based event replay: GetEvents
// returns the batch keyed by the REQUESTED cursor (not a FIFO index), so a run
// that aborts without advancing the cursor re-fetches the same batch next run.
// It also injects transient decrypt failures via failIDs like decryptNetClient.
type eventScriptClient struct {
	*proton.Fake
	batches map[string]proton.EventBatch // keyed by the requested cursor
	failIDs map[string]bool
}

func (c *eventScriptClient) GetEvents(_ context.Context, since string) (proton.EventBatch, error) {
	if b, ok := c.batches[since]; ok {
		return b, nil
	}
	return proton.EventBatch{NextCursor: since}, nil
}

func (c *eventScriptClient) DecryptMessage(ctx context.Context, id string) (proton.DecryptedMessage, error) {
	if c.failIDs[id] {
		return proton.DecryptedMessage{}, proton.ErrNetwork
	}
	return c.Fake.DecryptMessage(ctx, id)
}

// --- helpers ----------------------------------------------------------------

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(""); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return st
}

// authedFake returns a *proton.Fake already marked authenticated (as a real
// Resume leaves it), so the engine's Unlock/data calls succeed. Token/UID are
// pre-set to the stored values so no rotation write occurs.
func authedFake(token, uid string) *proton.Fake {
	f := proton.NewFake()
	f.Token = token
	f.UID = uid
	f.Access = accessFor(token)         // matches the seeded keychain access token
	_ = f.Refresh(context.Background()) // marks authed like a cold resume
	return f
}

// accessFor derives the access token seedActiveMailbox stores for a mailbox from
// its refresh token, so authedFake and the seeded keychain agree and no spurious
// rotation write occurs.
func accessFor(token string) string { return "acc-" + token }

// seedActiveMailbox inserts an active mailbox with its secrets, matching how the
// auth layer leaves a freshly-added mailbox.
func seedActiveMailbox(t *testing.T, st *store.Store, ks keychain.Store, id, address, userID, uid, token, pass string) {
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
	if err := ks.Set(id, keychain.AccessToken, accessFor(token)); err != nil {
		t.Fatalf("set access token: %v", err)
	}
	if err := ks.Set(id, keychain.MailboxPassphrase, pass); err != nil {
		t.Fatalf("set passphrase: %v", err)
	}
}

// newEngine builds an engine with instantaneous backoff for tests.
func newEngine(st *store.Store, ks keychain.Store, d Dialer, cfg Config) *Engine {
	e := New(Deps{Store: st, Keychain: ks, Dialer: d, Config: cfg})
	e.sleep = func(context.Context, time.Duration) {} // no real backoff in tests
	return e
}

func inboxLabels() []proton.Label {
	return []proton.Label{
		{ID: "0", Name: "Inbox", Type: proton.LabelTypeSystem},
		{ID: "7", Name: "Sent", Type: proton.LabelTypeSystem},
		{ID: "lbl-1", Name: "Work", Type: proton.LabelTypeLabel},
	}
}

func msg(id, subject, sender string, labelIDs []string, body string, atts ...proton.AttachmentMeta) proton.DecryptedMessage {
	return proton.DecryptedMessage{
		MessageID:   id,
		Subject:     subject,
		Sender:      proton.Address{Name: "Sender", Email: sender},
		To:          []proton.Address{{Name: "Recip", Email: "recip@example.com"}},
		Date:        time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		MIMEType:    "text/plain",
		Body:        []byte(body),
		LabelIDs:    labelIDs,
		Attachments: atts,
	}
}

func countRows(t *testing.T, st *store.Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := st.DB.GetContext(context.Background(), &n, query, args...); err != nil {
		t.Fatalf("count query %q: %v", query, err)
	}
	return n
}

// --- tests ------------------------------------------------------------------

func TestBootstrap_BackfillsMessagesAndSetsCursor(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newMemKeychain()
	seedActiveMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")

	fake := authedFake("tok-1", "uid-1")
	fake.LabelList = inboxLabels()
	fake.LatestEvent = "ev-100"
	fake.BackfillIDs = []string{"m1", "m2"}
	fake.Messages = map[string]proton.DecryptedMessage{
		"m1": msg("m1", "Hello world", "alice@example.com", []string{"0"},
			"Check https://example.com/report for details.",
			proton.AttachmentMeta{ID: "a1", Name: "report.pdf", MIMEType: "application/pdf", Size: 12}),
		"m2": msg("m2", "Zebra stripes", "bob@example.com", []string{"7"}, "no links here"),
	}

	eng := newEngine(st, ks, &fakeDialer{clients: map[string]proton.Client{"user-1": fake}}, Config{})

	sum, err := eng.SyncMailbox(ctx, "mb-1")
	if err != nil {
		t.Fatalf("SyncMailbox: %v", err)
	}
	if sum.Err != nil {
		t.Fatalf("run err: %v", sum.Err)
	}
	if sum.Added != 2 || sum.Updated != 0 || sum.Errors != 0 {
		t.Errorf("counts = added %d updated %d errors %d, want 2/0/0", sum.Added, sum.Updated, sum.Errors)
	}
	if sum.Attachments != 1 {
		t.Errorf("attachments = %d, want 1", sum.Attachments)
	}

	if n := countRows(t, st, `SELECT COUNT(*) FROM messages`); n != 2 {
		t.Errorf("messages rows = %d, want 2", n)
	}
	// Contacts materialized for sender + recipient of each message.
	if n := countRows(t, st, `SELECT COUNT(*) FROM contact_identifiers WHERE address = ?`, "alice@example.com"); n != 1 {
		t.Errorf("alice identifier rows = %d, want 1", n)
	}
	// Link extracted from m1's body.
	if n := countRows(t, st, `SELECT COUNT(*) FROM links WHERE url = ?`, "https://example.com/report"); n != 1 {
		t.Errorf("link rows = %d, want 1", n)
	}
	// Attachment metadata written.
	if n := countRows(t, st, `SELECT COUNT(*) FROM attachments WHERE proton_att_id = ?`, "a1"); n != 1 {
		t.Errorf("attachment rows = %d, want 1", n)
	}
	// FTS finds the messages by content (trigger-maintained).
	if n := countRows(t, st, `SELECT COUNT(*) FROM messages_fts WHERE messages_fts MATCH 'Zebra'`); n != 1 {
		t.Errorf("FTS match Zebra = %d, want 1", n)
	}
	// Folder resolved from the system label.
	var folder string
	if err := st.DB.GetContext(ctx, &folder, `SELECT folder FROM messages WHERE proton_id = 'm1'`); err != nil {
		t.Fatalf("read folder: %v", err)
	}
	if folder != "Inbox" {
		t.Errorf("folder = %q, want Inbox", folder)
	}

	// Cursor set to the PRE-backfill head so tail resumes from before it.
	ss, err := st.GetSyncState(ctx, "mb-1")
	if err != nil {
		t.Fatalf("GetSyncState: %v", err)
	}
	if ss.EventCursor == nil || *ss.EventCursor != "ev-100" {
		t.Errorf("cursor = %v, want ev-100", ss.EventCursor)
	}

	// A per-run summary was persisted with the right counts.
	run, ok, err := st.LatestSyncRun(ctx, "mb-1")
	if err != nil || !ok {
		t.Fatalf("LatestSyncRun: ok=%v err=%v", ok, err)
	}
	if run.Added != 2 || run.Attachments != 1 || run.LastError != nil {
		t.Errorf("sync_run = %+v, want added 2 attachments 1 no error", run)
	}
	// last_sync_at stamped on success.
	m, _ := st.GetMailbox(ctx, "mb-1")
	if m.LastSyncAt == nil {
		t.Error("last_sync_at not stamped after successful run")
	}
}

func TestTail_AppliesCreatesUpdatesDeletes(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newMemKeychain()
	seedActiveMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")

	// Pre-set a cursor so the engine tails rather than bootstraps.
	if err := st.UpsertSyncState(ctx, "mb-1", "ev-0", time.Now().UTC()); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}

	fake := authedFake("tok-1", "uid-1")
	fake.LabelList = inboxLabels()
	fake.Messages = map[string]proton.DecryptedMessage{
		"m1": msg("m1", "First", "alice@example.com", []string{"0"}, "body one"),
		"m3": msg("m3", "Third", "carol@example.com", []string{"0"}, "body three"),
	}
	fake.Batches = []proton.EventBatch{
		{Events: []proton.Event{{EventID: "ev-1", Messages: []proton.MessageEvent{
			{Action: proton.EventCreate, MessageID: "m1"},
			{Action: proton.EventCreate, MessageID: "m3"},
		}}}, NextCursor: "ev-1", More: true},
		{Events: []proton.Event{{EventID: "ev-2", Messages: []proton.MessageEvent{
			{Action: proton.EventUpdate, MessageID: "m1"},
			{Action: proton.EventDelete, MessageID: "m3"},
		}}}, NextCursor: "ev-2", More: false},
	}

	eng := newEngine(st, ks, &fakeDialer{clients: map[string]proton.Client{"user-1": fake}}, Config{})

	sum, err := eng.SyncMailbox(ctx, "mb-1")
	if err != nil {
		t.Fatalf("SyncMailbox: %v", err)
	}
	// batch1: create m1 + m3 = 2 adds. batch2: update m1 = 1 update, delete m3 = 1 delete.
	if sum.Added != 2 || sum.Updated != 1 || sum.Deleted != 1 {
		t.Errorf("counts = added %d updated %d deleted %d, want 2/1/1", sum.Added, sum.Updated, sum.Deleted)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM messages`); n != 1 {
		t.Errorf("messages rows = %d, want 1 (m3 deleted)", n)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM messages WHERE proton_id = 'm3'`); n != 0 {
		t.Errorf("m3 still present after delete")
	}
	ss, _ := st.GetSyncState(ctx, "mb-1")
	if ss.EventCursor == nil || *ss.EventCursor != "ev-2" {
		t.Errorf("cursor = %v, want ev-2", ss.EventCursor)
	}

	// Re-run with the stream drained is a no-op (incremental by default).
	sum2, err := eng.SyncMailbox(ctx, "mb-1")
	if err != nil {
		t.Fatalf("SyncMailbox rerun: %v", err)
	}
	if sum2.Added != 0 || sum2.Updated != 0 || sum2.Deleted != 0 {
		t.Errorf("re-run not a no-op: %+v", sum2)
	}
}

func TestResync_ConvergesWithoutDuplicates(t *testing.T) {
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
	// bootstrap is called directly here (bypassing resumeClient), so unlock the
	// fake ourselves — a real Resume+Unlock would have.
	if err := fake.Unlock(ctx, []byte("pass-1")); err != nil {
		t.Fatalf("unlock fake: %v", err)
	}
	m, _ := st.GetMailbox(ctx, "mb-1")
	folders := newFolderResolver(fake.LabelList)
	eng := newEngine(st, ks, &fakeDialer{clients: map[string]proton.Client{"user-1": fake}}, Config{})

	var first RunSummary
	if err := eng.bootstrap(ctx, fake, m, folders, &first); err != nil {
		t.Fatalf("bootstrap 1: %v", err)
	}
	if first.Added != 2 || first.Updated != 0 {
		t.Errorf("first bootstrap counts = %d/%d, want 2/0", first.Added, first.Updated)
	}

	var second RunSummary
	if err := eng.bootstrap(ctx, fake, m, folders, &second); err != nil {
		t.Fatalf("bootstrap 2: %v", err)
	}
	// Re-import converges: everything updates, nothing is added, count is stable.
	if second.Added != 0 || second.Updated != 2 {
		t.Errorf("second bootstrap counts = %d/%d, want 0/2", second.Added, second.Updated)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM messages`); n != 2 {
		t.Errorf("messages rows = %d after re-sync, want 2 (no duplicates)", n)
	}
}

func TestTail_RefreshTriggersRebootstrap(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newMemKeychain()
	seedActiveMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")
	if err := st.UpsertSyncState(ctx, "mb-1", "ev-old", time.Now().UTC()); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}

	fake := authedFake("tok-1", "uid-1")
	fake.LabelList = inboxLabels()
	fake.LatestEvent = "ev-fresh"
	fake.BackfillIDs = []string{"m1"}
	fake.Messages = map[string]proton.DecryptedMessage{
		"m1": msg("m1", "Rebootstrapped", "a@example.com", []string{"0"}, "body"),
	}
	fake.Batches = []proton.EventBatch{
		{Events: []proton.Event{{EventID: "ev-x", Refresh: true}}, NextCursor: "ev-x"},
	}

	eng := newEngine(st, ks, &fakeDialer{clients: map[string]proton.Client{"user-1": fake}}, Config{})
	sum, err := eng.SyncMailbox(ctx, "mb-1")
	if err != nil {
		t.Fatalf("SyncMailbox: %v", err)
	}
	if sum.Added != 1 {
		t.Errorf("added = %d, want 1 (re-bootstrap backfilled)", sum.Added)
	}
	ss, _ := st.GetSyncState(ctx, "mb-1")
	if ss.EventCursor == nil || *ss.EventCursor != "ev-fresh" {
		t.Errorf("cursor = %v, want ev-fresh (re-bootstrapped head)", ss.EventCursor)
	}
}

func TestDecryptFailure_SkipsAndContinues(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newMemKeychain()
	seedActiveMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")

	fake := authedFake("tok-1", "uid-1")
	fake.LabelList = inboxLabels()
	fake.LatestEvent = "ev-1"
	fake.BackfillIDs = []string{"m1", "m2", "m3"}
	// m2 is intentionally absent → DecryptMessage returns ErrMessageNotFound.
	fake.Messages = map[string]proton.DecryptedMessage{
		"m1": msg("m1", "One", "a@example.com", []string{"0"}, "b1"),
		"m3": msg("m3", "Three", "c@example.com", []string{"0"}, "b3"),
	}

	eng := newEngine(st, ks, &fakeDialer{clients: map[string]proton.Client{"user-1": fake}}, Config{})
	sum, err := eng.SyncMailbox(ctx, "mb-1")
	if err != nil {
		t.Fatalf("SyncMailbox: %v", err)
	}
	if sum.Err != nil {
		t.Fatalf("run should succeed despite one decrypt failure: %v", sum.Err)
	}
	if sum.Added != 2 || sum.Errors != 1 {
		t.Errorf("counts = added %d errors %d, want 2/1", sum.Added, sum.Errors)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM messages WHERE proton_id = 'm2'`); n != 0 {
		t.Errorf("m2 wrote a partial row; want none")
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM messages`); n != 2 {
		t.Errorf("messages rows = %d, want 2", n)
	}
}

func TestBootstrap_TransientDecryptAbortsAndRecovers(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newMemKeychain()
	seedActiveMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")

	base := authedFake("tok-1", "uid-1")
	base.LabelList = inboxLabels()
	base.LatestEvent = "ev-100"
	base.BackfillIDs = []string{"m1", "m2"}
	base.Messages = map[string]proton.DecryptedMessage{
		"m1": msg("m1", "One", "a@example.com", []string{"0"}, "b1"),
		"m2": msg("m2", "Two", "b@example.com", []string{"0"}, "b2"),
	}
	// m1 decrypt is transiently unreachable; retries are exhausted.
	client := &decryptNetClient{Fake: base, failIDs: map[string]bool{"m1": true}}
	eng := newEngine(st, ks, &fakeDialer{clients: map[string]proton.Client{"user-1": client}}, Config{})

	// Run 1: the transient decrypt aborts the bootstrap BEFORE the cursor is
	// persisted — a transient failure must not be bucketed with terminal skips.
	sum, err := eng.SyncMailbox(ctx, "mb-1")
	if err == nil || sum.Err == nil {
		t.Fatal("transient decrypt during backfill must fail the run, not skip")
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM messages WHERE proton_id = 'm1'`); n != 0 {
		t.Errorf("m1 should be absent after aborted bootstrap")
	}
	// Cursor stays nil so the next run re-bootstraps (no silent skip past m1).
	ss, _ := st.GetSyncState(ctx, "mb-1")
	if ss.EventCursor != nil {
		t.Fatalf("cursor = %v, want nil (bootstrap must not persist on abort)", ss.EventCursor)
	}

	// Run 2: network restored → re-bootstrap recovers m1 (and m2), cursor set.
	client.failIDs = map[string]bool{}
	sum2, err := eng.SyncMailbox(ctx, "mb-1")
	if err != nil {
		t.Fatalf("recovery run: %v", err)
	}
	if sum2.Err != nil {
		t.Fatalf("recovery run err: %v", sum2.Err)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM messages WHERE proton_id = 'm1'`); n != 1 {
		t.Errorf("m1 not recovered on re-bootstrap")
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM messages`); n != 2 {
		t.Errorf("messages rows = %d, want 2 after recovery", n)
	}
	ss2, _ := st.GetSyncState(ctx, "mb-1")
	if ss2.EventCursor == nil || *ss2.EventCursor != "ev-100" {
		t.Errorf("cursor = %v, want ev-100 after recovery", ss2.EventCursor)
	}
}

func TestTail_TransientDecryptAbortsAndRecovers(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newMemKeychain()
	seedActiveMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")
	if err := st.UpsertSyncState(ctx, "mb-1", "ev-0", time.Now().UTC()); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}

	base := authedFake("tok-1", "uid-1")
	base.LabelList = inboxLabels()
	base.Messages = map[string]proton.DecryptedMessage{
		"m1": msg("m1", "One", "a@example.com", []string{"0"}, "b1"),
	}
	client := &eventScriptClient{
		Fake: base,
		// The batch is keyed by the cursor it is fetched at, so an un-advanced
		// cursor re-fetches it — exactly Proton's behavior.
		batches: map[string]proton.EventBatch{
			"ev-0": {Events: []proton.Event{{EventID: "ev-1", Messages: []proton.MessageEvent{
				{Action: proton.EventCreate, MessageID: "m1"},
			}}}, NextCursor: "ev-1", More: false},
		},
		failIDs: map[string]bool{"m1": true},
	}
	eng := newEngine(st, ks, &fakeDialer{clients: map[string]proton.Client{"user-1": client}}, Config{})

	// Run 1: transient decrypt of m1 aborts the batch BEFORE the cursor advances.
	sum, err := eng.SyncMailbox(ctx, "mb-1")
	if err == nil || sum.Err == nil {
		t.Fatal("transient decrypt during tail must fail the run, not skip")
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM messages WHERE proton_id = 'm1'`); n != 0 {
		t.Errorf("m1 should be absent after aborted batch")
	}
	// Cursor did NOT advance past m1's create — no silent, permanent skip.
	ss, _ := st.GetSyncState(ctx, "mb-1")
	if ss.EventCursor == nil || *ss.EventCursor != "ev-0" {
		t.Fatalf("cursor = %v, want ev-0 (must not advance past a transiently-failed message)", ss.EventCursor)
	}

	// Run 2: network restored → the same batch is re-fetched from ev-0, m1 lands.
	client.failIDs = map[string]bool{}
	sum2, err := eng.SyncMailbox(ctx, "mb-1")
	if err != nil {
		t.Fatalf("recovery run: %v", err)
	}
	if sum2.Added != 1 {
		t.Errorf("recovery added = %d, want 1 (m1)", sum2.Added)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM messages WHERE proton_id = 'm1'`); n != 1 {
		t.Errorf("m1 not recovered on retry")
	}
	ss2, _ := st.GetSyncState(ctx, "mb-1")
	if ss2.EventCursor == nil || *ss2.EventCursor != "ev-1" {
		t.Errorf("cursor = %v, want ev-1 after recovery", ss2.EventCursor)
	}
}

func TestSyncAll_PerMailboxIsolation(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newMemKeychain()
	seedActiveMailbox(t, st, ks, "mb-a", "a@proton.test", "user-a", "uid-a", "tok-a", "pass-a")
	seedActiveMailbox(t, st, ks, "mb-b", "b@proton.test", "user-b", "uid-b", "tok-b", "pass-b")

	// Mailbox B has a healthy client that backfills.
	fakeB := authedFake("tok-b", "uid-b")
	fakeB.LabelList = inboxLabels()
	fakeB.LatestEvent = "ev-b"
	fakeB.BackfillIDs = []string{"mb1"}
	fakeB.Messages = map[string]proton.DecryptedMessage{
		"mb1": msg("mb1", "B message", "z@example.com", []string{"0"}, "hi"),
	}

	dialer := &fakeDialer{
		clients: map[string]proton.Client{"user-b": fakeB},
		// Mailbox A's Resume fails with an invalid refresh token → needs_reauth.
		errs: map[string]error{"user-a": proton.ErrRefreshTokenInvalid},
	}
	eng := newEngine(st, ks, dialer, Config{Concurrency: 2})

	summaries, err := eng.SyncAll(ctx)
	if err != nil {
		t.Fatalf("SyncAll: %v", err)
	}
	if len(summaries) != 2 {
		t.Fatalf("summaries = %d, want 2", len(summaries))
	}

	byID := map[string]RunSummary{}
	for _, s := range summaries {
		byID[s.MailboxID] = s
	}
	if byID["mb-a"].Err == nil {
		t.Error("mailbox A should have failed")
	}
	if byID["mb-b"].Err != nil {
		t.Errorf("mailbox B should have succeeded: %v", byID["mb-b"].Err)
	}
	if byID["mb-b"].Added != 1 {
		t.Errorf("mailbox B added = %d, want 1", byID["mb-b"].Added)
	}
	// A's auth failure flips only A to needs_reauth; B stays active.
	ma, _ := st.GetMailbox(ctx, "mb-a")
	if ma.State != store.MailboxStateNeedsReauth {
		t.Errorf("mailbox A state = %q, want needs_reauth", ma.State)
	}
	mb, _ := st.GetMailbox(ctx, "mb-b")
	if mb.State != store.MailboxStateActive {
		t.Errorf("mailbox B state = %q, want active", mb.State)
	}
	// A's failure is recorded to its own sync_run with a cause.
	runA, ok, _ := st.LatestSyncRun(ctx, "mb-a")
	if !ok || runA.LastError == nil {
		t.Errorf("mailbox A sync_run missing last_error: ok=%v run=%+v", ok, runA)
	}
}

func TestSyncAll_PanicIsolation(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newMemKeychain()
	seedActiveMailbox(t, st, ks, "mb-a", "a@proton.test", "user-a", "uid-a", "tok-a", "pass-a")
	seedActiveMailbox(t, st, ks, "mb-b", "b@proton.test", "user-b", "uid-b", "tok-b", "pass-b")

	fakeA := authedFake("tok-a", "uid-a") // Labels panics
	fakeB := authedFake("tok-b", "uid-b")
	fakeB.LabelList = inboxLabels()
	fakeB.LatestEvent = "ev-b"
	fakeB.BackfillIDs = []string{"mb1"}
	fakeB.Messages = map[string]proton.DecryptedMessage{
		"mb1": msg("mb1", "B", "z@example.com", []string{"0"}, "hi"),
	}
	dialer := &fakeDialer{clients: map[string]proton.Client{
		"user-a": panicClient{fakeA},
		"user-b": fakeB,
	}}
	eng := newEngine(st, ks, dialer, Config{Concurrency: 2})

	summaries, err := eng.SyncAll(ctx)
	if err != nil {
		t.Fatalf("SyncAll must not propagate a mailbox panic: %v", err)
	}
	byID := map[string]RunSummary{}
	for _, s := range summaries {
		byID[s.MailboxID] = s
	}
	if byID["mb-a"].Err == nil {
		t.Error("panicking mailbox A should record an error")
	}
	if byID["mb-b"].Err != nil || byID["mb-b"].Added != 1 {
		t.Errorf("mailbox B should have completed: %+v", byID["mb-b"])
	}
}

func TestTail_CursorAdvancesAtomicallyAndResumes(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newMemKeychain()
	seedActiveMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")
	if err := st.UpsertSyncState(ctx, "mb-1", "ev-0", time.Now().UTC()); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}

	base := authedFake("tok-1", "uid-1")
	base.LabelList = inboxLabels()
	base.Messages = map[string]proton.DecryptedMessage{
		"m1": msg("m1", "One", "a@example.com", []string{"0"}, "b1"),
		"m2": msg("m2", "Two", "b@example.com", []string{"0"}, "b2"),
	}
	// Batch1 commits (m1). Batch2 would apply m2, but GetEvents fails on the 2nd
	// call, so batch2 is never applied.
	base.Batches = []proton.EventBatch{
		{Events: []proton.Event{{EventID: "ev-1", Messages: []proton.MessageEvent{
			{Action: proton.EventCreate, MessageID: "m1"},
		}}}, NextCursor: "ev-1", More: true},
		{Events: []proton.Event{{EventID: "ev-2", Messages: []proton.MessageEvent{
			{Action: proton.EventCreate, MessageID: "m2"},
		}}}, NextCursor: "ev-2", More: false},
	}
	flaky := &flakyClient{Fake: base, getEventsErrOn: 2, getEventsErr: errors.New("connection dropped mid-drain")}

	eng := newEngine(st, ks, &fakeDialer{clients: map[string]proton.Client{"user-1": flaky}}, Config{})
	sum, err := eng.SyncMailbox(ctx, "mb-1")
	if err == nil {
		t.Fatal("expected the run to surface the mid-drain failure")
	}
	if sum.Err == nil {
		t.Fatal("run summary should carry the failure cause")
	}
	// Batch1 committed atomically: m1 present AND cursor at ev-1. Batch2 not applied.
	if n := countRows(t, st, `SELECT COUNT(*) FROM messages WHERE proton_id = 'm1'`); n != 1 {
		t.Errorf("m1 not committed from batch1")
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM messages WHERE proton_id = 'm2'`); n != 0 {
		t.Errorf("m2 must not be present (batch2 failed before commit)")
	}
	ss, _ := st.GetSyncState(ctx, "mb-1")
	if ss.EventCursor == nil || *ss.EventCursor != "ev-1" {
		t.Fatalf("cursor = %v, want ev-1 (batch1 only)", ss.EventCursor)
	}

	// Resume: a fresh run continues from ev-1. Clear the injected fault and let
	// batch2 flow (the fake's batchIdx already advanced past batch1).
	flaky.getEventsErrOn = 0
	sum2, err := eng.SyncMailbox(ctx, "mb-1")
	if err != nil {
		t.Fatalf("resume run: %v", err)
	}
	if sum2.Added != 1 {
		t.Errorf("resume added = %d, want 1 (m2)", sum2.Added)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM messages WHERE proton_id = 'm2'`); n != 1 {
		t.Errorf("m2 not applied on resume")
	}
	ss2, _ := st.GetSyncState(ctx, "mb-1")
	if ss2.EventCursor == nil || *ss2.EventCursor != "ev-2" {
		t.Errorf("cursor = %v, want ev-2 after resume", ss2.EventCursor)
	}
}

// TestSync_AbsentAccessTokenNeedsReauth covers a pre-fix mailbox row: a refresh
// token and session UID are stored, but no access token. Resuming via an eager
// refresh would reduce the session scope and later 9101 on key/salt access, so
// the engine treats the missing access token as a re-auth condition — the
// mailbox is flipped to needs_reauth with an actionable cause, never silently
// resumed (SPEC-0007 "Cross-Process Session Resume").
func TestSync_AbsentAccessTokenNeedsReauth(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newMemKeychain()
	seedActiveMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")
	// Simulate a pre-fix row by removing the access token seedActiveMailbox wrote.
	if err := ks.Delete("mb-1", keychain.AccessToken); err != nil {
		t.Fatalf("delete access token: %v", err)
	}

	fake := authedFake("tok-1", "uid-1")
	fake.LabelList = inboxLabels()
	eng := newEngine(st, ks, &fakeDialer{clients: map[string]proton.Client{"user-1": fake}}, Config{})

	sum, err := eng.SyncMailbox(ctx, "mb-1")
	if err == nil || sum.Err == nil {
		t.Fatal("sync must fail when no access token is stored")
	}
	if !strings.Contains(sum.Err.Error(), "access token") {
		t.Errorf("error = %v, want it to mention the missing access token", sum.Err)
	}
	m, _ := st.GetMailbox(ctx, "mb-1")
	if m.State != store.MailboxStateNeedsReauth {
		t.Errorf("state = %q, want needs_reauth", m.State)
	}
}

// TestSync_PersistsRotatedAccessToken asserts that when a lazy refresh rotates
// the access token mid-run (simulated here by the resumed client surfacing a new
// access token), the engine persists it after operations so the next resume
// reuses the current token (SPEC-0007 "Cross-Process Session Resume").
func TestSync_PersistsRotatedAccessToken(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newMemKeychain()
	seedActiveMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")

	fake := authedFake("tok-1", "uid-1")
	fake.LabelList = inboxLabels()
	fake.LatestEvent = "ev-1"
	// A lazy refresh during the run rotated the access token; the wrapper's auth
	// handler would have captured it. Model that end state on the fake.
	fake.Access = "acc-rotated"
	eng := newEngine(st, ks, &fakeDialer{clients: map[string]proton.Client{"user-1": fake}}, Config{})

	if _, err := eng.SyncMailbox(ctx, "mb-1"); err != nil {
		t.Fatalf("SyncMailbox: %v", err)
	}
	if got, _ := ks.Get("mb-1", keychain.AccessToken); got != "acc-rotated" {
		t.Errorf("rotated access token not persisted: %q, want acc-rotated", got)
	}
}

// TestSync_ResumeUsesKeyPassAndSkipsSalts is the core of the 9101-on-resume fix:
// when a salted key pass is stored, the resume unlocks via UnlockWithKeyPass and
// NEVER takes the salts-fetching Unlock path — so a scope-downgraded session can
// still sync. The Fake's call counters stand in for "GetSalts was not called"
// (only Unlock reaches GetSalts on the real client).
func TestSync_ResumeUsesKeyPassAndSkipsSalts(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newMemKeychain()
	seedActiveMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")
	keyPass := []byte("salted-key-pass")
	if err := ks.Set("mb-1", keychain.SaltedKeyPass, keychain.EncodeSaltedKeyPass(keyPass)); err != nil {
		t.Fatalf("seed salted key pass: %v", err)
	}

	fake := authedFake("tok-1", "uid-1")
	fake.LabelList = inboxLabels()
	fake.LatestEvent = "ev-1"
	fake.SaltedKeyPassValue = keyPass // UnlockWithKeyPass accepts exactly this
	eng := newEngine(st, ks, &fakeDialer{clients: map[string]proton.Client{"user-1": fake}}, Config{})

	if _, err := eng.SyncMailbox(ctx, "mb-1"); err != nil {
		t.Fatalf("SyncMailbox: %v", err)
	}
	if fake.UnlockWithKeyPassCalls != 1 {
		t.Errorf("UnlockWithKeyPass calls = %d, want 1", fake.UnlockWithKeyPassCalls)
	}
	if fake.UnlockCalls != 0 {
		t.Errorf("Unlock (salts path) calls = %d, want 0 — the salts endpoint must not be hit on resume", fake.UnlockCalls)
	}
}

// TestSync_PreFixMailboxSelfHeals covers a mailbox with no stored key pass (the
// state right after this fix ships): the resume falls back to the passphrase
// Unlock and persists the freshly-derived key pass, so the NEXT resume skips the
// salts endpoint (self-heal). Requires a FULL-scope session for the first
// unlock; the fallback Unlock succeeds here (the fake models a full-scope
// session).
func TestSync_PreFixMailboxSelfHeals(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newMemKeychain()
	seedActiveMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")
	// No salted_key_pass stored (pre-fix row).
	derived := []byte("derived-key-pass")

	fake := authedFake("tok-1", "uid-1")
	fake.LabelList = inboxLabels()
	fake.LatestEvent = "ev-1"
	fake.Passphrase = "pass-1"        // full-scope Unlock accepts the passphrase
	fake.SaltedKeyPassValue = derived // Unlock derives and retains this
	eng := newEngine(st, ks, &fakeDialer{clients: map[string]proton.Client{"user-1": fake}}, Config{})

	if _, err := eng.SyncMailbox(ctx, "mb-1"); err != nil {
		t.Fatalf("first SyncMailbox (self-heal): %v", err)
	}
	if fake.UnlockCalls != 1 {
		t.Errorf("first run Unlock calls = %d, want 1 (fallback derives the key pass)", fake.UnlockCalls)
	}
	// The freshly-derived key pass was persisted.
	enc, err := ks.Get("mb-1", keychain.SaltedKeyPass)
	if err != nil {
		t.Fatalf("self-healed key pass not persisted: %v", err)
	}
	if got, _ := keychain.DecodeSaltedKeyPass(enc); string(got) != string(derived) {
		t.Errorf("persisted key pass = %q, want %q", got, derived)
	}

	// Next resume: a fresh client for the same user, now with the key pass stored.
	fake2 := authedFake("tok-1", "uid-1")
	fake2.LabelList = inboxLabels()
	fake2.LatestEvent = "ev-1"
	fake2.SaltedKeyPassValue = derived
	eng.dialer = &fakeDialer{clients: map[string]proton.Client{"user-1": fake2}}
	if _, err := eng.SyncMailbox(ctx, "mb-1"); err != nil {
		t.Fatalf("second SyncMailbox: %v", err)
	}
	if fake2.UnlockWithKeyPassCalls != 1 || fake2.UnlockCalls != 0 {
		t.Errorf("second run used salts path: UnlockWithKeyPass=%d Unlock=%d, want 1/0",
			fake2.UnlockWithKeyPassCalls, fake2.UnlockCalls)
	}
}

// TestSync_StaleKeyPassFallsBackAndRepersists covers a password change: the
// stored key pass no longer decrypts (UnlockWithKeyPass → ErrUnlockFailed), so
// the resume retries the passphrase Unlock ONCE (a still-full-scope session
// salvages it) and re-persists the newly-derived key pass.
func TestSync_StaleKeyPassFallsBackAndRepersists(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newMemKeychain()
	seedActiveMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "pass-1")
	if err := ks.Set("mb-1", keychain.SaltedKeyPass, keychain.EncodeSaltedKeyPass([]byte("STALE"))); err != nil {
		t.Fatalf("seed stale key pass: %v", err)
	}
	fresh := []byte("fresh-key-pass")

	fake := authedFake("tok-1", "uid-1")
	fake.LabelList = inboxLabels()
	fake.LatestEvent = "ev-1"
	fake.Passphrase = "pass-1"      // full-scope passphrase Unlock succeeds
	fake.SaltedKeyPassValue = fresh // UnlockWithKeyPass("STALE") != fresh → ErrUnlockFailed; Unlock derives fresh
	eng := newEngine(st, ks, &fakeDialer{clients: map[string]proton.Client{"user-1": fake}}, Config{})

	if _, err := eng.SyncMailbox(ctx, "mb-1"); err != nil {
		t.Fatalf("SyncMailbox: %v", err)
	}
	if fake.UnlockWithKeyPassCalls != 1 || fake.UnlockCalls != 1 {
		t.Errorf("expected stale-then-fallback: UnlockWithKeyPass=%d Unlock=%d, want 1/1",
			fake.UnlockWithKeyPassCalls, fake.UnlockCalls)
	}
	enc, _ := ks.Get("mb-1", keychain.SaltedKeyPass)
	if got, _ := keychain.DecodeSaltedKeyPass(enc); string(got) != string(fresh) {
		t.Errorf("stale key pass not replaced: %q, want %q", got, fresh)
	}
}

// TestSync_StaleKeyPassAndBadPassphraseNeedsReauth covers both unlock paths
// failing (key pass stale AND the passphrase no longer unlocks — e.g. after a
// password change the stored passphrase is also wrong): the mailbox flips to
// needs_reauth with the actionable "auth refresh" cause.
func TestSync_StaleKeyPassAndBadPassphraseNeedsReauth(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newMemKeychain()
	seedActiveMailbox(t, st, ks, "mb-1", "joe@proton.test", "user-1", "uid-1", "tok-1", "wrong-pass")
	if err := ks.Set("mb-1", keychain.SaltedKeyPass, keychain.EncodeSaltedKeyPass([]byte("STALE"))); err != nil {
		t.Fatalf("seed stale key pass: %v", err)
	}

	fake := authedFake("tok-1", "uid-1")
	fake.LabelList = inboxLabels()
	fake.Passphrase = "correct-pass"         // stored "wrong-pass" fails Unlock
	fake.SaltedKeyPassValue = []byte("real") // "STALE" fails UnlockWithKeyPass
	eng := newEngine(st, ks, &fakeDialer{clients: map[string]proton.Client{"user-1": fake}}, Config{})

	sum, err := eng.SyncMailbox(ctx, "mb-1")
	if err == nil || sum.Err == nil {
		t.Fatal("sync must fail when neither unlock path works")
	}
	if !strings.Contains(sum.Err.Error(), "auth refresh") {
		t.Errorf("error = %v, want the actionable 'auth refresh' hint", sum.Err)
	}
	m, _ := st.GetMailbox(ctx, "mb-1")
	if m.State != store.MailboxStateNeedsReauth {
		t.Errorf("state = %q, want needs_reauth", m.State)
	}
}
