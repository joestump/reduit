package mailbox

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/store"
)

// migrateMu serializes calls to store.Migrate across parallel tests —
// goose's package-level config (SetBaseFS / SetDialect / SetTableName)
// is global state. Mirrors the lock in account/account_test.go for the
// same reason.
var migrateMu sync.Mutex

// newTestStore opens a fresh on-disk SQLite under t.TempDir, runs every
// embedded migration, and seeds an `accounts` row for `accountID` so
// the FK on mailboxes.account_id is satisfied. Returns the store + the
// account ID.
func newTestStore(t *testing.T) (*store.Store, string) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "reduit-mailbox-test.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	migrateMu.Lock()
	err = st.Migrate("")
	migrateMu.Unlock()
	if err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}

	// Seed one account for the FK. The test does not exercise the
	// account package's lifecycle so we insert directly with the minimum
	// required columns.
	const accountID = "acct-test"
	if err := seedAccount(st, accountID); err != nil {
		t.Fatalf("seedAccount: %v", err)
	}
	return st, accountID
}

func seedAccount(st *store.Store, id string) error {
	const q = `
INSERT INTO accounts (id, oidc_subject, state, key_envelope, created_at, updated_at)
VALUES (?, ?, 'active', X'00', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`
	_, err := st.DB.Exec(q, id, "sub-"+id)
	return err
}

func newMessage(t *testing.T, svc Service, accountID, protonID string) int64 {
	t.Helper()
	id, err := svc.UpsertMessage(context.Background(), &Message{
		AccountID:       accountID,
		ProtonMessageID: protonID,
		Subject:         "test " + protonID,
		Sender:          "alice@example.com",
		RFC822Size:      4096,
		InternalDate:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("UpsertMessage(%s): %v", protonID, err)
	}
	return id
}

// TestEnsureMailboxAssignsUIDValidityOnce confirms that the first call
// for (account, name) inserts a row with a populated UIDVALIDITY and
// every subsequent call returns the same row unchanged.
//
// Governing: SPEC-0003 REQ "UIDVALIDITY assigned at first sync".
func TestEnsureMailboxAssignsUIDValidityOnce(t *testing.T) {
	t.Parallel()
	st, acct := newTestStore(t)
	svc := New(st)
	ctx := context.Background()

	first, err := svc.EnsureMailbox(ctx, acct, "INBOX", ProtonInboxLabelID, KindSystem)
	if err != nil {
		t.Fatalf("EnsureMailbox(first): %v", err)
	}
	if first.UIDValidity == 0 {
		t.Fatalf("UIDVALIDITY not assigned on first call")
	}
	if first.UIDNext != 1 {
		t.Errorf("UIDNext = %d, want 1 on a fresh mailbox", first.UIDNext)
	}

	// Second call MUST be idempotent: same row, same UIDVALIDITY.
	second, err := svc.EnsureMailbox(ctx, acct, "INBOX", ProtonInboxLabelID, KindSystem)
	if err != nil {
		t.Fatalf("EnsureMailbox(second): %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("EnsureMailbox not idempotent: id1=%d id2=%d", first.ID, second.ID)
	}
	if second.UIDValidity != first.UIDValidity {
		t.Errorf("UIDVALIDITY changed across calls: %d -> %d",
			first.UIDValidity, second.UIDValidity)
	}
}

// TestAssignUIDIsMonotonicUnderRace launches 16 goroutines × 200
// AssignUID calls each (3200 total) and asserts that every issued UID
// is distinct and falls in [1, 3200]. The test fails (in -race) if the
// transactional pattern in repository.assignUID has a TOCTOU window.
//
// Governing: SPEC-0003 REQ "UID assignment is monotonic" + REQ
// "Reused message ID does not get a reused UID".
func TestAssignUIDIsMonotonicUnderRace(t *testing.T) {
	t.Parallel()
	st, acct := newTestStore(t)
	svc := New(st)
	ctx := context.Background()

	mb, err := svc.EnsureMailbox(ctx, acct, "INBOX", ProtonInboxLabelID, KindSystem)
	if err != nil {
		t.Fatalf("EnsureMailbox: %v", err)
	}

	const goroutines = 16
	const perGoroutine = 200
	const total = goroutines * perGoroutine

	// Pre-create 3200 distinct messages so each AssignUID call has a
	// unique (mailbox, message) pair to insert. We do this serially to
	// avoid the messages-table contention dwarfing the AssignUID race
	// we are actually testing.
	msgIDs := make([]int64, total)
	for i := 0; i < total; i++ {
		msgIDs[i] = newMessage(t, svc, acct, idxProtonID(i))
	}

	results := make([]uint32, total)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		g := g
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				idx := g*perGoroutine + i
				uid, err := svc.AssignUID(ctx, acct, mb.ID, msgIDs[idx])
				if err != nil {
					t.Errorf("AssignUID(idx=%d): %v", idx, err)
					return
				}
				results[idx] = uid
			}
		}()
	}
	wg.Wait()

	// Every UID must be in [1, total] and distinct.
	seen := make(map[uint32]struct{}, total)
	for _, u := range results {
		if u < 1 || u > total {
			t.Errorf("UID %d out of range [1, %d]", u, total)
		}
		if _, dup := seen[u]; dup {
			t.Errorf("UID %d issued twice", u)
		}
		seen[u] = struct{}{}
	}

	// Sanity: uid_next on the mailbox must equal total+1.
	final, err := svc.GetMailboxByName(ctx, acct, "INBOX")
	if err != nil {
		t.Fatalf("GetMailboxByName: %v", err)
	}
	if final.UIDNext != uint32(total)+1 {
		t.Errorf("post-race UIDNext = %d, want %d", final.UIDNext, total+1)
	}
}

// idxProtonID returns a unique deterministic Proton-style message ID
// for the integer i. fmt.Sprintf with %010d guarantees a one-to-one
// mapping in [0, 9999999999].
func idxProtonID(i int) string {
	return fmt.Sprintf("msg-%010d", i)
}

// TestAssignUIDDoesNotReuseAfterExpunge re-adds a Proton message ID
// after expunge and asserts the new UID is greater than the prior one.
//
// Governing: SPEC-0003 REQ "Reused message ID does not get a reused
// UID".
func TestAssignUIDDoesNotReuseAfterExpunge(t *testing.T) {
	t.Parallel()
	st, acct := newTestStore(t)
	svc := New(st)
	ctx := context.Background()

	mb, err := svc.EnsureMailbox(ctx, acct, "INBOX", ProtonInboxLabelID, KindSystem)
	if err != nil {
		t.Fatalf("EnsureMailbox: %v", err)
	}
	msgID := newMessage(t, svc, acct, "msg-recycle")

	uid1, err := svc.AssignUID(ctx, acct, mb.ID, msgID)
	if err != nil {
		t.Fatalf("AssignUID(first): %v", err)
	}

	// Expunge: drop the message_uids row.
	removed, err := svc.RemoveMessageFromMailbox(ctx, acct, mb.ID, msgID)
	if err != nil {
		t.Fatalf("RemoveMessageFromMailbox: %v", err)
	}
	if !removed {
		t.Fatalf("RemoveMessageFromMailbox returned no removal")
	}

	// Re-add the SAME message ID. It must get a fresh UID > uid1.
	uid2, err := svc.AssignUID(ctx, acct, mb.ID, msgID)
	if err != nil {
		t.Fatalf("AssignUID(second): %v", err)
	}
	if uid2 <= uid1 {
		t.Errorf("re-added message reused UID: first=%d second=%d", uid1, uid2)
	}
}

// TestListMailboxesScopesToAccount inserts mailboxes for two distinct
// accounts and asserts ListMailboxes returns ONLY the caller's rows.
//
// Governing: SPEC-0003 REQ "LIST shows only own folders".
func TestListMailboxesScopesToAccount(t *testing.T) {
	t.Parallel()
	st, acctA := newTestStore(t)
	svc := New(st)
	ctx := context.Background()

	// Seed a second account.
	const acctB = "acct-bob"
	if err := seedAccount(st, acctB); err != nil {
		t.Fatalf("seedAccount(B): %v", err)
	}

	if _, err := svc.EnsureMailbox(ctx, acctA, "INBOX", ProtonInboxLabelID, KindSystem); err != nil {
		t.Fatalf("EnsureMailbox(A INBOX): %v", err)
	}
	if _, err := svc.EnsureMailbox(ctx, acctA, "Labels/Receipts", "user-receipts", KindUserLabel); err != nil {
		t.Fatalf("EnsureMailbox(A Labels/Receipts): %v", err)
	}
	if _, err := svc.EnsureMailbox(ctx, acctB, "INBOX", ProtonInboxLabelID, KindSystem); err != nil {
		t.Fatalf("EnsureMailbox(B INBOX): %v", err)
	}
	if _, err := svc.EnsureMailbox(ctx, acctB, "Labels/Secrets", "user-secrets", KindUserLabel); err != nil {
		t.Fatalf("EnsureMailbox(B Labels/Secrets): %v", err)
	}

	listA, err := svc.ListMailboxes(ctx, acctA)
	if err != nil {
		t.Fatalf("ListMailboxes(A): %v", err)
	}
	if len(listA) != 2 {
		t.Errorf("ListMailboxes(A) returned %d mailboxes, want 2", len(listA))
	}
	for _, m := range listA {
		if m.AccountID != acctA {
			t.Errorf("ListMailboxes(A) leaked account %s mailbox %q", m.AccountID, m.Name)
		}
		if m.Name == "Labels/Secrets" {
			t.Errorf("ListMailboxes(A) returned account-B-only mailbox %q", m.Name)
		}
	}

	// And the other direction.
	listB, err := svc.ListMailboxes(ctx, acctB)
	if err != nil {
		t.Fatalf("ListMailboxes(B): %v", err)
	}
	if len(listB) != 2 {
		t.Errorf("ListMailboxes(B) returned %d mailboxes, want 2", len(listB))
	}
}

// TestGetMailboxByNameRefusesNonOwnedMailbox confirms an account
// looking up another account's mailbox by exact name receives
// ErrMailboxNotFound — never the foreign row.
//
// Governing: SPEC-0003 REQ "SELECT of a non-owned mailbox fails as
// not-found".
func TestGetMailboxByNameRefusesNonOwnedMailbox(t *testing.T) {
	t.Parallel()
	st, acctA := newTestStore(t)
	svc := New(st)
	ctx := context.Background()

	const acctB = "acct-bob"
	if err := seedAccount(st, acctB); err != nil {
		t.Fatalf("seedAccount(B): %v", err)
	}

	// Create a mailbox under account B.
	bMbox, err := svc.EnsureMailbox(ctx, acctB, "Labels/Family", "user-family", KindUserLabel)
	if err != nil {
		t.Fatalf("EnsureMailbox(B): %v", err)
	}

	// Account A asks for the same name. MUST miss.
	if _, err := svc.GetMailboxByName(ctx, acctA, "Labels/Family"); err == nil {
		t.Errorf("GetMailboxByName(A) returned a mailbox owned by B (id=%d)", bMbox.ID)
	} else if !isNotFound(err) {
		t.Errorf("GetMailboxByName(A) returned %v, want ErrMailboxNotFound", err)
	}
}

// TestAssignUIDRefusesNonOwnedMailbox confirms that a forged
// (accountID, mailboxID) pair is rejected with ErrMailboxNotFound.
// Defense-in-depth: even if a session attempts to assign a UID to a
// mailbox it does not own, the repository's WHERE clause will refuse.
func TestAssignUIDRefusesNonOwnedMailbox(t *testing.T) {
	t.Parallel()
	st, acctA := newTestStore(t)
	svc := New(st)
	ctx := context.Background()

	const acctB = "acct-bob"
	if err := seedAccount(st, acctB); err != nil {
		t.Fatalf("seedAccount(B): %v", err)
	}

	bMbox, err := svc.EnsureMailbox(ctx, acctB, "INBOX", ProtonInboxLabelID, KindSystem)
	if err != nil {
		t.Fatalf("EnsureMailbox(B): %v", err)
	}
	bMsg := newMessage(t, svc, acctB, "msg-b")

	// Account A tries to assign a UID against B's mailbox.
	if _, err := svc.AssignUID(ctx, acctA, bMbox.ID, bMsg); err == nil {
		t.Errorf("AssignUID(A, B's mailbox) succeeded; expected ErrMailboxNotFound")
	} else if !isNotFound(err) {
		t.Errorf("AssignUID(A, B's mailbox) returned %v, want ErrMailboxNotFound", err)
	}
}

// TestAssignUIDRefusesCrossAccountMessage confirms that AssignUID
// refuses a (mailboxID, messageID) pair where the message belongs to a
// different account than the mailbox's owner. Belt-and-suspenders for
// the per-row account scoping.
func TestAssignUIDRefusesCrossAccountMessage(t *testing.T) {
	t.Parallel()
	st, acctA := newTestStore(t)
	svc := New(st)
	ctx := context.Background()

	const acctB = "acct-bob"
	if err := seedAccount(st, acctB); err != nil {
		t.Fatalf("seedAccount(B): %v", err)
	}

	aMbox, err := svc.EnsureMailbox(ctx, acctA, "INBOX", ProtonInboxLabelID, KindSystem)
	if err != nil {
		t.Fatalf("EnsureMailbox(A): %v", err)
	}
	bMsg := newMessage(t, svc, acctB, "msg-b")

	// AccountA's mailbox + AccountB's message → ErrMessageNotFound.
	if _, err := svc.AssignUID(ctx, acctA, aMbox.ID, bMsg); err == nil {
		t.Errorf("AssignUID(A's mailbox, B's message) succeeded; expected ErrMessageNotFound")
	}
}

// TestEnsureMailboxRaceIsIdempotent fires N concurrent EnsureMailbox
// calls for the SAME (account, name). Exactly one INSERT must win; all
// callers receive the same row.
func TestEnsureMailboxRaceIsIdempotent(t *testing.T) {
	t.Parallel()
	st, acct := newTestStore(t)
	svc := New(st)
	ctx := context.Background()

	const N = 8
	results := make([]*Mailbox, N)
	errs := make([]error, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = svc.EnsureMailbox(ctx, acct, "INBOX", ProtonInboxLabelID, KindSystem)
		}()
	}
	wg.Wait()

	var winnerID int64
	var winnerUIDV uint32
	for i, m := range results {
		if errs[i] != nil {
			t.Errorf("call %d: %v", i, errs[i])
			continue
		}
		if winnerID == 0 {
			winnerID = m.ID
			winnerUIDV = m.UIDValidity
			continue
		}
		if m.ID != winnerID {
			t.Errorf("call %d: got id=%d, want %d", i, m.ID, winnerID)
		}
		if m.UIDValidity != winnerUIDV {
			t.Errorf("call %d: got UIDVALIDITY=%d, want %d", i, m.UIDValidity, winnerUIDV)
		}
	}

	// And the on-disk row count is exactly one.
	var n int
	if err := st.DB.Get(&n, `SELECT COUNT(*) FROM mailboxes WHERE account_id = ? AND name = ?`, acct, "INBOX"); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("inserted %d rows for the same (account, name); want 1", n)
	}
}

// TestSystemFolderMapping pins the IMAP↔Proton resolver against the
// canonical seven mailboxes the spec requires.
//
// Governing: SPEC-0003 REQ "System folders map to standard names".
func TestSystemFolderMapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		imapName       string
		protonLabelID  string
		isSystem       bool
		expectKind     Kind
		expectProtonID string
	}{
		{"INBOX", ProtonInboxLabelID, true, KindSystem, ProtonInboxLabelID},
		{"Sent", ProtonSentLabelID, true, KindSystem, ProtonSentLabelID},
		{"Drafts", ProtonDraftsLabelID, true, KindSystem, ProtonDraftsLabelID},
		{"Trash", ProtonTrashLabelID, true, KindSystem, ProtonTrashLabelID},
		{"Spam", ProtonSpamLabelID, true, KindSystem, ProtonSpamLabelID},
		{"Archive", ProtonArchiveLabelID, true, KindSystem, ProtonArchiveLabelID},
		{"All Mail", ProtonAllMailLabelID, true, KindSystem, ProtonAllMailLabelID},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.imapName, func(t *testing.T) {
			gotName := ResolveSystemFolderName(tc.protonLabelID)
			if gotName != tc.imapName {
				t.Errorf("ResolveSystemFolderName(%q) = %q, want %q",
					tc.protonLabelID, gotName, tc.imapName)
			}
			gotID := ResolveSystemFolderID(tc.imapName)
			if gotID != tc.protonLabelID {
				t.Errorf("ResolveSystemFolderID(%q) = %q, want %q",
					tc.imapName, gotID, tc.protonLabelID)
			}
			kind, ref, ok := ClassifyName(tc.imapName)
			if !ok {
				t.Errorf("ClassifyName(%q) ok=false", tc.imapName)
			}
			if kind != tc.expectKind {
				t.Errorf("ClassifyName(%q) kind=%q, want %q", tc.imapName, kind, tc.expectKind)
			}
			if ref != tc.expectProtonID {
				t.Errorf("ClassifyName(%q) ref=%q, want %q", tc.imapName, ref, tc.expectProtonID)
			}
		})
	}

	// Negative: unknown system name.
	if id := ResolveSystemFolderID("Nothing"); id != "" {
		t.Errorf("ResolveSystemFolderID(unknown) = %q, want empty", id)
	}
}

// TestUserLabelMapping covers Labels/<name> parsing.
//
// Governing: SPEC-0003 REQ "User labels appear under Labels/".
func TestUserLabelMapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		imapName string
		wantPath string
		wantOK   bool
	}{
		{"Labels/Receipts", "Receipts", true},
		{"Labels/Family/Tax", "Family/Tax", true},
		{"Labels/Family/Trips", "Family/Trips", true},
		{"INBOX", "", false},
		{"Labels", "", false},
		{"Labels/", "", false},
		{"OtherNamespace/Foo", "", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.imapName, func(t *testing.T) {
			path, ok := ParseUserLabelName(tc.imapName)
			if ok != tc.wantOK {
				t.Errorf("ParseUserLabelName(%q) ok=%v want %v", tc.imapName, ok, tc.wantOK)
			}
			if path != tc.wantPath {
				t.Errorf("ParseUserLabelName(%q) path=%q want %q", tc.imapName, path, tc.wantPath)
			}
		})
	}

	// Round-trip: FormatUserLabelName ∘ ParseUserLabelName == identity
	// for any input that parses.
	in := "Labels/Family/Tax"
	if got := FormatUserLabelName("Family/Tax"); got != in {
		t.Errorf("FormatUserLabelName round-trip: %q, want %q", got, in)
	}
}

// TestUpsertMessageIsIdempotent is the contract the sync worker
// depends on: re-syncing a Proton message must not duplicate the row.
func TestUpsertMessageIsIdempotent(t *testing.T) {
	t.Parallel()
	st, acct := newTestStore(t)
	svc := New(st)
	ctx := context.Background()

	id1, err := svc.UpsertMessage(ctx, &Message{
		AccountID:       acct,
		ProtonMessageID: "msg-1",
		Subject:         "first",
		InternalDate:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("upsert 1: %v", err)
	}
	id2, err := svc.UpsertMessage(ctx, &Message{
		AccountID:       acct,
		ProtonMessageID: "msg-1",
		Subject:         "first-but-edited",
		InternalDate:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("upsert 2: %v", err)
	}
	if id1 != id2 {
		t.Errorf("upsert returned distinct IDs for same proton id: %d vs %d", id1, id2)
	}

	// Single row in the table.
	var n int
	if err := st.DB.Get(&n, `SELECT COUNT(*) FROM messages WHERE account_id = ? AND proton_message_id = ?`,
		acct, "msg-1"); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 message row, got %d", n)
	}
}

// TestCountMessagesInMailboxIsAccountScoped confirms that the count
// query refuses to leak cross-account totals.
func TestCountMessagesInMailboxIsAccountScoped(t *testing.T) {
	t.Parallel()
	st, acctA := newTestStore(t)
	svc := New(st)
	ctx := context.Background()

	const acctB = "acct-bob"
	if err := seedAccount(st, acctB); err != nil {
		t.Fatalf("seedAccount(B): %v", err)
	}

	mboxA, _ := svc.EnsureMailbox(ctx, acctA, "INBOX", ProtonInboxLabelID, KindSystem)
	mboxB, _ := svc.EnsureMailbox(ctx, acctB, "INBOX", ProtonInboxLabelID, KindSystem)

	// Seed two messages in A, three in B.
	for i := 0; i < 2; i++ {
		mid := newMessage(t, svc, acctA, idxProtonID(100+i))
		if _, err := svc.AssignUID(ctx, acctA, mboxA.ID, mid); err != nil {
			t.Fatalf("AssignUID(A): %v", err)
		}
	}
	for i := 0; i < 3; i++ {
		mid := newMessage(t, svc, acctB, idxProtonID(200+i))
		if _, err := svc.AssignUID(ctx, acctB, mboxB.ID, mid); err != nil {
			t.Fatalf("AssignUID(B): %v", err)
		}
	}

	if got, _ := svc.CountMessagesInMailbox(ctx, acctA, mboxA.ID); got != 2 {
		t.Errorf("CountMessagesInMailbox(A) = %d, want 2", got)
	}
	if got, _ := svc.CountMessagesInMailbox(ctx, acctB, mboxB.ID); got != 3 {
		t.Errorf("CountMessagesInMailbox(B) = %d, want 3", got)
	}
	// Cross-account: A asking for B's mailbox count returns 0
	// (account_id filter excludes the rows entirely).
	if got, _ := svc.CountMessagesInMailbox(ctx, acctA, mboxB.ID); got != 0 {
		t.Errorf("CountMessagesInMailbox(A, B's mailbox) = %d, want 0", got)
	}
}

// isNotFound checks whether err is one of our typed not-found errors.
// Used by tests that accept either ErrMailboxNotFound or
// ErrMessageNotFound depending on which scoping check fires first.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	switch err {
	case ErrMailboxNotFound, ErrMessageNotFound, sql.ErrNoRows:
		return true
	}
	return false
}
