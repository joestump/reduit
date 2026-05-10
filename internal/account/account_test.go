package account

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/store"
	"github.com/joestump/reduit/internal/storetest"
	"golang.org/x/crypto/bcrypt"
)

// migrateMu serializes calls to store.Migrate across parallel tests.
// goose's package-level config (SetBaseFS / SetDialect / SetTableName)
// is global state, so concurrent migrations race on those writes even
// when each test owns its own DB file. The race is purely in the
// goose globals — actual schema application is isolated per database
// — so a process-wide lock around Migrate is enough.
var migrateMu sync.Mutex

// newTestService spins up a fresh on-disk SQLite (under t.TempDir),
// runs the embedded migrations, and returns a Service plus the
// underlying store (so tests can seed users directly via raw SQL).
//
// Per ADR-0010 admin status is no longer an account attribute, so
// no admin allowlist is wired here -- that's the session layer's
// concern (computed from OIDC_ADMIN_SUBS at session-bind time).
func newTestService(t *testing.T) (Service, *store.Store) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "reduit-test.db")
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

	master, err := cryptenv.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	svc := New(st, master)
	return svc, st
}

// createTestAccount mints a user keyed by the supplied OIDC subject
// (via storetest.SeedUser) and returns a freshly-created account
// owned by that user. Use this for the common "I just need an
// account in pending state" pattern; tests that need finer control
// should call storetest.SeedUser + svc.Create directly.
func createTestAccount(t *testing.T, svc Service, st *store.Store, ctx context.Context, sub string) *Account {
	t.Helper()
	uid := storetest.SeedUser(t, st, sub)
	a, err := svc.Create(ctx, CreateParams{UserID: uid})
	if err != nil {
		t.Fatalf("createTestAccount(%q): %v", sub, err)
	}
	return a
}

func TestCreateAndGetByID(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	uid := storetest.SeedUser(t, st, "sub-joe")
	created, err := svc.Create(ctx, CreateParams{UserID: uid})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" {
		t.Fatal("Create returned empty ID")
	}
	if created.State != StatePendingProtonSetup {
		t.Errorf("new account state = %q, want %q", created.State, StatePendingProtonSetup)
	}
	if len(created.KeyEnvelope) == 0 {
		t.Fatal("KeyEnvelope must be populated at creation")
	}
	if created.UserID != uid {
		t.Errorf("UserID = %q, want %q", created.UserID, uid)
	}

	got, err := svc.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("GetByID round-trip ID mismatch: got %q want %q", got.ID, created.ID)
	}
	if got.UserID != uid {
		t.Errorf("GetByID UserID = %q, want %q", got.UserID, uid)
	}

	if _, err := svc.GetByID(ctx, "id-missing"); !errors.Is(err, ErrAccountNotFound) {
		t.Errorf("missing id error = %v, want ErrAccountNotFound", err)
	}
}

// TestUserCanCreateMultipleAccounts pins ADR-0010's central
// affordance: one user owns N accounts. Two pending-Proton-setup rows
// for the same user MUST be accepted (proton_user_id is NULL on both
// and SQLite treats NULLs as distinct under UNIQUE).
//
// Governing: ADR-0010, SPEC-0001 REQ "Account Identity".
func TestUserCanCreateMultipleAccounts(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	uid := storetest.SeedUser(t, st, "sub-multi-acct")

	first, err := svc.Create(ctx, CreateParams{UserID: uid})
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}
	second, err := svc.Create(ctx, CreateParams{UserID: uid})
	if err != nil {
		t.Fatalf("second Create: %v", err)
	}
	if first.ID == second.ID {
		t.Fatalf("Create returned the same ID twice: %q", first.ID)
	}

	got, err := svc.ListByUser(ctx, uid)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListByUser len = %d, want 2", len(got))
	}
}

// TestCreateRejectsDuplicateProtonAccountForUser pins SPEC-0001's
// "no duplicate Proton account per user" rule: the UNIQUE
// (user_id, proton_user_id) constraint surfaces as
// ErrAccountAlreadyExists at the service layer when a user attempts
// to relay the same Proton mailbox twice.
func TestCreateRejectsDuplicateProtonAccountForUser(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	uid := storetest.SeedUser(t, st, "sub-dup-proton")

	if _, err := svc.Create(ctx, CreateParams{UserID: uid, ProtonUserID: "proton-1"}); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	_, err := svc.Create(ctx, CreateParams{UserID: uid, ProtonUserID: "proton-1"})
	if !errors.Is(err, ErrAccountAlreadyExists) {
		t.Fatalf("dup proton Create error = %v, want ErrAccountAlreadyExists", err)
	}
}

// TestDifferentUsersMaySharePollutedProtonID confirms the unique
// constraint is per-user, not global -- two users may relay the same
// Proton mailbox from independent accounts (per SPEC-0001).
func TestDifferentUsersMaySharePollutedProtonID(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	u1 := storetest.SeedUser(t, st, "sub-share-1")
	u2 := storetest.SeedUser(t, st, "sub-share-2")

	if _, err := svc.Create(ctx, CreateParams{UserID: u1, ProtonUserID: "proton-shared"}); err != nil {
		t.Fatalf("user1 Create: %v", err)
	}
	if _, err := svc.Create(ctx, CreateParams{UserID: u2, ProtonUserID: "proton-shared"}); err != nil {
		t.Fatalf("user2 Create: %v", err)
	}
}

func TestTransitionTable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		from    State
		to      State
		allowed bool
	}{
		// Allowed
		{StatePendingProtonSetup, StateActive, true},
		{StatePendingProtonSetup, StateSoftDeleted, true},
		{StateActive, StateSuspended, true},
		{StateActive, StateSoftDeleted, true},
		// SPEC-0002 REQ "Backoff on Failure" — refresh-token-revoked
		// kicks the account back to pending so the wizard re-prompts.
		{StateActive, StatePendingProtonSetup, true},
		{StateSuspended, StateActive, true},
		{StateSuspended, StateSoftDeleted, true},
		// Denied
		{StatePendingProtonSetup, StateSuspended, false},
		{StateSuspended, StatePendingProtonSetup, false},
		{StateSoftDeleted, StateActive, false},
		{StateSoftDeleted, StateSuspended, false},
		{StateSoftDeleted, StatePendingProtonSetup, false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.from)+"->"+string(tc.to), func(t *testing.T) {
			t.Parallel()
			if got := transitionAllowed(tc.from, tc.to); got != tc.allowed {
				t.Errorf("transitionAllowed(%q,%q) = %v, want %v", tc.from, tc.to, got, tc.allowed)
			}
		})
	}
}

func TestTransitionEnforcement(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, st, ctx, "sub-trans")

	// Illegal: pending -> suspended.
	if _, err := svc.Transition(ctx, a.ID, StateSuspended); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected ErrInvalidTransition, got %v", err)
	}

	// Legal: pending -> active.
	active, err := svc.Transition(ctx, a.ID, StateActive)
	if err != nil {
		t.Fatalf("Transition pending->active: %v", err)
	}
	if active.State != StateActive {
		t.Errorf("state after transition = %q, want active", active.State)
	}

	// Same-state -> ErrInvalidTransition.
	if _, err := svc.Transition(ctx, a.ID, StateActive); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("same-state transition should fail, got %v", err)
	}

	// active -> suspended.
	susp, err := svc.Transition(ctx, a.ID, StateSuspended)
	if err != nil {
		t.Fatalf("active->suspended: %v", err)
	}
	if susp.State != StateSuspended {
		t.Errorf("state = %q, want suspended", susp.State)
	}

	// suspended -> active (un-suspend).
	if _, err := svc.Transition(ctx, a.ID, StateActive); err != nil {
		t.Fatalf("suspended->active: %v", err)
	}

	// Delete (soft).
	deleted, err := svc.Delete(ctx, a.ID)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if deleted.State != StateSoftDeleted {
		t.Errorf("state after Delete = %q, want soft_deleted", deleted.State)
	}
	if deleted.DeletedAt == nil {
		t.Error("DeletedAt should be set after soft delete")
	}

	// soft_deleted is terminal.
	if _, err := svc.Transition(ctx, a.ID, StateActive); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("soft_deleted->active should fail, got %v", err)
	}

	// Invalid target state.
	if _, err := svc.Transition(ctx, a.ID, State("garbage")); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("invalid target state should fail, got %v", err)
	}

	// Missing account.
	if _, err := svc.Transition(ctx, "missing-id", StateActive); !errors.Is(err, ErrAccountNotFound) {
		t.Errorf("missing-id transition error = %v, want ErrAccountNotFound", err)
	}
}

func TestList(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	for _, sub := range []string{"sub-a", "sub-b", "sub-c"} {
		_ = createTestAccount(t, svc, st, ctx, sub)
	}
	got, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("List len = %d, want 3", len(got))
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, st, ctx, "sub-seal")

	// Refresh token.
	rt := []byte("proton-refresh-token-payload-deadbeef")
	if err := svc.SealRefreshToken(ctx, a.ID, rt); err != nil {
		t.Fatalf("SealRefreshToken: %v", err)
	}
	got, err := svc.OpenRefreshToken(ctx, a.ID)
	if err != nil {
		t.Fatalf("OpenRefreshToken: %v", err)
	}
	if !bytes.Equal(got, rt) {
		t.Errorf("refresh token round-trip mismatch")
	}

	// UpdateRefreshToken alias.
	rt2 := []byte("rotated-refresh-token")
	if err := svc.UpdateRefreshToken(ctx, a.ID, rt2); err != nil {
		t.Fatalf("UpdateRefreshToken: %v", err)
	}
	got, err = svc.OpenRefreshToken(ctx, a.ID)
	if err != nil {
		t.Fatalf("OpenRefreshToken (after update): %v", err)
	}
	if !bytes.Equal(got, rt2) {
		t.Error("UpdateRefreshToken did not overwrite ciphertext")
	}

	// Mailbox passphrase.
	mp := []byte("super-long-mailbox-passphrase-with-symbols-!@#$")
	if err := svc.SealMailboxPassphrase(ctx, a.ID, mp); err != nil {
		t.Fatalf("SealMailboxPassphrase: %v", err)
	}
	gotMP, err := svc.OpenMailboxPassphrase(ctx, a.ID)
	if err != nil {
		t.Fatalf("OpenMailboxPassphrase: %v", err)
	}
	if !bytes.Equal(gotMP, mp) {
		t.Error("mailbox passphrase round-trip mismatch")
	}

	// IMAP password (Seal explicitly).
	imap := []byte("user-supplied-imap-password")
	if err := svc.SealIMAPPassword(ctx, a.ID, imap); err != nil {
		t.Fatalf("SealIMAPPassword: %v", err)
	}
	gotIMAP, err := svc.OpenIMAPPassword(ctx, a.ID)
	if err != nil {
		t.Fatalf("OpenIMAPPassword: %v", err)
	}
	if !bytes.Equal(gotIMAP, imap) {
		t.Error("imap password round-trip mismatch")
	}
	if err := svc.VerifyIMAPPassword(ctx, a.ID, imap); err != nil {
		t.Errorf("VerifyIMAPPassword(correct): %v", err)
	}
	if err := svc.VerifyIMAPPassword(ctx, a.ID, []byte("wrong")); err == nil {
		t.Error("VerifyIMAPPassword should fail on wrong candidate")
	}
}

func TestSealUsesFreshNoncePerCall(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, st, ctx, "sub-nonce")

	pt := []byte("identical-plaintext")
	if err := svc.SealRefreshToken(ctx, a.ID, pt); err != nil {
		t.Fatalf("seal 1: %v", err)
	}
	var ct1 []byte
	if err := st.DB.Get(&ct1, `SELECT refresh_token_ciphertext FROM accounts WHERE id = ?`, a.ID); err != nil {
		t.Fatalf("read ct1: %v", err)
	}

	if err := svc.SealRefreshToken(ctx, a.ID, pt); err != nil {
		t.Fatalf("seal 2: %v", err)
	}
	var ct2 []byte
	if err := st.DB.Get(&ct2, `SELECT refresh_token_ciphertext FROM accounts WHERE id = ?`, a.ID); err != nil {
		t.Fatalf("read ct2: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Fatal("two seals of identical plaintext produced identical ciphertext (nonce reuse?)")
	}
}

func TestRotateIMAPPassword(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, st, ctx, "sub-rotate")

	// First rotation.
	pw1, err := svc.RotateIMAPPassword(ctx, a.ID)
	if err != nil {
		t.Fatalf("RotateIMAPPassword 1: %v", err)
	}
	if len(pw1) == 0 {
		t.Fatal("rotated password is empty")
	}

	// Hash verifies.
	var hash1 string
	if err := st.DB.Get(&hash1, `SELECT imap_password_hash FROM accounts WHERE id = ?`, a.ID); err != nil {
		t.Fatalf("read hash1: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash1), []byte(pw1)); err != nil {
		t.Errorf("bcrypt verify against pw1: %v", err)
	}
	if err := svc.VerifyIMAPPassword(ctx, a.ID, []byte(pw1)); err != nil {
		t.Errorf("Service.VerifyIMAPPassword(pw1): %v", err)
	}

	// Ciphertext decrypts to same plaintext.
	openedPW1, err := svc.OpenIMAPPassword(ctx, a.ID)
	if err != nil {
		t.Fatalf("OpenIMAPPassword after rotate 1: %v", err)
	}
	if string(openedPW1) != pw1 {
		t.Errorf("opened ciphertext = %q, want %q", openedPW1, pw1)
	}

	// Second rotation: different plaintext, hash invalidates first password.
	pw2, err := svc.RotateIMAPPassword(ctx, a.ID)
	if err != nil {
		t.Fatalf("RotateIMAPPassword 2: %v", err)
	}
	if pw1 == pw2 {
		t.Error("two rotations produced identical passwords")
	}
	if err := svc.VerifyIMAPPassword(ctx, a.ID, []byte(pw1)); err == nil {
		t.Error("old pw1 should NOT verify after rotation")
	}
	if err := svc.VerifyIMAPPassword(ctx, a.ID, []byte(pw2)); err != nil {
		t.Errorf("new pw2 should verify: %v", err)
	}

	openedPW2, err := svc.OpenIMAPPassword(ctx, a.ID)
	if err != nil {
		t.Fatalf("OpenIMAPPassword after rotate 2: %v", err)
	}
	if string(openedPW2) != pw2 {
		t.Errorf("opened ciphertext after rotate 2 = %q, want %q", openedPW2, pw2)
	}
}

func TestOpenWhenSecretAbsent(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, st, ctx, "sub-empty")
	if _, err := svc.OpenRefreshToken(ctx, a.ID); !errors.Is(err, ErrSecretNotPresent) {
		t.Errorf("OpenRefreshToken on empty = %v, want ErrSecretNotPresent", err)
	}
	if _, err := svc.OpenMailboxPassphrase(ctx, a.ID); !errors.Is(err, ErrSecretNotPresent) {
		t.Errorf("OpenMailboxPassphrase on empty = %v, want ErrSecretNotPresent", err)
	}
	if _, err := svc.OpenIMAPPassword(ctx, a.ID); !errors.Is(err, ErrSecretNotPresent) {
		t.Errorf("OpenIMAPPassword on empty = %v, want ErrSecretNotPresent", err)
	}
	if err := svc.VerifyIMAPPassword(ctx, a.ID, []byte("anything")); !errors.Is(err, ErrSecretNotPresent) {
		t.Errorf("VerifyIMAPPassword on empty = %v, want ErrSecretNotPresent", err)
	}
}

func TestCreateRequiresUserID(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.Create(ctx, CreateParams{}); err == nil {
		t.Fatal("Create with empty UserID should error")
	}
	// Whitespace-only UserID MUST also be rejected (TrimSpace + empty check).
	if _, err := svc.Create(ctx, CreateParams{UserID: "   "}); err == nil {
		t.Fatal("Create with whitespace-only UserID should error")
	}
}

// TestSealAADPreventsCrossColumnSubstitution proves that ciphertext
// from one column cannot be decrypted as another column's secret.
//
// Threat model: an attacker (or buggy code) with DB write access copies
// the IMAP-password ciphertext into the refresh-token slot. Without
// AAD binding the column name into the AEAD tag, OpenRefreshToken
// would happily decrypt the IMAP password and ship it upstream to
// Proton. With AAD, the tag fails to verify and Open returns an error.
//
// Governing: ADR-0003 (envelope encryption). This test locks in the
// column-name AAD invariant so a future refactor cannot silently
// regress to aad=nil.
func TestSealAADPreventsCrossColumnSubstitution(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, st, ctx, "sub-aad")

	// Seal a distinctive plaintext into the IMAP password column.
	imapPT := []byte("imap-secret-do-not-leak")
	if err := svc.SealIMAPPassword(ctx, a.ID, imapPT); err != nil {
		t.Fatalf("SealIMAPPassword: %v", err)
	}
	var imapCT []byte
	if err := st.DB.Get(&imapCT, `SELECT imap_password_ciphertext FROM accounts WHERE id = ?`, a.ID); err != nil {
		t.Fatalf("read imap ciphertext: %v", err)
	}
	if len(imapCT) == 0 {
		t.Fatal("imap ciphertext unexpectedly empty")
	}

	// Substitution attack: copy the IMAP ciphertext into the refresh
	// token column. With aad=nil this would decrypt cleanly; with the
	// column-name AAD binding it MUST fail.
	if _, err := st.DB.Exec(
		`UPDATE accounts SET refresh_token_ciphertext = ? WHERE id = ?`,
		imapCT, a.ID,
	); err != nil {
		t.Fatalf("substitute ciphertext: %v", err)
	}

	pt, err := svc.OpenRefreshToken(ctx, a.ID)
	if err == nil {
		t.Fatalf("OpenRefreshToken on substituted ciphertext returned plaintext %q; want auth failure", pt)
	}
	// Belt-and-suspenders: even if a future refactor accidentally
	// returned plaintext on AAD mismatch, ensure it is NOT the IMAP
	// secret we tried to smuggle through.
	if bytes.Equal(pt, imapPT) {
		t.Fatal("cross-column substitution leaked IMAP password as refresh token")
	}

	// Symmetric direction: copy refresh-token ciphertext (we have
	// none right now; seal a known one) into the mailbox passphrase
	// column and confirm OpenMailboxPassphrase rejects it.
	rtPT := []byte("refresh-secret-also-do-not-leak")
	if err := svc.SealRefreshToken(ctx, a.ID, rtPT); err != nil {
		t.Fatalf("SealRefreshToken: %v", err)
	}
	var rtCT []byte
	if err := st.DB.Get(&rtCT, `SELECT refresh_token_ciphertext FROM accounts WHERE id = ?`, a.ID); err != nil {
		t.Fatalf("read refresh ciphertext: %v", err)
	}
	if _, err := st.DB.Exec(
		`UPDATE accounts SET mailbox_passphrase_ciphertext = ? WHERE id = ?`,
		rtCT, a.ID,
	); err != nil {
		t.Fatalf("substitute mailbox ciphertext: %v", err)
	}
	if pt, err := svc.OpenMailboxPassphrase(ctx, a.ID); err == nil {
		t.Fatalf("OpenMailboxPassphrase on substituted ciphertext returned plaintext %q; want auth failure", pt)
	}
}

// TestOpenWithTamperedCiphertext flips a byte in a stored ciphertext
// and asserts Open* surfaces an error. This pins down the AEAD
// authenticity guarantee the package relies on; without it a silent
// regression to a non-authenticating cipher would only show up in
// production.
func TestOpenWithTamperedCiphertext(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, st, ctx, "sub-tamper")
	if err := svc.SealRefreshToken(ctx, a.ID, []byte("real-token")); err != nil {
		t.Fatalf("SealRefreshToken: %v", err)
	}

	var ct []byte
	if err := st.DB.Get(&ct, `SELECT refresh_token_ciphertext FROM accounts WHERE id = ?`, a.ID); err != nil {
		t.Fatalf("read ct: %v", err)
	}
	if len(ct) < 30 {
		t.Fatalf("ciphertext unexpectedly short (%d bytes)", len(ct))
	}
	// Flip a byte in the middle (avoids the nonce prefix and the tag).
	tampered := append([]byte(nil), ct...)
	tampered[len(tampered)/2] ^= 0xFF
	if _, err := st.DB.Exec(`UPDATE accounts SET refresh_token_ciphertext = ? WHERE id = ?`, tampered, a.ID); err != nil {
		t.Fatalf("write tampered ct: %v", err)
	}

	if pt, err := svc.OpenRefreshToken(ctx, a.ID); err == nil {
		t.Fatalf("OpenRefreshToken on tampered ciphertext returned %q; want auth failure", pt)
	}
}

// TestOpenWithWrongMasterKey confirms that a service constructed with
// a different master key cannot open envelopes sealed under the
// original. Together with TestOpenWithTamperedCiphertext this locks
// the AEAD authenticity contract from both ends (wrong key + wrong
// data).
func TestOpenWithWrongMasterKey(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, st, ctx, "sub-wrong-key")
	if err := svc.SealRefreshToken(ctx, a.ID, []byte("payload")); err != nil {
		t.Fatalf("SealRefreshToken: %v", err)
	}

	// Build a second Service against the same DB but with a fresh
	// master key. Envelope-open MUST fail.
	otherMaster, err := cryptenv.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	otherSvc := New(st, otherMaster)
	if pt, err := otherSvc.OpenRefreshToken(ctx, a.ID); err == nil {
		t.Fatalf("OpenRefreshToken under wrong master key returned %q; want envelope-open failure", pt)
	}
}

// TestSealIMAPPasswordRejectsOversizedInput verifies the explicit
// 72-byte ceiling on externally-supplied IMAP passwords. bcrypt
// silently truncates beyond that ceiling, which would let two distinct
// passwords sharing a 72-byte prefix verify against the same hash.
func TestSealIMAPPasswordRejectsOversizedInput(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, st, ctx, "sub-bcrypt-cap")

	oversized := bytes.Repeat([]byte("A"), bcryptMaxPasswordBytes+1)
	if err := svc.SealIMAPPassword(ctx, a.ID, oversized); !errors.Is(err, ErrIMAPPasswordTooLong) {
		t.Fatalf("SealIMAPPassword(oversized) error = %v, want ErrIMAPPasswordTooLong", err)
	}

	// At-the-ceiling input must still succeed.
	atCeiling := bytes.Repeat([]byte("B"), bcryptMaxPasswordBytes)
	if err := svc.SealIMAPPassword(ctx, a.ID, atCeiling); err != nil {
		t.Fatalf("SealIMAPPassword(at-ceiling) unexpected error: %v", err)
	}
}

// TestTransitionIsAtomicUnderConcurrency races two goroutines on the
// same account: one tries Suspend, one tries Delete. The contract we
// guarantee is *atomicity*, not exclusivity: each Transition call
// observes-and-writes under a single SQLite transaction, so the row
// can never be left half-written (state=suspended with deleted_at
// already set, or vice versa). Whether one or both transitions
// succeed depends on which one wins the SQLite write lock and on
// whether the loser's allowedFrom set still contains the new state:
//
//   - Suspend then Delete: both succeed (active→suspended→soft_deleted
//     is a legal chain).
//   - Delete then Suspend: only Delete succeeds — Suspend's
//     allowedFrom is [active], and soft_deleted is terminal.
//
// In every case the final state MUST be one of `{suspended,
// soft_deleted}` and `deleted_at` MUST be set iff the final state is
// soft_deleted. That is the actual atomicity invariant the
// conditional UPDATE buys us; this test pins it down so a future
// refactor that re-introduces a stale-snapshot read (e.g. SELECT in
// one tx, UPDATE in another) cannot regress without tripping the
// "deleted_at coherence" assertion.
//
// Governing: SPEC-0001 REQ "Account Lifecycle States".
func TestTransitionIsAtomicUnderConcurrency(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, st, ctx, "sub-race")
	if _, err := svc.Transition(ctx, a.ID, StateActive); err != nil {
		t.Fatalf("seed active: %v", err)
	}

	// Register an OnTransition subscriber AFTER the seed so we only
	// count callbacks from the racing goroutines below. The supervisor
	// (SPEC-0002 REQ "One Worker Per Active Account") depends on each
	// successful Transition firing exactly one callback with the
	// correct prev/next pair — including in the chained case where
	// Suspend lands first and then Delete observes state=suspended.
	type cbCapture struct{ prev, next State }
	var (
		cbMu  sync.Mutex
		cbLog []cbCapture
	)
	unsub := svc.OnTransition(func(_ context.Context, prev, next State, _ *Account) {
		cbMu.Lock()
		cbLog = append(cbLog, cbCapture{prev: prev, next: next})
		cbMu.Unlock()
	})
	t.Cleanup(unsub)

	var (
		successes int32
		failures  int32
		wg        sync.WaitGroup
		start     = make(chan struct{})
	)

	race := func(target State) {
		defer wg.Done()
		<-start // align goroutine launches
		_, err := svc.Transition(ctx, a.ID, target)
		switch {
		case err == nil:
			atomic.AddInt32(&successes, 1)
		case errors.Is(err, ErrInvalidTransition):
			atomic.AddInt32(&failures, 1)
		default:
			t.Errorf("unexpected error from Transition(%s): %v", target, err)
		}
	}

	wg.Add(2)
	go race(StateSuspended)
	go race(StateSoftDeleted)
	close(start)
	wg.Wait()

	successCount := atomic.LoadInt32(&successes)
	failureCount := atomic.LoadInt32(&failures)
	if successCount+failureCount != 2 {
		t.Fatalf("totals don't add up: %d successes + %d failures != 2", successCount, failureCount)
	}
	if successCount < 1 {
		t.Fatalf("at least one transition must succeed, got %d", successCount)
	}

	// Atomicity invariant: deleted_at is set IFF the final state is
	// soft_deleted. A torn write (e.g. update state but not deleted_at,
	// or vice versa) would trip this assertion regardless of which
	// goroutine "won".
	final, err := svc.GetByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	switch final.State {
	case StateSoftDeleted:
		if final.DeletedAt == nil {
			t.Error("final state soft_deleted but DeletedAt is nil")
		}
	case StateSuspended:
		if final.DeletedAt != nil {
			t.Error("final state suspended but DeletedAt is set")
		}
	default:
		t.Fatalf("final state = %q, want suspended or soft_deleted", final.State)
	}

	// Callback-fidelity invariant: the OnTransition callback must
	// fire once per successful Transition, with prev matching the
	// state actually observed at the moment the conditional UPDATE
	// landed. The supervisor (SPEC-0002 REQ "One Worker Per Active
	// Account") consumes these notifications and a missed or
	// stale-prev callback would cause it to drop or duplicate workers.
	cbMu.Lock()
	defer cbMu.Unlock()
	if int32(len(cbLog)) != successCount {
		t.Fatalf("callback fires = %d, want %d (one per successful transition)", len(cbLog), successCount)
	}
	switch successCount {
	case 1:
		// Either Delete won outright (prev=active, next=soft_deleted),
		// OR Suspend won and Delete failed because soft_deleted is
		// terminal — but Delete-from-suspended is actually legal
		// (allowedPrevStates(soft_deleted) includes suspended), so
		// successCount=1 only happens when the loser raced into a
		// state from which its target is illegal, which in practice
		// for this two-target race means the only stable single-
		// success outcome is "Delete won and Suspend then saw
		// soft_deleted (terminal)". Pin both legs.
		if cbLog[0].prev != StateActive {
			t.Errorf("single-success callback prev = %q, want %q", cbLog[0].prev, StateActive)
		}
		if cbLog[0].next != StateSoftDeleted && cbLog[0].next != StateSuspended {
			t.Errorf("single-success callback next = %q, want suspended or soft_deleted", cbLog[0].next)
		}
	case 2:
		// Both succeeded: the only legal chain is Suspend then Delete
		// (active→suspended→soft_deleted). The second callback's prev
		// MUST be suspended — that pins down "no callback was lost in
		// the chain" which is exactly what the supervisor depends on
		// to stop the worker on the first transition and not respawn
		// on the second.
		if cbLog[0].prev != StateActive || cbLog[0].next != StateSuspended {
			t.Errorf("first callback = (%s -> %s), want (active -> suspended)", cbLog[0].prev, cbLog[0].next)
		}
		if cbLog[1].prev != StateSuspended || cbLog[1].next != StateSoftDeleted {
			t.Errorf("second callback = (%s -> %s), want (suspended -> soft_deleted)", cbLog[1].prev, cbLog[1].next)
		}
	}
}

// TestCreateTrimsUserID confirms whitespace is stripped from the
// supplied UserID so a value pasted with surrounding whitespace
// resolves to the same row a clean value would.
func TestCreateTrimsUserID(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	uid := storetest.SeedUser(t, st, "sub-paste")
	a, err := svc.Create(ctx, CreateParams{UserID: "  " + uid + "  "})
	if err != nil {
		t.Fatalf("Create with whitespace-padded UserID: %v", err)
	}
	if a.UserID != uid {
		t.Errorf("UserID = %q, want trimmed %q", a.UserID, uid)
	}
}

// TestPrimaryAlias covers the SASL identity lookup contract used by
// the IMAP and SMTP servers (SPEC-0003 / SPEC-0004): set + get round-
// trip, case-fold + trim normalisation, NULL multiplicity, and the
// unique-index collision when two accounts try to claim the same
// alias.
//
// Governing: SPEC-0003 REQ "SASL PLAIN With user@host Identity".
func TestPrimaryAlias(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	// New accounts have an empty alias and are not findable.
	a1 := createTestAccount(t, svc, st, ctx, "sub-alias-1")
	if a1.PrimaryAlias != "" {
		t.Errorf("new account PrimaryAlias = %q, want empty", a1.PrimaryAlias)
	}
	a2 := createTestAccount(t, svc, st, ctx, "sub-alias-2")
	if _, err := svc.GetByPrimaryAlias(ctx, "joe@reduit.example"); !errors.Is(err, ErrAccountNotFound) {
		t.Errorf("lookup before set = %v, want ErrAccountNotFound", err)
	}

	// Two NULL aliases coexist (partial unique index).
	// (Implicit — both Create calls succeeded above.)

	// Provision an alias on a1 with mixed-case + whitespace input;
	// lookup with a different case must still resolve.
	if err := svc.SetPrimaryAlias(ctx, a1.ID, "  Joe@Reduit.Example  "); err != nil {
		t.Fatalf("SetPrimaryAlias: %v", err)
	}
	got, err := svc.GetByPrimaryAlias(ctx, "JOE@reduit.EXAMPLE")
	if err != nil {
		t.Fatalf("GetByPrimaryAlias (case-fold): %v", err)
	}
	if got.ID != a1.ID {
		t.Errorf("GetByPrimaryAlias returned ID %q, want %q", got.ID, a1.ID)
	}
	if got.PrimaryAlias != "joe@reduit.example" {
		t.Errorf("PrimaryAlias stored = %q, want lowercased+trimmed", got.PrimaryAlias)
	}

	// Lookup with empty / whitespace identity = ErrAccountNotFound,
	// not a panic and not a false-positive match.
	for _, q := range []string{"", "   ", "\t\n"} {
		if _, err := svc.GetByPrimaryAlias(ctx, q); !errors.Is(err, ErrAccountNotFound) {
			t.Errorf("GetByPrimaryAlias(%q) = %v, want ErrAccountNotFound", q, err)
		}
	}

	// Collision: a2 cannot take the same alias.
	err = svc.SetPrimaryAlias(ctx, a2.ID, "joe@reduit.example")
	if !errors.Is(err, ErrAccountAlreadyExists) {
		t.Errorf("colliding SetPrimaryAlias = %v, want ErrAccountAlreadyExists", err)
	}

	// a2 can take a different alias.
	if err := svc.SetPrimaryAlias(ctx, a2.ID, "hannah@reduit.example"); err != nil {
		t.Fatalf("SetPrimaryAlias a2 unique: %v", err)
	}

	// Clearing a1's alias frees it up for a2.
	if err := svc.SetPrimaryAlias(ctx, a1.ID, ""); err != nil {
		t.Fatalf("SetPrimaryAlias clear a1: %v", err)
	}
	if _, err := svc.GetByPrimaryAlias(ctx, "joe@reduit.example"); !errors.Is(err, ErrAccountNotFound) {
		t.Errorf("lookup after clear = %v, want ErrAccountNotFound", err)
	}
	if err := svc.SetPrimaryAlias(ctx, a2.ID, "joe@reduit.example"); err != nil {
		t.Fatalf("SetPrimaryAlias a2 after a1 cleared: %v", err)
	}

	// SetPrimaryAlias on a missing account row returns ErrAccountNotFound.
	if err := svc.SetPrimaryAlias(ctx, "missing-id", "ghost@reduit.example"); !errors.Is(err, ErrAccountNotFound) {
		t.Errorf("SetPrimaryAlias missing-id = %v, want ErrAccountNotFound", err)
	}
}

// (Per ADR-0010 admin status is no longer an account attribute --
// it's computed from OIDC_ADMIN_SUBS at session-bind time. The
// equivalent empty-subject defense for the session layer is owned
// by #61 and tested in internal/auth/session.)

// TestMarkCrashedSetsFlag pins SPEC-0002 REQ "Panic Isolation": the
// supervisor's panic-recovery defer calls MarkCrashed to surface the
// "needs manual reset" signal in the admin UI without polling. Calling
// it on a non-existent account returns ErrAccountNotFound.
//
// Governing: SPEC-0002 REQ "Panic Isolation".
func TestMarkCrashedSetsFlag(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	a := createTestAccount(t, svc, st, ctx, "sub-mark-crashed")
	if a.Crashed {
		t.Fatalf("freshly-created account is crashed; want false")
	}

	if err := svc.MarkCrashed(ctx, a.ID); err != nil {
		t.Fatalf("MarkCrashed: %v", err)
	}

	got, err := svc.GetByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !got.Crashed {
		t.Errorf("Crashed = false after MarkCrashed; want true")
	}

	// State MUST NOT change: crashed is a flag, not a transition.
	if got.State != StatePendingProtonSetup {
		t.Errorf("state changed by MarkCrashed: got %q, want pending_proton_setup", got.State)
	}

	// Idempotent: a second call is a no-op (the row matches; the
	// column already holds 1).
	if err := svc.MarkCrashed(ctx, a.ID); err != nil {
		t.Errorf("idempotent MarkCrashed: %v", err)
	}

	// Missing-row → ErrAccountNotFound.
	if err := svc.MarkCrashed(ctx, "no-such-id"); !errors.Is(err, ErrAccountNotFound) {
		t.Errorf("MarkCrashed(missing) = %v, want ErrAccountNotFound", err)
	}
}

// TestSoftDeleteOldPending exercises the retention sweep that #82
// added so orphan pending_proton_setup rows (created when a wizard
// expires from the in-memory store before Proton login completes) do
// not accumulate forever.
//
// We seed three accounts with different shapes:
//   - stale-pending: state=pending_proton_setup, created_at > cutoff
//     (must be soft-deleted)
//   - fresh-pending: state=pending_proton_setup, created_at < cutoff
//     (must be left alone)
//   - active: state=active, created_at older than cutoff
//     (must be left alone -- only pending rows are swept)
//
// Then we call SoftDeleteOldPending with a 24h horizon and assert
// only the stale row was flipped.
//
// Governing: SPEC-0001 REQ "Account Lifecycle States"; SPEC-0005 REQ
// "Add-Proton-Account Wizard"; issue #82.
func TestSoftDeleteOldPending(t *testing.T) {
	t.Parallel()
	svc, st := newTestService(t)
	ctx := context.Background()

	stale := createTestAccount(t, svc, st, ctx, "sub-stale")
	fresh := createTestAccount(t, svc, st, ctx, "sub-fresh")
	activeAcc := createTestAccount(t, svc, st, ctx, "sub-active")

	// Backdate the stale row's created_at to 48h ago and the active
	// row's created_at to 72h ago. Goose migrations stamp created_at
	// at NOW() on insert; we rewrite directly to simulate clock
	// drift past the sweep horizon. The active row is backdated too
	// to confirm the sweep filters by state, not by age alone.
	if _, err := st.DB.Exec(
		`UPDATE accounts SET created_at = datetime('now', '-48 hours') WHERE id = ?`,
		stale.ID,
	); err != nil {
		t.Fatalf("backdate stale: %v", err)
	}
	if _, err := st.DB.Exec(
		`UPDATE accounts SET created_at = datetime('now', '-72 hours'), state = 'active' WHERE id = ?`,
		activeAcc.ID,
	); err != nil {
		t.Fatalf("backdate active: %v", err)
	}

	n, err := svc.SoftDeleteOldPending(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("SoftDeleteOldPending: %v", err)
	}
	if n != 1 {
		t.Errorf("SoftDeleteOldPending rows affected = %d, want 1", n)
	}

	// stale: must now be soft_deleted with deleted_at set.
	got, err := svc.GetByID(ctx, stale.ID)
	if err != nil {
		t.Fatalf("GetByID stale: %v", err)
	}
	if got.State != StateSoftDeleted {
		t.Errorf("stale.State = %q, want %q", got.State, StateSoftDeleted)
	}
	if got.DeletedAt == nil {
		t.Error("stale.DeletedAt must be set after sweep")
	}

	// fresh: must remain pending.
	got, err = svc.GetByID(ctx, fresh.ID)
	if err != nil {
		t.Fatalf("GetByID fresh: %v", err)
	}
	if got.State != StatePendingProtonSetup {
		t.Errorf("fresh.State = %q, want %q (sweep should not touch fresh rows)",
			got.State, StatePendingProtonSetup)
	}

	// active: must remain active even though older than cutoff.
	got, err = svc.GetByID(ctx, activeAcc.ID)
	if err != nil {
		t.Fatalf("GetByID active: %v", err)
	}
	if got.State != StateActive {
		t.Errorf("active.State = %q, want %q (sweep must filter by state)",
			got.State, StateActive)
	}

	// Idempotent: a second sweep with the same horizon affects 0 rows
	// because the previously-stale row is now soft_deleted (filtered
	// out by `state = 'pending_proton_setup'`).
	n, err = svc.SoftDeleteOldPending(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("SoftDeleteOldPending second pass: %v", err)
	}
	if n != 0 {
		t.Errorf("second sweep rows affected = %d, want 0", n)
	}

	// Negative horizon is a programmer error.
	if _, err := svc.SoftDeleteOldPending(ctx, 0); err == nil {
		t.Error("SoftDeleteOldPending(0) must error")
	}
}
