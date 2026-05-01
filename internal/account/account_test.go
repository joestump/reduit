package account

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/store"
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
// runs the embedded migrations, and returns a Service plus a cleanup.
func newTestService(t *testing.T, adminSubs ...string) (Service, *store.Store) {
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
	svc := New(st, master, adminSubs)
	return svc, st
}

func TestCreateAndGetByOIDCSubject(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t)
	ctx := context.Background()

	created, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-joe"})
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
	if created.IsAdmin {
		t.Error("IsAdmin should default to false when subject not in allowlist")
	}

	got, err := svc.GetByOIDCSubject(ctx, "sub-joe")
	if err != nil {
		t.Fatalf("GetByOIDCSubject: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("round-trip ID mismatch: got %q want %q", got.ID, created.ID)
	}

	gotByID, err := svc.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if gotByID.OIDCSubject != "sub-joe" {
		t.Errorf("GetByID subject = %q, want sub-joe", gotByID.OIDCSubject)
	}

	if _, err := svc.GetByOIDCSubject(ctx, "sub-missing"); !errors.Is(err, ErrAccountNotFound) {
		t.Errorf("missing subject error = %v, want ErrAccountNotFound", err)
	}
	if _, err := svc.GetByID(ctx, "id-missing"); !errors.Is(err, ErrAccountNotFound) {
		t.Errorf("missing id error = %v, want ErrAccountNotFound", err)
	}
}

func TestCreateDuplicateOIDCSubject(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Create(ctx, CreateParams{OIDCSubject: "dup"}); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	_, err := svc.Create(ctx, CreateParams{OIDCSubject: "dup"})
	if !errors.Is(err, ErrAccountAlreadyExists) {
		t.Fatalf("dup Create error = %v, want ErrAccountAlreadyExists", err)
	}
}

func TestIsAdminAllowlist(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t, "sub-admin", "sub-other-admin")
	ctx := context.Background()

	admin, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-admin"})
	if err != nil {
		t.Fatalf("Create admin: %v", err)
	}
	if !admin.IsAdmin {
		t.Error("admin row.IsAdmin should be true at create time")
	}
	if !svc.IsAdmin(admin) {
		t.Error("Service.IsAdmin should return true for allowlisted subject")
	}
	if !admin.AdminBy([]string{"sub-admin"}) {
		t.Error("Account.AdminBy should match exact subject")
	}

	user, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-user"})
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}
	if user.IsAdmin {
		t.Error("non-admin row.IsAdmin should be false")
	}
	if svc.IsAdmin(user) {
		t.Error("Service.IsAdmin should return false for non-allowlisted subject")
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
		{StateSuspended, StateActive, true},
		{StateSuspended, StateSoftDeleted, true},
		// Denied
		{StatePendingProtonSetup, StateSuspended, false},
		{StateActive, StatePendingProtonSetup, false},
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
	svc, _ := newTestService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-trans"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

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
	svc, _ := newTestService(t)
	ctx := context.Background()

	for _, sub := range []string{"sub-a", "sub-b", "sub-c"} {
		if _, err := svc.Create(ctx, CreateParams{OIDCSubject: sub}); err != nil {
			t.Fatalf("Create %s: %v", sub, err)
		}
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
	svc, _ := newTestService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-seal"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

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

	a, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-nonce"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

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

	a, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-rotate"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

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
	svc, _ := newTestService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-empty"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
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

func TestCreateRequiresOIDCSubject(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.Create(ctx, CreateParams{}); err == nil {
		t.Fatal("Create with empty OIDCSubject should error")
	}
	// Whitespace-only subject MUST also be rejected (TrimSpace + empty check).
	if _, err := svc.Create(ctx, CreateParams{OIDCSubject: "   "}); err == nil {
		t.Fatal("Create with whitespace-only OIDCSubject should error")
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

	a, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-aad"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

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

	a, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-tamper"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
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

	a, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-wrong-key"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := svc.SealRefreshToken(ctx, a.ID, []byte("payload")); err != nil {
		t.Fatalf("SealRefreshToken: %v", err)
	}

	// Build a second Service against the same DB but with a fresh
	// master key. Envelope-open MUST fail.
	otherMaster, err := cryptenv.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	otherSvc := New(st, otherMaster, nil)
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
	svc, _ := newTestService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-bcrypt-cap"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

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
	svc, _ := newTestService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, CreateParams{OIDCSubject: "sub-race"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Transition(ctx, a.ID, StateActive); err != nil {
		t.Fatalf("seed active: %v", err)
	}

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
}

// TestCreateTrimsOIDCSubject confirms whitespace is stripped from the
// stored subject so it matches the in-memory allowlist regardless of
// operator paste hygiene.
func TestCreateTrimsOIDCSubject(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t, "sub-paste")
	ctx := context.Background()

	a, err := svc.Create(ctx, CreateParams{OIDCSubject: "  sub-paste  "})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if a.OIDCSubject != "sub-paste" {
		t.Errorf("OIDCSubject = %q, want trimmed %q", a.OIDCSubject, "sub-paste")
	}
	if !svc.IsAdmin(a) {
		t.Error("IsAdmin should return true after subject is trimmed to match allowlist entry")
	}
}

// TestIsAdminRejectsEmptySubject locks in the empty-string defense:
// even if OIDC_ADMIN_SUBS contains a stray empty entry (e.g. from
// "OIDC_ADMIN_SUBS=,sub-foo"), an account with an empty subject must
// not be elevated.
func TestIsAdminRejectsEmptySubject(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t, "", "sub-foo")

	empty := &Account{OIDCSubject: ""}
	if svc.IsAdmin(empty) {
		t.Error("IsAdmin must reject accounts with empty OIDCSubject even if the allowlist contains \"\"")
	}
}
