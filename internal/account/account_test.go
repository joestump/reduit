package account

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
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
}
