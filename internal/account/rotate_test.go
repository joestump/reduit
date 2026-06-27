package account

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/store"
	"github.com/joestump/reduit/internal/storetest"
)

// newTestStore spins up a fresh on-disk SQLite (under t.TempDir) with the
// embedded migrations applied. Unlike newTestService it does NOT mint the
// service, so a rotation test can construct two services (old key, new
// key) against the same store.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "reduit-rotate-test.db")
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
	return st
}

// TestRewrapEnvelopesRotatesAllAccounts proves the #50 happy path:
// after re-wrapping every account's envelope from the old master key to
// a new one, a service built with the NEW key can still unseal each
// account's data key and decrypt a secret sealed BEFORE rotation. The
// data key and the secret ciphertext are unchanged — only the envelope
// wrapping is re-encrypted.
func TestRewrapEnvelopesRotatesAllAccounts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newTestStore(t)

	oldKey, err := cryptenv.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	oldSvc := New(st, oldKey)

	// Seed several accounts and seal a distinct refresh token in each so
	// we can prove the per-account secret survives rotation untouched.
	const nAccounts = 3
	type fixture struct {
		id    string
		token []byte
	}
	fixtures := make([]fixture, 0, nAccounts)
	for i := 0; i < nAccounts; i++ {
		sub := "sub-rotate-" + string(rune('a'+i))
		uid := storetest.SeedUser(t, st, sub)
		a, err := oldSvc.Create(ctx, CreateParams{UserID: uid})
		if err != nil {
			t.Fatalf("Create[%d]: %v", i, err)
		}
		token := []byte("refresh-token-" + a.ID)
		if err := oldSvc.SealRefreshToken(ctx, a.ID, token); err != nil {
			t.Fatalf("SealRefreshToken[%d]: %v", i, err)
		}
		fixtures = append(fixtures, fixture{id: a.ID, token: token})
	}

	// Snapshot the pre-rotation envelopes so we can prove they actually
	// changed (re-wrapped) while the secret ciphertext did not.
	preEnvelopes := make(map[string][]byte, nAccounts)
	preTokenCT := make(map[string][]byte, nAccounts)
	for _, f := range fixtures {
		row, err := oldSvc.(*service).repo.getByID(ctx, f.id)
		if err != nil {
			t.Fatalf("getByID pre[%s]: %v", f.id, err)
		}
		preEnvelopes[f.id] = append([]byte(nil), row.KeyEnvelope...)
		preTokenCT[f.id] = append([]byte(nil), row.RefreshTokenCiphertext...)
	}

	newKey, err := cryptenv.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if newKey == oldKey {
		t.Fatal("generated identical keys")
	}

	n, err := oldSvc.RewrapEnvelopes(ctx, newKey)
	if err != nil {
		t.Fatalf("RewrapEnvelopes: %v", err)
	}
	if n != nAccounts {
		t.Fatalf("RewrapEnvelopes re-wrapped %d accounts, want %d", n, nAccounts)
	}

	// A service built with the NEW key must decrypt every secret; the OLD
	// service must now fail to open the re-wrapped envelopes.
	newSvc := New(st, newKey)
	for _, f := range fixtures {
		got, err := newSvc.OpenRefreshToken(ctx, f.id)
		if err != nil {
			t.Fatalf("OpenRefreshToken[%s] under new key: %v", f.id, err)
		}
		if !bytes.Equal(got, f.token) {
			t.Fatalf("token mismatch[%s]: got %q want %q", f.id, got, f.token)
		}

		row, err := newSvc.(*service).repo.getByID(ctx, f.id)
		if err != nil {
			t.Fatalf("getByID post[%s]: %v", f.id, err)
		}
		// Envelope MUST have changed (re-wrapped under the new key).
		if bytes.Equal(row.KeyEnvelope, preEnvelopes[f.id]) {
			t.Fatalf("envelope[%s] unchanged after rotation", f.id)
		}
		// Secret ciphertext MUST be byte-identical: rotation never
		// touches the per-account data key or the fields sealed under it.
		if !bytes.Equal(row.RefreshTokenCiphertext, preTokenCT[f.id]) {
			t.Fatalf("refresh-token ciphertext[%s] changed during rotation", f.id)
		}

		// The OLD key must no longer unseal the re-wrapped envelope.
		if _, err := oldSvc.OpenRefreshToken(ctx, f.id); err == nil {
			t.Fatalf("old key still opens envelope[%s] after rotation", f.id)
		}
	}
}

// TestRewrapEnvelopesRejectsWrongOldKey proves the mismatched-key guard:
// if the service's current master key cannot unseal an existing
// envelope, RewrapEnvelopes refuses (ErrMasterKeyMismatch) and leaves
// every envelope untouched (the transaction rolls back).
func TestRewrapEnvelopesRejectsWrongOldKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newTestStore(t)

	realKey, err := cryptenv.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	realSvc := New(st, realKey)
	uid := storetest.SeedUser(t, st, "sub-wrongkey")
	a, err := realSvc.Create(ctx, CreateParams{UserID: uid})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	token := []byte("refresh-token-wrongkey")
	if err := realSvc.SealRefreshToken(ctx, a.ID, token); err != nil {
		t.Fatalf("SealRefreshToken: %v", err)
	}

	before, err := realSvc.(*service).repo.getByID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	beforeEnvelope := append([]byte(nil), before.KeyEnvelope...)

	// Build a service holding a WRONG "current" key, then try to rotate
	// to a third key. The wrong key cannot unseal the stored envelope.
	wrongKey, err := cryptenv.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	wrongSvc := New(st, wrongKey)
	targetKey, err := cryptenv.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}

	n, err := wrongSvc.RewrapEnvelopes(ctx, targetKey)
	if !errors.Is(err, ErrMasterKeyMismatch) {
		t.Fatalf("RewrapEnvelopes with wrong old key: err = %v, want ErrMasterKeyMismatch", err)
	}
	if n != 0 {
		t.Fatalf("RewrapEnvelopes reported %d rewrapped on mismatch, want 0", n)
	}

	// Envelope must be untouched, and the REAL key must still open the
	// secret — the failed rotation rolled back cleanly.
	after, err := realSvc.(*service).repo.getByID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after.KeyEnvelope, beforeEnvelope) {
		t.Fatal("envelope changed despite mismatched-key rejection (rollback failed?)")
	}
	got, err := realSvc.OpenRefreshToken(ctx, a.ID)
	if err != nil {
		t.Fatalf("real key no longer opens secret after rejected rotation: %v", err)
	}
	if !bytes.Equal(got, token) {
		t.Fatalf("secret mismatch after rejected rotation: got %q want %q", got, token)
	}
}
