package cli

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/filelock"
	"github.com/joestump/reduit/internal/store"
	"github.com/joestump/reduit/internal/storetest"
)

// quietLogger discards rotation log output so tests stay clean.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// writeMasterKeyFile generates a master key and persists it at path,
// returning the key so a test can assert it was (or was not) swapped.
func writeMasterKeyFile(t *testing.T, path string) cryptenv.MasterKey {
	t.Helper()
	k, err := cryptenv.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := cryptenv.WriteMasterKey(path, k); err != nil {
		t.Fatalf("WriteMasterKey: %v", err)
	}
	return k
}

// openTestStore opens + migrates a fresh on-disk store at dbPath.
func openTestStore(t *testing.T, dbPath string) *store.Store {
	t.Helper()
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(""); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}
	return st
}

// TestRotateMasterKeyHappyPath proves a populated DB rotates cleanly: the
// new key opens every account secret, the key file is swapped, exactly
// one timestamped+random .bak of the old key is left behind, and the WAL
// checkpoint on the path does not break the rotation.
func TestRotateMasterKeyHappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	dir := t.TempDir()
	mkPath := filepath.Join(dir, "master.key")
	dbPath := filepath.Join(dir, "reduit.db")

	oldKey := writeMasterKeyFile(t, mkPath)

	// Seed one account with a sealed secret under the OLD key.
	st := openTestStore(t, dbPath)
	svc := account.New(st, oldKey)
	uid := storetest.SeedUser(t, st, "sub-happy")
	a, err := svc.Create(ctx, account.CreateParams{UserID: uid})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	token := []byte("refresh-token-happy")
	if err := svc.SealRefreshToken(ctx, a.ID, token); err != nil {
		t.Fatalf("SealRefreshToken: %v", err)
	}
	// Close so rotateMasterKey opens its own handle against the same file.
	if err := st.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	if err := rotateMasterKey(ctx, quietLogger(), rotateParams{
		MasterKeyPath: mkPath,
		StorePath:     dbPath,
	}); err != nil {
		t.Fatalf("rotateMasterKey: %v", err)
	}

	// The key file must have changed.
	newKey, err := cryptenv.LoadMasterKey(mkPath)
	if err != nil {
		t.Fatalf("LoadMasterKey post-rotate: %v", err)
	}
	if newKey == oldKey {
		t.Fatal("master key file was not swapped")
	}

	// The new key must unseal the account secret sealed before rotation.
	st2 := openTestStore(t, dbPath)
	newSvc := account.New(st2, newKey)
	got, err := newSvc.OpenRefreshToken(ctx, a.ID)
	if err != nil {
		t.Fatalf("OpenRefreshToken under new key: %v", err)
	}
	if string(got) != string(token) {
		t.Fatalf("token mismatch: got %q want %q", got, token)
	}

	// Exactly one .bak of the old key must exist, and it must contain the
	// OLD key bytes.
	baks := bakFiles(t, dir, "master.key")
	if len(baks) != 1 {
		t.Fatalf("want exactly 1 .bak, got %d: %v", len(baks), baks)
	}
	bakKey, err := cryptenv.LoadMasterKey(baks[0])
	if err != nil {
		t.Fatalf("LoadMasterKey bak: %v", err)
	}
	if bakKey != oldKey {
		t.Fatal(".bak does not contain the old key")
	}
}

// TestRotateMasterKeyEmptyDBRefused proves the empty-DB guard: a DB with
// zero accounts refuses to swap the key (no envelope verified the current
// key) and leaves the key file untouched and no .bak behind.
func TestRotateMasterKeyEmptyDBRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	dir := t.TempDir()
	mkPath := filepath.Join(dir, "master.key")
	dbPath := filepath.Join(dir, "reduit.db")

	oldKey := writeMasterKeyFile(t, mkPath)
	// Migrate an empty DB so Open+Migrate succeed but there are 0 accounts.
	_ = openTestStore(t, dbPath)

	err := rotateMasterKey(ctx, quietLogger(), rotateParams{
		MasterKeyPath: mkPath,
		StorePath:     dbPath,
	})
	if err == nil {
		t.Fatal("rotateMasterKey on empty DB: want error, got nil")
	}
	if !strings.Contains(err.Error(), "no accounts to re-wrap") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Key file must be untouched.
	stillOld, err := cryptenv.LoadMasterKey(mkPath)
	if err != nil {
		t.Fatalf("LoadMasterKey: %v", err)
	}
	if stillOld != oldKey {
		t.Fatal("empty-DB refusal still swapped the key file")
	}
	// No .bak should have been written.
	if baks := bakFiles(t, dir, "master.key"); len(baks) != 0 {
		t.Fatalf("empty-DB refusal left a .bak: %v", baks)
	}
}

// TestRotateMasterKeyEmptyDBAllowEmpty proves --allow-empty bypasses the
// empty-DB guard for the legitimate fresh-install case: the key file is
// swapped even though zero accounts were re-wrapped.
func TestRotateMasterKeyEmptyDBAllowEmpty(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	dir := t.TempDir()
	mkPath := filepath.Join(dir, "master.key")
	dbPath := filepath.Join(dir, "reduit.db")

	oldKey := writeMasterKeyFile(t, mkPath)
	_ = openTestStore(t, dbPath)

	if err := rotateMasterKey(ctx, quietLogger(), rotateParams{
		MasterKeyPath: mkPath,
		StorePath:     dbPath,
		AllowEmpty:    true,
	}); err != nil {
		t.Fatalf("rotateMasterKey --allow-empty: %v", err)
	}

	newKey, err := cryptenv.LoadMasterKey(mkPath)
	if err != nil {
		t.Fatalf("LoadMasterKey: %v", err)
	}
	if newKey == oldKey {
		t.Fatal("--allow-empty did not swap the key file")
	}
	if baks := bakFiles(t, dir, "master.key"); len(baks) != 1 {
		t.Fatalf("want 1 .bak after allow-empty rotation, got %d", len(baks))
	}
}

// TestRotateMasterKeyRefusesWhenLocked proves the concurrency lock: if the
// master-key lock is already held (e.g. by a running daemon), rotate
// refuses with ErrLocked and does not touch the key file.
func TestRotateMasterKeyRefusesWhenLocked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	dir := t.TempDir()
	mkPath := filepath.Join(dir, "master.key")
	dbPath := filepath.Join(dir, "reduit.db")

	oldKey := writeMasterKeyFile(t, mkPath)
	_ = openTestStore(t, dbPath)

	// Simulate a running daemon holding the lock.
	held, err := filelock.Acquire(MasterKeyLockPath(mkPath))
	if err != nil {
		t.Fatalf("pre-acquire lock: %v", err)
	}
	defer func() { _ = held.Release() }()

	err = rotateMasterKey(ctx, quietLogger(), rotateParams{
		MasterKeyPath: mkPath,
		StorePath:     dbPath,
	})
	if !errors.Is(err, filelock.ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
	stillOld, err := cryptenv.LoadMasterKey(mkPath)
	if err != nil {
		t.Fatal(err)
	}
	if stillOld != oldKey {
		t.Fatal("locked rotation still swapped the key file")
	}
}

// bakFiles returns the rotation backups for keyBase in dir (files named
// keyBase.<...>.bak).
func bakFiles(t *testing.T, dir, keyBase string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, keyBase+".") && strings.HasSuffix(name, ".bak") {
			out = append(out, filepath.Join(dir, name))
		}
	}
	return out
}
