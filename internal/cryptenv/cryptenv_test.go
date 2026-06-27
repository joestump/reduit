package cryptenv

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	t.Parallel()
	dk, err := GenerateDataKey()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("the proton refresh token would go here")

	ct, err := Seal(dk[:], plaintext, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(ct, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := Open(dk[:], ct, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestOpenWithWrongKeyFails(t *testing.T) {
	t.Parallel()
	dk1, _ := GenerateDataKey()
	dk2, _ := GenerateDataKey()
	ct, err := Seal(dk1[:], []byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dk2[:], ct, nil); err == nil {
		t.Fatal("Open with wrong key should fail")
	}
}

func TestOpenWithTamperedCiphertextFails(t *testing.T) {
	t.Parallel()
	dk, _ := GenerateDataKey()
	ct, err := Seal(dk[:], []byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a body byte (skip past the 24-byte nonce).
	ct[24] ^= 0xff
	if _, err := Open(dk[:], ct, nil); err == nil {
		t.Fatal("Open with tampered ciphertext should fail")
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	t.Parallel()
	master, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	dk, err := GenerateDataKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SealEnvelope(master, dk)
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}
	got, err := OpenEnvelope(master, envelope)
	if err != nil {
		t.Fatalf("OpenEnvelope: %v", err)
	}
	if got != dk {
		t.Fatal("data key mismatch after envelope round-trip")
	}
}

func TestNoncesAreUnique(t *testing.T) {
	t.Parallel()
	dk, _ := GenerateDataKey()
	a, _ := Seal(dk[:], []byte("same plaintext"), nil)
	b, _ := Seal(dk[:], []byte("same plaintext"), nil)
	if bytes.Equal(a, b) {
		t.Fatal("two Seal calls with identical plaintext produced identical ciphertext (nonce reuse?)")
	}
}

func TestMasterKeyFileLifecycle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")

	exists, err := MasterKeyExists(path)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("expected master key not to exist yet")
	}

	k, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteMasterKey(path, k); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadMasterKey(path)
	if err != nil {
		t.Fatalf("LoadMasterKey: %v", err)
	}
	if loaded != k {
		t.Fatal("loaded key does not match written key")
	}

	exists, err = MasterKeyExists(path)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("expected master key to exist after write")
	}
}

func TestLoadMasterKeyRejectsLooseMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")
	k, _ := GenerateMasterKey()
	if err := WriteMasterKey(path, k); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadMasterKey(path)
	if err == nil {
		t.Fatal("expected LoadMasterKey to reject mode 0644")
	}
}

// TestWriteMasterKeyIs0600UnderPermissiveUmask pins #53: WriteMasterKey
// must force mode exactly 0600 even when the process umask is wide open
// (umask 0 would otherwise let os.OpenFile's 0600 request stand, but a
// real-world umask like 022 silently strips group/other bits the wrong
// way — we set umask 0 here so a MISSING explicit Chmod would surface as
// a too-permissive 0666-ish file, and assert the file is 0600 anyway).
//
// This test is intentionally NOT parallel: syscall.Umask mutates a
// process-global and must be restored before any other test reads it.
func TestWriteMasterKeyIs0600UnderPermissiveUmask(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")
	k, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteMasterKey(path, k); err != nil {
		t.Fatalf("WriteMasterKey: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("WriteMasterKey mode = %#o, want 0600 (umask was 0; explicit Chmod missing?)", got)
	}
	// LoadMasterKey enforces 0600 on read; if the mode were wrong it
	// would reject, so this is belt-and-suspenders.
	if _, err := LoadMasterKey(path); err != nil {
		t.Fatalf("LoadMasterKey after write: %v", err)
	}
}

// TestWriteMasterKeyAtomicReplacesAnd0600 covers the rotation key-swap
// primitive: it overwrites an existing key file (unlike WriteMasterKey,
// which is O_EXCL) and the result is exactly 0600 even under a wide-open
// umask. Not parallel for the same syscall.Umask reason as above.
func TestWriteMasterKeyAtomicReplacesAnd0600(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")
	k1, _ := GenerateMasterKey()
	if err := WriteMasterKey(path, k1); err != nil {
		t.Fatalf("WriteMasterKey: %v", err)
	}

	k2, _ := GenerateMasterKey()
	if k2 == k1 {
		t.Fatal("two generated keys were identical (broken RNG?)")
	}
	if err := WriteMasterKeyAtomic(path, k2); err != nil {
		t.Fatalf("WriteMasterKeyAtomic: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("WriteMasterKeyAtomic mode = %#o, want 0600", got)
	}
	loaded, err := LoadMasterKey(path)
	if err != nil {
		t.Fatalf("LoadMasterKey: %v", err)
	}
	if loaded != k2 {
		t.Fatal("atomic write did not replace the key bytes")
	}

	// No leftover temp files in the directory after a successful swap.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "master.key" {
			t.Fatalf("unexpected leftover file after atomic write: %q", e.Name())
		}
	}
}

// TestMasterKeyZero proves Zero() wipes the backing array so a master
// key does not linger in memory after a rotation completes (#50).
func TestMasterKeyZero(t *testing.T) {
	t.Parallel()
	k, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	// Vanishingly unlikely to be all-zero already, but assert it so the
	// test is meaningful.
	if k == (MasterKey{}) {
		t.Fatal("freshly generated key was all-zero (broken RNG?)")
	}
	k.Zero()
	if k != (MasterKey{}) {
		t.Fatalf("Zero did not wipe key: %x", k[:])
	}
	for i, b := range k {
		if b != 0 {
			t.Fatalf("byte %d not zeroed: %#x", i, b)
		}
	}
	// Nil receiver must be a safe no-op.
	var nilKey *MasterKey
	nilKey.Zero()
}

func TestLoadMasterKeyRejectsBadSize(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")
	if err := os.WriteFile(path, []byte("too short"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadMasterKey(path)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected size error, got %v", err)
	}
}
