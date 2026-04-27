package cryptenv

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
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
