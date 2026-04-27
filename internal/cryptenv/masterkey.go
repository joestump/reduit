// Package cryptenv implements Reduit's two-layer envelope encryption
// scheme per ADR-0003. A 32-byte service master key (loaded from a
// configured file path at startup) seals per-account data keys; each
// data key in turn seals an account's secret fields (refresh token,
// mailbox passphrase, IMAP password).
//
// The package exposes:
//
//   - MasterKey type plus LoadMasterKey / GenerateMasterKey for
//     bootstrapping.
//   - Seal / Open primitives keyed on a 32-byte symmetric key, used
//     for both the envelope and per-account field encryption.
//
// Higher-level account-secret helpers (per-account data key envelope
// open/seal) live alongside the account model and are not in this
// package.
//
// Governing: ADR-0003 (encryption-at-rest scheme), SPEC-0001 REQ
// "Per-Account Data Key", SPEC-0001 REQ "Encrypted Secret Storage".
package cryptenv

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// MasterKeyBytes is the master key length in bytes (256 bits).
const MasterKeyBytes = 32

// MasterKey is the 32-byte service master key. Treat the bytes as
// sensitive — do not log, do not include in error messages, do not
// store anywhere except the configured file path.
type MasterKey [MasterKeyBytes]byte

// GenerateMasterKey reads MasterKeyBytes of cryptographic randomness
// and returns a fresh master key.
func GenerateMasterKey() (MasterKey, error) {
	var k MasterKey
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		return MasterKey{}, fmt.Errorf("cryptenv: read random: %w", err)
	}
	return k, nil
}

// WriteMasterKey persists `k` to `path` with mode 0600. The parent
// directory is created if it does not exist (with mode 0700). The
// write is NOT atomic — callers writing to a path that already exists
// should remove the old file first or use a temp-and-rename pattern.
func WriteMasterKey(path string, k MasterKey) error {
	if path == "" {
		return errors.New("cryptenv: master-key path is empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("cryptenv: mkdir %s: %w", dir, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("cryptenv: create %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(k[:]); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("cryptenv: write master key: %w", err)
	}
	return nil
}

// LoadMasterKey reads a master key from `path`. The file MUST be
// exactly MasterKeyBytes long and have file mode 0600 — anything
// looser fails with a clear error. The strict mode check is a guard
// against operators leaving the file world-readable.
func LoadMasterKey(path string) (MasterKey, error) {
	if path == "" {
		return MasterKey{}, errors.New("cryptenv: master-key path is empty")
	}
	info, err := os.Stat(path)
	if err != nil {
		return MasterKey{}, fmt.Errorf("cryptenv: stat %s: %w", path, err)
	}
	mode := info.Mode().Perm()
	if mode != 0o600 {
		return MasterKey{}, fmt.Errorf("cryptenv: master-key %s has mode %#o, want 0600", path, mode)
	}
	if info.Size() != int64(MasterKeyBytes) {
		return MasterKey{}, fmt.Errorf("cryptenv: master-key %s has size %d, want %d", path, info.Size(), MasterKeyBytes)
	}

	f, err := os.Open(path)
	if err != nil {
		return MasterKey{}, fmt.Errorf("cryptenv: open %s: %w", path, err)
	}
	defer f.Close()

	var k MasterKey
	if _, err := io.ReadFull(f, k[:]); err != nil {
		return MasterKey{}, fmt.Errorf("cryptenv: read %s: %w", path, err)
	}
	return k, nil
}

// MasterKeyExists reports whether a master-key file is present at the
// configured path. Non-existence is signaled by `false, nil`; other
// errors (permission, etc.) are returned.
func MasterKeyExists(path string) (bool, error) {
	if path == "" {
		return false, errors.New("cryptenv: master-key path is empty")
	}
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("cryptenv: stat %s: %w", path, err)
}
