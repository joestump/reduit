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

// Zero best-effort wipes the master-key bytes from memory after use. Go
// gives no hard guarantee against compiler reuse or copies the caller
// made, but explicitly zeroing the backing array shrinks the residency
// window for a value whose exposure is total compromise. Callers that
// hold a MasterKey only for the duration of an operation (e.g.
// `master-key rotate`) should `defer k.Zero()`, mirroring the
// zeroDataKey discipline in internal/account.
//
// Governing: ADR-0003 (service-master-key envelope encryption); #50.
func (k *MasterKey) Zero() {
	if k == nil {
		return
	}
	for i := range k {
		k[i] = 0
	}
}

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
// should remove the old file first or use a temp-and-rename pattern
// (see WriteMasterKeyAtomic, used by `master-key rotate`).
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
	// The 0600 mode passed to OpenFile is masked by the process umask, so
	// a permissive umask (e.g. 022) would leave the file group/other
	// readable despite the O_EXCL create. An explicit Chmod after create
	// guarantees the master key is owner-only regardless of umask — a
	// hard requirement for a file whose loss-or-exposure is total
	// compromise. LoadMasterKey enforces the same 0600 on read.
	//
	// Governing: ADR-0003 (service-master-key envelope encryption); #53.
	if err := f.Chmod(0o600); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("cryptenv: chmod %s: %w", path, err)
	}
	if _, err := f.Write(k[:]); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("cryptenv: write master key: %w", err)
	}
	return nil
}

// WriteMasterKeyAtomic durably and atomically replaces the master-key
// file at `path` with `k`. It writes to a fresh temp file in the SAME
// directory (so the final os.Rename is a same-filesystem atomic swap),
// chmods it to 0600 (umask-proof, like WriteMasterKey), fsyncs both the
// file and its parent directory, then renames over `path`.
//
// Unlike WriteMasterKey this overwrites an existing file — it is the
// key-swap primitive for `master-key rotate`, which must replace the
// live key only after the re-wrapped envelopes have committed. The
// fsyncs ensure the new key bytes hit stable storage before the rename
// makes them visible, so a crash cannot leave a torn/empty key file at
// `path`. The temp file is removed on any error before the rename;
// after a successful rename there is no temp file to clean up.
//
// Governing: ADR-0003 (service-master-key envelope encryption); #50, #53.
func WriteMasterKeyAtomic(path string, k MasterKey) error {
	if path == "" {
		return errors.New("cryptenv: master-key path is empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("cryptenv: mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".master.key.*.tmp")
	if err != nil {
		return fmt.Errorf("cryptenv: create temp in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup if we error out before a successful rename.
	// After Rename succeeds tmpPath no longer exists, so this Remove is
	// a harmless no-op.
	cleanup := true
	defer func() {
		if cleanup {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	// CreateTemp makes the file 0600 already, but it too is umask-masked;
	// chmod explicitly so the guarantee does not depend on the umask.
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("cryptenv: chmod temp %s: %w", tmpPath, err)
	}
	if _, err := tmp.Write(k[:]); err != nil {
		return fmt.Errorf("cryptenv: write temp %s: %w", tmpPath, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("cryptenv: fsync temp %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cryptenv: close temp %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("cryptenv: rename %s -> %s: %w", tmpPath, path, err)
	}
	cleanup = false
	// fsync the directory so the rename itself is durable — without this
	// a crash right after rename could lose the directory entry update
	// and resurrect the old key file. The Sync error is load-bearing for
	// rename durability, so it is RETURNED rather than swallowed: a caller
	// (e.g. `master-key rotate`) that ignores it would believe the swap
	// hit stable storage when it may not have, defeating the crash-safety
	// ordering. The rename already succeeded, so on a Sync error the new
	// key IS at `path`; the error tells the operator durability is
	// unconfirmed, not that the swap failed.
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("cryptenv: open dir %s for fsync: %w", dir, err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return fmt.Errorf("cryptenv: fsync dir %s: %w", dir, err)
	}
	if err := d.Close(); err != nil {
		return fmt.Errorf("cryptenv: close dir %s: %w", dir, err)
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
