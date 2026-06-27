// Package filelock provides a lightweight advisory exclusive lock backed
// by a lockfile and flock(2). It exists so that mutually-exclusive
// administrative operations on the same Reduit data directory cannot
// race: `master-key rotate` re-wraps every account's data-key envelope
// and then swaps the master-key file, and a running `serve` daemon holds
// the OLD master key in memory while serving. If the two overlap, the
// daemon would keep sealing/unsealing under a key the rotation is in the
// middle of replacing, corrupting envelopes (split-brain).
//
// The lock is advisory (flock) — it coordinates Reduit processes that
// opt in, not arbitrary writers — and process-associated: the kernel
// releases it automatically if the holder crashes without calling
// Release, so a killed rotation never leaves a stale lock that wedges
// the daemon. This is the property a plain O_EXCL lockfile lacks.
//
// Governing: ADR-0003 (service-master-key envelope encryption), ADR-0006
// (SQLite single-host); #50.
package filelock

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// ErrLocked is returned by Acquire when the lock is already held by
// another process. Callers should surface a clear "is the daemon
// running / another rotation in flight?" message.
var ErrLocked = errors.New("filelock: already held by another process")

// Lock is a held advisory file lock. Call Release (typically via defer)
// to drop it; Release is idempotent.
type Lock struct {
	f    *os.File
	path string
}

// Acquire takes an exclusive, non-blocking advisory lock on `path`,
// creating the lockfile (mode 0600) if it does not exist. If another
// process already holds the lock, Acquire returns ErrLocked without
// blocking. The lockfile is intentionally NOT removed on Release — the
// inode is what flock coordinates on, and unlinking it would let a
// racing Acquire create a fresh inode and lock that instead, defeating
// the mutual exclusion. An empty stale lockfile on disk is harmless.
func Acquire(path string) (*Lock, error) {
	if path == "" {
		return nil, errors.New("filelock: path is empty")
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("filelock: open %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s", ErrLocked, path)
		}
		return nil, fmt.Errorf("filelock: flock %s: %w", path, err)
	}
	return &Lock{f: f, path: path}, nil
}

// Release drops the lock and closes the underlying file descriptor.
// Closing the fd releases the flock; it is idempotent and safe to defer.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	// Closing the descriptor releases the flock. We do not unlink the
	// lockfile (see Acquire) — a zero-byte file left behind is harmless.
	err := l.f.Close()
	l.f = nil
	if err != nil {
		return fmt.Errorf("filelock: close %s: %w", l.path, err)
	}
	return nil
}
