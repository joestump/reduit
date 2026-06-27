package filelock

import (
	"errors"
	"path/filepath"
	"testing"
)

// TestAcquireExclusive proves a second Acquire on a held lock returns
// ErrLocked, and that Release frees the lock for a subsequent Acquire.
func TestAcquireExclusive(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "test.lock")

	first, err := Acquire(path)
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}

	if _, err := Acquire(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Acquire while held: want ErrLocked, got %v", err)
	}

	if err := first.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	// After release the lock is acquirable again.
	second, err := Acquire(path)
	if err != nil {
		t.Fatalf("Acquire after Release: %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatalf("second Release: %v", err)
	}
}

// TestReleaseIdempotent proves Release is safe to call twice and on a nil
// lock.
func TestReleaseIdempotent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "test.lock")
	l, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("first Release: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("second Release should be no-op: %v", err)
	}
	var nilLock *Lock
	if err := nilLock.Release(); err != nil {
		t.Fatalf("nil Release: %v", err)
	}
}

func TestAcquireEmptyPath(t *testing.T) {
	t.Parallel()
	if _, err := Acquire(""); err == nil {
		t.Fatal("Acquire(\"\") should error")
	}
}
