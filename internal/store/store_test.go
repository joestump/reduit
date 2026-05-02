package store

import (
	"path/filepath"
	"testing"
)

func TestOpenAndMigrate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if got := s.Path(); got == "" {
		t.Errorf("Path() returned empty")
	}

	if err := s.Migrate(""); err != nil {
		t.Fatalf("Migrate (embedded): %v", err)
	}

	// Idempotent: running again is a no-op.
	if err := s.Migrate(""); err != nil {
		t.Fatalf("Migrate (re-run): %v", err)
	}

	// Confirm the accounts table exists.
	var n int
	if err := s.DB.Get(&n, `SELECT COUNT(*) FROM accounts`); err != nil {
		t.Fatalf("query accounts: %v", err)
	}
	if n != 0 {
		t.Errorf("expected empty accounts, got %d rows", n)
	}
}

func TestOpenRejectsEmptyPath(t *testing.T) {
	t.Parallel()
	if _, err := Open(""); err == nil {
		t.Fatal("expected Open(\"\") to fail")
	}
}

// TestWriterDBSerialisesWrites confirms the writer pool is capped at
// one connection so contended writers wait at the database/sql layer
// instead of racing for the SQLite file lock and triggering SQLITE_BUSY.
func TestWriterDBSerialisesWrites(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "writer.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	wdb := s.WriterDB()
	if wdb == nil {
		t.Fatal("WriterDB returned nil")
	}
	if got := wdb.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("writer MaxOpenConnections = %d, want 1", got)
	}
}
