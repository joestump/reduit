package store

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

// TestMigrateRoutesGooseOutputThroughLogger verifies that goose's migration
// output ("OK <migration>", "successfully migrated database ...") flows through
// the *slog.Logger wired via SetLogger — not goose's stdlib `log` default. The
// logger writes to a buffer at DEBUG (the level migration lines log at), and the
// captured text must carry goose's own message, proving the adapter installed by
// Migrate replaced goose's package-global stdLogger.
//
// Not parallel: goose.SetLogger is process-global. Migrate sets it under
// migrateMu right before Up, so this test is deterministic on its own, but we
// keep it serial to avoid interleaving assertions with other Migrate callers.
func TestMigrateRoutesGooseOutputThroughLogger(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "migrate-log.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	var buf bytes.Buffer
	s.SetLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	if err := s.Migrate(""); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	out := buf.String()
	if out == "" {
		t.Fatal("no migration output captured through the slog logger; goose output did not route through SetLogger")
	}
	// goose emits this line from its legacy Up path on a successful migration.
	if !strings.Contains(out, "successfully migrated database") {
		t.Errorf("captured log does not contain goose's migration message:\n%s", out)
	}
	// It must be at DEBUG (routine bookkeeping), so a default info-level run stays quiet.
	if !strings.Contains(out, "level=DEBUG") {
		t.Errorf("migration output not logged at DEBUG:\n%s", out)
	}
}

// TestMigrateSilentAtInfoLevel confirms the default-run behavior: because
// migration lines log at DEBUG, a logger at the default info level captures
// none of goose's per-migration output — a normal `reduit sync`/`mcp` run is
// not noisy with migration chatter.
func TestMigrateSilentAtInfoLevel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "migrate-info.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	var buf bytes.Buffer
	s.SetLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))

	if err := s.Migrate(""); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	if out := buf.String(); strings.Contains(out, "successfully migrated database") || strings.Contains(out, "OK ") {
		t.Errorf("migration output leaked at info level (should be debug-only):\n%s", out)
	}
}
