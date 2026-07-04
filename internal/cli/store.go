package cli

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/joestump/reduit/internal/config"
	"github.com/joestump/reduit/internal/store"
)

// openStore ensures the data dir exists, then opens the SQLite store.
//
// modernc.org/sqlite will not create parent directories, so on a clean
// machine (~/.local/share/reduit absent) store.Open fails with
// "unable to open database file (14)". Every store-opening command routes
// through here so the dir is created once, owner-only (0700) — the cache is
// personal data (ADR-0012).
func openStore(cfg config.Config) (*store.Store, error) {
	dbPath := cfg.DBPath()
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	return st, nil
}

// openMigratedStore opens the store and brings it to HEAD before returning it,
// so a command that queries the cache on a brand-new install sees a migrated
// schema instead of a "no such table" error. It mirrors the tui/sync/mcp
// bootstrap and is what the auth commands use — `auth add` is the very first
// onboarding command, run against a fresh data_dir that no migration has touched
// yet. goose's migration output is routed through reduit's logger onto stderr
// (ADR-0022). On a migrate failure the store is closed so the caller need not.
func openMigratedStore(cfg config.Config, logger *slog.Logger) (*store.Store, error) {
	st, err := openStore(cfg)
	if err != nil {
		return nil, err
	}
	st.SetLogger(logger)
	if err := st.Migrate(""); err != nil {
		st.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return st, nil
}
