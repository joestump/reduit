package cli

import (
	"fmt"
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
