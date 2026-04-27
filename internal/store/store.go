// Package store wraps the SQLite database. It opens the connection
// with WAL mode + foreign keys + a generous busy timeout, exposes a
// typed wrapper around sqlx.DB, and runs goose migrations either from
// disk (config) or the binary's embedded migrations.
//
// Governing: ADR-0006 (SQLite + WAL + goose), SPEC-0001 REQ
// "Account-Scoped Data" (every per-account table carries account_id;
// enforced at the schema layer in migrations).
package store

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"

	"github.com/jmoiron/sqlx"
	"github.com/pressly/goose/v3"

	_ "modernc.org/sqlite" // sqlite driver, pure-Go, no CGO
)

//go:embed all:migrations/*.sql
var embeddedMigrations embed.FS

// Store wraps a *sqlx.DB plus knowledge of where it came from so we
// can produce useful error messages and clean diagnostic output.
type Store struct {
	DB   *sqlx.DB
	path string
}

// Open dials the SQLite database at `path`. The connection string
// applies WAL mode, foreign keys, a 5s busy timeout, and the
// modernc.org/sqlite-style URL. Open does NOT run migrations;
// callers should call Migrate after a successful Open.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: path is empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("store: abs path: %w", err)
	}
	dsn := buildDSN(abs)

	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	if err := raw.Ping(); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}

	db := sqlx.NewDb(raw, "sqlite")
	return &Store{DB: db, path: abs}, nil
}

// Path returns the absolute path the database is open against.
func (s *Store) Path() string { return s.path }

// Close releases the database handle.
func (s *Store) Close() error {
	if s == nil || s.DB == nil {
		return nil
	}
	return s.DB.Close()
}

// Migrate runs all unapplied goose migrations. If `dirOverride` is
// non-empty, migrations are read from that directory; otherwise the
// binary's embedded migrations are used. Migrate is idempotent — it
// returns nil if the database is already at HEAD.
func (s *Store) Migrate(dirOverride string) error {
	if s == nil || s.DB == nil {
		return errors.New("store: not open")
	}
	goose.SetBaseFS(nil)
	goose.SetTableName("goose_db_version")
	if err := goose.SetDialect("sqlite3"); err != nil {
		return fmt.Errorf("store: set dialect: %w", err)
	}
	dir := dirOverride
	if dir == "" {
		goose.SetBaseFS(embeddedMigrations)
		dir = "migrations"
	}
	if err := goose.Up(s.DB.DB, dir); err != nil {
		return fmt.Errorf("store: goose up: %w", err)
	}
	return nil
}

// buildDSN returns the modernc.org/sqlite DSN with our standard
// pragmas applied via URL query params.
func buildDSN(absPath string) string {
	q := url.Values{}
	q.Set("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "foreign_keys(ON)")
	q.Add("_pragma", "busy_timeout(5000)")
	return fmt.Sprintf("file:%s?%s", absPath, q.Encode())
}
