// Package store wraps the SQLite database. It opens the connection
// with WAL mode + foreign keys + a generous busy timeout, exposes a
// typed wrapper around sqlx.DB, and runs goose migrations either from
// disk (config) or the binary's embedded migrations.
//
// Two pools live here: the default `DB` is the multi-conn pool used
// by reads and write paths whose contention frequency is rare enough
// that BEGIN IMMEDIATE serialisation does not matter. The writer pool
// returned by `WriterDB` is opened against the SAME underlying file
// but pinned to MaxOpenConns(1), so callers that race for the write
// lock (mailbox.AssignUID is the canonical example) serialise at the
// connection layer instead of through SQLITE_BUSY retries.
//
// SQLite's WAL mode allows exactly one writer at a time anyway; the
// single-conn writer pool surfaces that constraint at the database/sql
// layer where Go's pool already has a wait queue, instead of pushing
// the contention to the driver where every loser has to back off,
// jitter, and retry. Reads continue to use `DB` and remain fully
// concurrent under WAL.
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
	"sync"

	"github.com/jmoiron/sqlx"
	"github.com/pressly/goose/v3"

	_ "modernc.org/sqlite" // sqlite driver, pure-Go, no CGO
)

// migrateMu serialises calls to goose.Up within a process. Goose's
// package-level globals (SetBaseFS, SetDialect, SetTableName) are not
// concurrency-safe, so two parallel callers of Migrate can race on
// them even though their target databases are independent.
//
// Scope: process-local only. This lock is sufficient for the v0.x
// single-process Reduit deployment described in ADR-0006 ("the relay
// is single-host", "single-file deployment") and for parallel `go
// test` runs that open many fresh stores. It does NOT generalise to
// a multi-replica deployment: two Reduit processes pointed at the
// same SQLite file calling goose.Up concurrently still race on
// `goose_db_version` at the database level — one will hit a UNIQUE
// constraint violation and the migration will fail. A future
// multi-replica deployment MUST coordinate via a database-level
// advisory lock (e.g. `BEGIN IMMEDIATE; SELECT version_id FROM
// goose_db_version`); tracked separately so a single-host operator
// is not paying that complexity today.
var migrateMu sync.Mutex

//go:embed all:migrations/*.sql
var embeddedMigrations embed.FS

// Store wraps a *sqlx.DB plus knowledge of where it came from so we
// can produce useful error messages and clean diagnostic output.
type Store struct {
	DB     *sqlx.DB
	writer *sqlx.DB
	path   string
}

// Open dials the SQLite database at `path`. The connection string
// applies WAL mode, foreign keys, a 5s busy timeout, and the
// modernc.org/sqlite-style URL. Open does NOT run migrations;
// callers should call Migrate after a successful Open.
//
// Two pools are opened against the same file:
//
//   - `DB` is the default multi-connection pool. Concurrent readers
//     proceed in parallel (WAL); writers compete for the file lock at
//     BEGIN time.
//   - The writer pool (returned by WriterDB) is pinned to
//     MaxOpenConns(1) so contended writers serialise at the database/
//     sql layer instead of via driver-level SQLITE_BUSY retries.
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

	writerRaw, err := sql.Open("sqlite", dsn)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: open writer: %w", err)
	}
	// Single connection: SQLite's WAL mode permits one writer at a
	// time, so a multi-conn writer pool would just push the queue from
	// Go's sync.Pool down to SQLite's BEGIN IMMEDIATE retry path. By
	// capping at 1 we serialise at the (already-correct) database/sql
	// pool layer.
	writerRaw.SetMaxOpenConns(1)
	if err := writerRaw.Ping(); err != nil {
		_ = writerRaw.Close()
		_ = db.Close()
		return nil, fmt.Errorf("store: ping writer: %w", err)
	}
	writer := sqlx.NewDb(writerRaw, "sqlite")

	return &Store{DB: db, writer: writer, path: abs}, nil
}

// Path returns the absolute path the database is open against.
func (s *Store) Path() string { return s.path }

// WriterDB returns the single-connection writer pool. Callers whose
// writes would otherwise contend on SQLITE_BUSY at BEGIN IMMEDIATE
// time (e.g. internal/mailbox.AssignUID) should issue their writes
// through this handle. The connection cap of 1 means transactions
// queue at the database/sql layer instead of racing the file lock.
//
// Reads should continue to use `DB` so WAL's many-readers-one-writer
// concurrency story is preserved.
//
// Returns nil if Store is not open.
func (s *Store) WriterDB() *sqlx.DB {
	if s == nil {
		return nil
	}
	return s.writer
}

// Close releases both database handles.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	var first error
	if s.writer != nil {
		if err := s.writer.Close(); err != nil {
			first = err
		}
	}
	if s.DB != nil {
		if err := s.DB.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Migrate runs all unapplied goose migrations. If `dirOverride` is
// non-empty, migrations are read from that directory; otherwise the
// binary's embedded migrations are used. Migrate is idempotent — it
// returns nil if the database is already at HEAD.
func (s *Store) Migrate(dirOverride string) error {
	if s == nil || s.DB == nil {
		return errors.New("store: not open")
	}
	migrateMu.Lock()
	defer migrateMu.Unlock()
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
