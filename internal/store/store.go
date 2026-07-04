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
// lock (any hot write path that would otherwise contend on the file
// lock) serialise at the connection layer instead of through
// SQLITE_BUSY retries.
//
// SQLite's WAL mode allows exactly one writer at a time anyway; the
// single-conn writer pool surfaces that constraint at the database/sql
// layer where Go's pool already has a wait queue, instead of pushing
// the contention to the driver where every loser has to back off,
// jitter, and retry. Reads continue to use `DB` and remain fully
// concurrent under WAL.
//
// Governing: ADR-0006 (SQLite + WAL + goose), ADR-0012 (single-user
// local-first; the schema is mailbox-scoped — per-mailbox tables carry
// mailbox_id, enforced at the schema layer in migrations).
package store

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"path/filepath"
	"strings"
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
// Scope: process-local only. This lock is sufficient for the
// single-process Reduit binary described in ADR-0006 ("single-file
// deployment", "Replication / HA is out of scope") and ADR-0012
// (single-user local-first; one process owns the data directory) and
// for parallel `go test` runs that open many fresh stores.
//
// DECISION (item #20.3): a database-level advisory lock around
// goose.Up (e.g. BEGIN IMMEDIATE) is deliberately NOT added. It would
// only matter if two Reduit *processes* pointed at the same SQLite
// file ran goose.Up concurrently — and that arrangement is excluded by
// ADR-0006, which makes single-process/single-host the accepted
// posture (SQLite + a single writer; HA/replication out of scope). In
// that excluded multi-replica setup the two processes would race on
// `goose_db_version` at the database level and one would hit a UNIQUE
// constraint violation; if Reduit ever adopts a multi-replica posture
// (a new ADR superseding ADR-0006), the fix is a DB advisory lock
// here. Until then a process-local mutex is the lighter correct
// choice and a DB lock would be complexity a single-host operator
// pays for nothing.
//
// Governing: ADR-0006 (SQLite, single-host, HA out of scope).
var migrateMu sync.Mutex

//go:embed all:migrations
var embeddedMigrations embed.FS

// Store wraps a *sqlx.DB plus knowledge of where it came from so we
// can produce useful error messages and clean diagnostic output.
type Store struct {
	DB     *sqlx.DB
	writer *sqlx.DB
	path   string
	logger *slog.Logger
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

	// Default to a discarding logger so migration output (routed through
	// goose.SetLogger in Migrate) is silently dropped until a caller wires
	// in a real logger via SetLogger. This keeps `go test` runs — which open
	// stores without a logger — free of stray goose/stdlib log noise.
	return &Store{DB: db, writer: writer, path: abs, logger: slog.New(slog.DiscardHandler)}, nil
}

// Path returns the absolute path the database is open against. A nil receiver
// returns "" rather than panicking, matching the nil-guard degradation of the
// other read methods (Stats/MailboxStats/SchemaVersion/LatestSyncRun) so a
// caller holding a not-open Store degrades uniformly.
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// SetLogger sets the structured logger used for store-level diagnostics,
// most notably the goose migration output routed through Migrate. Commands
// that already build the root *slog.Logger (mcp, sync, migrate) call this
// before Migrate so goose's "OK <migration>" / "successfully migrated" lines
// flow through reduit's charmbracelet/log handler (ADR-0022) on stderr
// instead of goose's stdlib log default. A nil logger is ignored so the
// discarding default set at Open is preserved.
func (s *Store) SetLogger(l *slog.Logger) {
	if s == nil || l == nil {
		return
	}
	s.logger = l
}

// WriterDB returns the single-connection writer pool. Callers whose
// writes would otherwise contend on SQLITE_BUSY at BEGIN IMMEDIATE
// time (any hot, frequently-contended write path) should issue their
// writes through this handle. The connection cap of 1 means
// transactions queue at the database/sql layer instead of racing the
// file lock.
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
	// goose.SetLogger is process-global, but migrateMu already serialises
	// every Migrate call in-process (it guards goose's other package globals
	// too), so setting it here — right before Up, under the lock — is
	// deterministic and cannot race a concurrent Migrate. Each call installs
	// its own store's logger, so parallel `go test` stores never leak one
	// another's sink. Migrations are routine bookkeeping, so their output logs
	// at DEBUG: a normal `reduit sync`/`mcp` run at the default info level stays
	// quiet, while `--verbose` (debug) surfaces the "OK <migration>" lines in
	// charm format on stderr.
	goose.SetLogger(gooseSlogLogger{logger: s.logger})
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
		if errors.Is(err, goose.ErrNoMigrationFiles) {
			// No migration files yet — valid for a freshly-stripped store.
			return nil
		}
		return fmt.Errorf("store: goose up: %w", err)
	}
	return nil
}

// gooseSlogLogger adapts an *slog.Logger to goose's Logger interface
// (Printf/Fatalf) so goose's migration output joins the rest of reduit's
// structured logging (charmbracelet/log via slog, ADR-0022) on one stream
// instead of goose's stdlib `log` default. goose passes printf-style,
// newline-terminated strings; we render them and trim the trailing newline
// so the message reads cleanly through the slog handler.
type gooseSlogLogger struct {
	logger *slog.Logger
}

var _ goose.Logger = gooseSlogLogger{}

// Printf handles goose's routine progress output ("OK <migration>",
// "successfully migrated database ..."). Migrations are routine bookkeeping,
// so this logs at DEBUG — a normal run at the default info level stays quiet.
func (g gooseSlogLogger) Printf(format string, v ...any) {
	if g.logger == nil {
		return
	}
	g.logger.Debug(strings.TrimRight(fmt.Sprintf(format, v...), "\n"))
}

// Fatalf matches goose's interface faithfully but does NOT os.Exit: goose only
// calls Fatalf on a fatal internal error, and the Up error it accompanies is
// already returned up the stack (Migrate wraps it). We log it at ERROR so the
// detail is not swallowed, then let the surrounding error return drive control
// flow — killing the process here would strip callers of that error and their
// deferred cleanup.
func (g gooseSlogLogger) Fatalf(format string, v ...any) {
	if g.logger == nil {
		return
	}
	g.logger.Error(strings.TrimRight(fmt.Sprintf(format, v...), "\n"))
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
