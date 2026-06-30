// Package store — cache health/statistics methods.
//
// These read-only aggregates back the MCP `status` tool (SPEC-0006) and the
// loopback UI's health surface: both call the SAME store methods so the two
// surfaces cannot drift (SPEC-0006 REQ "Thin Adapter Over the Store").
//
// Governing: ADR-0006 (SQLite cache), ADR-0012 (single-user local-first),
//
//	ADR-0017 (stdio MCP), SPEC-0006 REQ "Thin Adapter Over the Store".
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Stats is a snapshot of the local cache's size: one COUNT(*) per primary
// content table. It is intentionally cheap (three indexed counts) so the MCP
// `status` tool can be polled freely to validate that the cache is reachable
// and populated.
type Stats struct {
	// Mailboxes is the number of configured Proton mailboxes.
	Mailboxes int64 `db:"mailboxes"`
	// Messages is the number of cached (decrypted) messages.
	Messages int64 `db:"messages"`
	// Attachments is the number of cached attachment rows.
	Attachments int64 `db:"attachments"`
	// Embedded is the number of messages that have at least one embedding
	// (any model). It is the corpus-wide numerator of embedding coverage.
	Embedded int64 `db:"embedded"`
}

// Stats returns row counts over the mailboxes, messages, and attachments
// tables, plus the count of messages carrying any embedding, in a single
// round trip. It is read-only.
//
// Governing: SPEC-0006 REQ "Thin Adapter Over the Store".
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	if s == nil || s.DB == nil {
		return Stats{}, errors.New("store: not open")
	}
	var st Stats
	// One query, four scalar subqueries: avoids round trips and keeps the
	// snapshot self-consistent within a single read transaction. `embedded`
	// joins messages→embeddings by stable hash (ADR-0014): a message counts
	// once regardless of how many model-specific vectors it has.
	const q = `SELECT
		(SELECT COUNT(*) FROM mailboxes)   AS mailboxes,
		(SELECT COUNT(*) FROM messages)    AS messages,
		(SELECT COUNT(*) FROM attachments) AS attachments,
		(SELECT COUNT(*) FROM messages msg
		   WHERE EXISTS (SELECT 1 FROM embeddings e WHERE e.hash = msg.hash)) AS embedded`
	if err := s.DB.GetContext(ctx, &st, q); err != nil {
		return Stats{}, fmt.Errorf("store: stats: %w", err)
	}
	return st, nil
}

// MailboxStat is a per-mailbox freshness/coverage row: how stale the cache is
// (LastSyncAt) and how complete the embedding index is (Embedded/Messages).
// It backs the `status` tool's per-mailbox breakdown so an agent can
// self-assess whether the cache is fresh and fully indexed before relying on
// semantic search. No secret fields (ADR-0013).
type MailboxStat struct {
	ID         string     `db:"id"`
	Address    string     `db:"address"`
	State      string     `db:"state"`
	LastSyncAt *time.Time `db:"last_sync_at"` // nil if never synced
	Messages   int64      `db:"messages"`
	Embedded   int64      `db:"embedded"`
}

// MailboxStats returns one MailboxStat per configured mailbox, ordered by
// address. `messages` counts cached messages for the mailbox; `embedded`
// counts those that have at least one embedding (any model), joined by stable
// hash. Both counts read 0 until sync and embed passes populate the cache,
// at which point they light up automatically. Read-only.
//
// Governing: SPEC-0006 REQ "Thin Adapter Over the Store", ADR-0015
//
//	(embeddings/vector backend), ADR-0014 (stable-hash keying).
func (s *Store) MailboxStats(ctx context.Context) ([]MailboxStat, error) {
	if s == nil || s.DB == nil {
		return nil, errors.New("store: not open")
	}
	const q = `SELECT
		m.id           AS id,
		m.address      AS address,
		m.state        AS state,
		m.last_sync_at AS last_sync_at,
		(SELECT COUNT(*) FROM messages msg WHERE msg.mailbox_id = m.id) AS messages,
		(SELECT COUNT(*) FROM messages msg
		   WHERE msg.mailbox_id = m.id
		     AND EXISTS (SELECT 1 FROM embeddings e WHERE e.hash = msg.hash)) AS embedded
		FROM mailboxes m
		ORDER BY m.address ASC`
	var rows []MailboxStat
	if err := s.DB.SelectContext(ctx, &rows, q); err != nil {
		return nil, fmt.Errorf("store: mailbox stats: %w", err)
	}
	return rows, nil
}

// SchemaVersion returns the current goose migration version: the highest
// applied version_id in the goose_db_version table that Migrate maintains.
// A return of 0 with a nil error means no migration has been applied yet
// (the version-tracking table exists but is empty, or only carries goose's
// initial version-0 sentinel row).
//
// Governing: ADR-0006 (SQLite + goose), SPEC-0006 REQ "Thin Adapter Over the
//
//	Store" (the `status` tool reports cache schema health via the store).
func (s *Store) SchemaVersion(ctx context.Context) (int64, error) {
	if s == nil || s.DB == nil {
		return 0, errors.New("store: not open")
	}
	// goose records each applied migration as a row; the live schema version
	// is the max version_id among applied rows. COALESCE guards the empty
	// table (no rows -> NULL). If the table itself is absent (Migrate never
	// ran), report version 0 rather than erroring so `status` can still
	// describe an un-migrated cache as unhealthy.
	var version int64
	const q = `SELECT COALESCE(MAX(version_id), 0) FROM goose_db_version WHERE is_applied = 1`
	if err := s.DB.GetContext(ctx, &version, q); err != nil {
		if isMissingTable(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("store: schema version: %w", err)
	}
	return version, nil
}

// isMissingTable reports whether err is SQLite's "no such table" error, which
// the modernc.org/sqlite driver surfaces as a plain error string (it does not
// wrap a typed sentinel). We match on the stable message fragment.
func isMissingTable(err error) bool {
	if err == nil || errors.Is(err, sql.ErrNoRows) {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such table")
}
