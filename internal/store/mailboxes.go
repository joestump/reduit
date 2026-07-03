// Package store — mailbox persistence methods.
//
// Governing: SPEC-0001 REQ "Mailbox Identity", SPEC-0001 REQ "Multi-Mailbox",
//
//	ADR-0006 (SQLite cache), ADR-0012 (single-user local-first),
//	ADR-0013 (secrets in OS keychain — no secret columns here).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// MailboxState is the lifecycle state of a configured Proton mailbox.
type MailboxState string

const (
	MailboxStatePendingAuth MailboxState = "pending_auth"
	MailboxStateActive      MailboxState = "active"
	MailboxStateNeedsReauth MailboxState = "needs_reauth"
)

// Mailbox is a row from the mailboxes table.
//
// No secret fields — refresh_token and mailbox_passphrase live in the OS
// keychain, keyed by mailbox/<id>/{refresh_token,mailbox_passphrase}.
//
// Governing: ADR-0013 (secrets in OS keychain), SPEC-0001 REQ "Mailbox Identity".
type Mailbox struct {
	ID           string       `db:"id"`
	ProtonUserID *string      `db:"proton_user_id"` // nil until first successful auth
	Address      string       `db:"address"`
	State        MailboxState `db:"state"`
	AddedAt      time.Time    `db:"added_at"`
	LastSyncAt   *time.Time   `db:"last_sync_at"` // nil if never synced
	// SessionUID is the go-proton-api session UID captured at Login. Proton's
	// refresh endpoint requires it to identify the session; resuming without it
	// yields 10013 "Invalid refresh token". It is non-secret session state, so
	// it lives here rather than the keychain (ADR-0013). nil for pre-migration
	// rows and until the first successful auth.
	SessionUID *string `db:"session_uid"`
}

// ErrMailboxNotFound is returned when a mailbox row is not found.
var ErrMailboxNotFound = errors.New("store: mailbox not found")

// ErrProtonUserIDConflict is returned when an auth would overwrite an existing
// proton_user_id — a hard error per SPEC-0001 REQ "Mailbox Identity".
var ErrProtonUserIDConflict = errors.New("store: proton_user_id mismatch — refusing to overwrite")

// InsertMailbox inserts a new mailbox row with state=pending_auth and no
// proton_user_id yet.
//
// Governing: SPEC-0001 REQ "Mailbox Identity" scenario "Mailbox row created with a UUIDv7 id".
func (s *Store) InsertMailbox(ctx context.Context, id, address string) error {
	const q = `INSERT INTO mailboxes (id, address, state) VALUES (?, ?, 'pending_auth')`
	_, err := s.DB.ExecContext(ctx, q, id, address)
	if err != nil {
		return fmt.Errorf("store: insert mailbox: %w", err)
	}
	return nil
}

// GetMailbox returns the mailbox row for the given id.
func (s *Store) GetMailbox(ctx context.Context, id string) (Mailbox, error) {
	var m Mailbox
	const q = `SELECT id, proton_user_id, address, state, added_at, last_sync_at, session_uid FROM mailboxes WHERE id = ?`
	if err := s.DB.GetContext(ctx, &m, q, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Mailbox{}, ErrMailboxNotFound
		}
		return Mailbox{}, fmt.Errorf("store: get mailbox: %w", err)
	}
	return m, nil
}

// GetMailboxByAddress returns the mailbox row for the given Proton address.
func (s *Store) GetMailboxByAddress(ctx context.Context, address string) (Mailbox, error) {
	var m Mailbox
	const q = `SELECT id, proton_user_id, address, state, added_at, last_sync_at, session_uid FROM mailboxes WHERE address = ?`
	if err := s.DB.GetContext(ctx, &m, q, address); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Mailbox{}, ErrMailboxNotFound
		}
		return Mailbox{}, fmt.Errorf("store: get mailbox by address: %w", err)
	}
	return m, nil
}

// ListMailboxes returns all configured mailboxes.
func (s *Store) ListMailboxes(ctx context.Context) ([]Mailbox, error) {
	var rows []Mailbox
	const q = `SELECT id, proton_user_id, address, state, added_at, last_sync_at, session_uid FROM mailboxes ORDER BY added_at ASC`
	if err := s.DB.SelectContext(ctx, &rows, q); err != nil {
		return nil, fmt.Errorf("store: list mailboxes: %w", err)
	}
	return rows, nil
}

// SetProtonUserID records the proton_user_id on first successful auth and
// transitions the mailbox to active. If proton_user_id is already set and
// does not match, returns ErrProtonUserIDConflict without modifying the row.
//
// Governing: SPEC-0001 REQ "proton_user_id recorded on first successful auth",
//
//	SPEC-0001 REQ "proton_user_id is immutable after it is set".
func (s *Store) SetProtonUserID(ctx context.Context, id, protonUserID string) error {
	m, err := s.GetMailbox(ctx, id)
	if err != nil {
		return err
	}
	if m.ProtonUserID != nil && *m.ProtonUserID != protonUserID {
		return fmt.Errorf("%w: stored=%q incoming=%q", ErrProtonUserIDConflict, *m.ProtonUserID, protonUserID)
	}
	if m.ProtonUserID != nil {
		// Already set and matches — just ensure state is active.
		return s.SetMailboxState(ctx, id, MailboxStateActive)
	}
	const q = `UPDATE mailboxes SET proton_user_id = ?, state = 'active' WHERE id = ?`
	if _, err := s.DB.ExecContext(ctx, q, protonUserID, id); err != nil {
		return fmt.Errorf("store: set proton_user_id: %w", err)
	}
	return nil
}

// SetSessionUID records the go-proton-api session UID on the mailbox row. It is
// written on first auth (alongside proton_user_id and the keychain secrets) and
// rewritten whenever a resume rotates the UID, so the next cross-process resume
// can identify the session (without it Proton's refresh returns 10013). The UID
// is non-secret session state, so it lives in the store, not the keychain
// (ADR-0013). Governing: SPEC-0007 "Re-Auth Flow", "Secrets read
// non-interactively at use time".
func (s *Store) SetSessionUID(ctx context.Context, id, uid string) error {
	const q = `UPDATE mailboxes SET session_uid = ? WHERE id = ?`
	res, err := s.DB.ExecContext(ctx, q, uid, id)
	if err != nil {
		return fmt.Errorf("store: set session_uid: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrMailboxNotFound
	}
	return nil
}

// SetMailboxState updates the lifecycle state of a mailbox.
func (s *Store) SetMailboxState(ctx context.Context, id string, state MailboxState) error {
	const q = `UPDATE mailboxes SET state = ? WHERE id = ?`
	res, err := s.DB.ExecContext(ctx, q, string(state), id)
	if err != nil {
		return fmt.Errorf("store: set mailbox state: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrMailboxNotFound
	}
	return nil
}

// SetLastSyncAt records the time of a successful sync completion.
func (s *Store) SetLastSyncAt(ctx context.Context, id string, t time.Time) error {
	const q = `UPDATE mailboxes SET last_sync_at = ? WHERE id = ?`
	_, err := s.DB.ExecContext(ctx, q, t, id)
	if err != nil {
		return fmt.Errorf("store: set last_sync_at: %w", err)
	}
	return nil
}

// DeleteMailbox removes a mailbox row and EVERY row that references it — the
// message cache (and the messages' hash-keyed children: links, attachments,
// embeddings), sync_runs, sync_state, fact_state, and mailbox-scoped denylist
// entries — in one transaction, so `auth remove` can never trip the FOREIGN KEY
// constraint (observed live: a recorded sync_run blocked the delete) and never
// leaves orphaned cache rows behind. Contacts are retained: they are shared
// across mailboxes and are not FK'd to this row. contact_facts are keyed by
// contact, not mailbox, and are likewise retained (the facts layer owns their
// lifecycle, SPEC-0011).
func (s *Store) DeleteMailbox(ctx context.Context, id string) error {
	if s == nil || s.WriterDB() == nil {
		return errNotOpen
	}
	tx, err := s.WriterDB().BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: delete mailbox: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// The messages' hash-keyed children first (no FK, but orphaning them would
	// leave dangling search/embedding rows pointing at deleted messages).
	for _, q := range []struct{ name, sql string }{
		{"links", `DELETE FROM links WHERE message_hash IN (SELECT hash FROM messages WHERE mailbox_id = ?)`},
		{"attachments", `DELETE FROM attachments WHERE message_hash IN (SELECT hash FROM messages WHERE mailbox_id = ?)`},
		{"embeddings", `DELETE FROM embeddings WHERE hash IN (SELECT hash FROM messages WHERE mailbox_id = ?)`},
		// messages last of the hash family (the subqueries above need them);
		// the messages_ad trigger clears messages_fts.
		{"messages", `DELETE FROM messages WHERE mailbox_id = ?`},
		// Direct mailbox_id dependents.
		{"sync_runs", `DELETE FROM sync_runs WHERE mailbox_id = ?`},
		{"sync_state", `DELETE FROM sync_state WHERE mailbox_id = ?`},
		{"fact_state", `DELETE FROM fact_state WHERE mailbox_id = ?`},
		{"denylist", `DELETE FROM denylist WHERE mailbox_id = ?`},
		{"mailbox", `DELETE FROM mailboxes WHERE id = ?`},
	} {
		if _, err := tx.ExecContext(ctx, q.sql, id); err != nil {
			return fmt.Errorf("store: delete mailbox: %s: %w", q.name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: delete mailbox: commit: %w", err)
	}
	return nil
}
