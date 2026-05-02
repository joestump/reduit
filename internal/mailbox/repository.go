// sqlx-backed CRUD for the mailbox / message / message_uids tables.
//
// Every method takes accountID as the first per-row argument and emits
// a `WHERE account_id = ?` clause. Per SPEC-0001 REQ "Account-Scoped
// Data" no per-account row is reachable without the owning account ID.
//
// Governing: SPEC-0001 REQ "Account-Scoped Data",
// SPEC-0003 REQ "UID Stability", SPEC-0003 REQ "Account Isolation in
// IMAP Operations".

package mailbox

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

// repository is the unexported persistence layer; callers go through
// Service.
type repository struct {
	db *sqlx.DB
}

// Mailbox is one row of the mailboxes table — the public projection
// the IMAP session uses.
type Mailbox struct {
	ID            int64     `db:"id"`
	AccountID     string    `db:"account_id"`
	Name          string    `db:"name"`
	ProtonLabelID string    `db:"proton_label_id"`
	Kind          Kind      `db:"kind"`
	UIDValidity   uint32    `db:"uid_validity"`
	UIDNext       uint32    `db:"uid_next"`
	CreatedAt     time.Time `db:"created_at"`
	UpdatedAt     time.Time `db:"updated_at"`
}

// Message is one row of the messages table.
type Message struct {
	ID              int64     `db:"id"`
	AccountID       string    `db:"account_id"`
	ProtonMessageID string    `db:"proton_message_id"`
	Subject         string    `db:"subject"`
	Sender          string    `db:"sender"`
	RFC822Size      int64     `db:"rfc822_size"`
	Flags           string    `db:"flags"`
	InternalDate    time.Time `db:"internal_date"`
	CreatedAt       time.Time `db:"created_at"`
}

// MessageInMailbox is the FETCH-shaped projection that joins
// message_uids → messages for a single mailbox.
type MessageInMailbox struct {
	UID             uint32    `db:"uid"`
	MessageID       int64     `db:"message_id"`
	ProtonMessageID string    `db:"proton_message_id"`
	Subject         string    `db:"subject"`
	Sender          string    `db:"sender"`
	RFC822Size      int64     `db:"rfc822_size"`
	Flags           string    `db:"flags"`
	InternalDate    time.Time `db:"internal_date"`
}

// getByName resolves a (account, name) pair to a Mailbox row. Returns
// ErrMailboxNotFound on a miss. The (account_id, name) UNIQUE index
// makes this an O(1) point lookup.
//
// Governing: SPEC-0003 REQ "Account Isolation in IMAP Operations" —
// the WHERE account_id clause is the structural enforcement.
func (r *repository) getByName(ctx context.Context, accountID, name string) (*Mailbox, error) {
	const q = `
SELECT id, account_id, name, proton_label_id, kind, uid_validity,
       uid_next, created_at, updated_at
FROM mailboxes
WHERE account_id = ? AND name = ?`
	var m Mailbox
	if err := r.db.GetContext(ctx, &m, q, accountID, name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrMailboxNotFound
		}
		return nil, fmt.Errorf("mailbox: get by name: %w", err)
	}
	return &m, nil
}

// listForAccount returns every mailbox owned by accountID, ordered by
// name ascending so the IMAP LIST output is stable across calls. Used
// by Session.List.
func (r *repository) listForAccount(ctx context.Context, accountID string) ([]*Mailbox, error) {
	const q = `
SELECT id, account_id, name, proton_label_id, kind, uid_validity,
       uid_next, created_at, updated_at
FROM mailboxes
WHERE account_id = ?
ORDER BY name ASC`
	var out []*Mailbox
	if err := r.db.SelectContext(ctx, &out, q, accountID); err != nil {
		return nil, fmt.Errorf("mailbox: list for account: %w", err)
	}
	return out, nil
}

// insertMailbox persists a new mailbox row and returns the auto-
// generated ID. Used inside EnsureMailbox; callers that want
// idempotent creation should go through Service.EnsureMailbox.
func (r *repository) insertMailbox(ctx context.Context, m *Mailbox, now time.Time) (int64, error) {
	const q = `
INSERT INTO mailboxes (
    account_id, name, proton_label_id, kind,
    uid_validity, uid_next, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, 1, ?, ?)`
	res, err := r.db.ExecContext(ctx, q,
		m.AccountID, m.Name, m.ProtonLabelID, string(m.Kind),
		m.UIDValidity, now, now)
	if err != nil {
		return 0, fmt.Errorf("mailbox: insert: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("mailbox: insert last id: %w", err)
	}
	return id, nil
}

// upsertMessage inserts a (account, proton_message_id) row if absent or
// returns the existing ID. Used by sync workers + tests; the IMAP
// session itself never inserts messages directly.
func (r *repository) upsertMessage(ctx context.Context, m *Message) (int64, error) {
	// SQLite's INSERT ... ON CONFLICT ... RETURNING lets us round-trip
	// the row's ID in one statement regardless of whether we inserted
	// or matched the conflict. The DO UPDATE clause is a no-op (we
	// touch only metadata that the sync worker should refresh in a
	// dedicated call); RETURNING is what we want.
	const q = `
INSERT INTO messages (
    account_id, proton_message_id, subject, sender,
    rfc822_size, flags, internal_date, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
ON CONFLICT(account_id, proton_message_id) DO UPDATE
    SET subject = excluded.subject
RETURNING id`
	var id int64
	if err := r.db.QueryRowxContext(ctx, q,
		m.AccountID, m.ProtonMessageID, m.Subject, m.Sender,
		m.RFC822Size, m.Flags, m.InternalDate,
	).Scan(&id); err != nil {
		return 0, fmt.Errorf("mailbox: upsert message: %w", err)
	}
	return id, nil
}

// assignUIDMaxRetries bounds the BEGIN IMMEDIATE retry loop. Under
// heavy concurrent write pressure (16+ goroutines vying for the write
// lock simultaneously) modernc.org/sqlite occasionally returns
// SQLITE_BUSY at BEGIN IMMEDIATE time even with the connection's
// busy_timeout pragma set, because the busy_timeout fires inside the
// C library on a single connection but BEGIN IMMEDIATE on a freshly-
// taken pool connection races at the OS file-lock layer. The retry
// loop with jittered backoff smooths the contention; in steady state
// (single writer) the first attempt always wins.
const (
	assignUIDMaxRetries = 32
	assignUIDBaseDelay  = 1 * time.Millisecond
	assignUIDMaxDelay   = 50 * time.Millisecond
)

// assignUID atomically claims the next UID for (mailbox, message).
//
// The transactional pattern mirrors account.repository.transitionState
// in spirit but commits to SQLite's BEGIN IMMEDIATE explicitly: we open
// a single Conn from the pool, issue `BEGIN IMMEDIATE TRANSACTION`, and
// run every statement on that Conn. BEGIN IMMEDIATE acquires the write
// lock at transaction start, so concurrent racers serialise at the
// write-lock layer instead of all observing a stale uid_next under
// DEFERRED locking and then racing the upgrade.
//
// Inside the tx we read uid_next, INSERT the message_uids row at that
// uid, then UPDATE uid_next = uid_next+1. The (mailbox_id, uid) UNIQUE
// index is belt-and-suspenders: if a second writer somehow beat the
// lock (a future SQLite version that breaks the IMMEDIATE semantics,
// say) the insert would fail and the tx would rollback.
//
// Returns ErrMessageNotFound if message_id does not resolve under
// accountID, ErrMailboxNotFound if the mailbox is missing, and
// ErrUIDExhausted on the (impossible-in-practice) uint32 overflow.
//
// Governing: SPEC-0003 REQ "UID Stability".
func (r *repository) assignUID(ctx context.Context, accountID string, mailboxID int64, messageID int64) (uint32, error) {
	// SQLITE_BUSY can fire on BEGIN IMMEDIATE when many goroutines
	// race for the write lock; the in-process retry loop unwinds the
	// transient contention. Each retry does NOT replay any state — the
	// helper opens a fresh Conn, runs the tx, and either commits or
	// rolls back atomically.
	var lastErr error
	for attempt := 0; attempt < assignUIDMaxRetries; attempt++ {
		uid, err := r.assignUIDOnce(ctx, accountID, mailboxID, messageID)
		if err == nil {
			return uid, nil
		}
		if !isSQLiteBusy(err) {
			return 0, err
		}
		lastErr = err
		// Jittered exponential backoff: the random component breaks
		// the lockstep that would otherwise have all retriers wake at
		// the same instant and race the lock again.
		delay := assignUIDBaseDelay << attempt
		if delay > assignUIDMaxDelay {
			delay = assignUIDMaxDelay
		}
		jitter := time.Duration(rand.Int64N(int64(delay)))
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(delay/2 + jitter):
		}
	}
	return 0, fmt.Errorf("mailbox: assignUID exhausted retries: %w", lastErr)
}

// isSQLiteBusy reports whether err looks like a SQLITE_BUSY return.
// modernc.org/sqlite surfaces the error as a typed sqlite.Error in
// most cases but the BEGIN IMMEDIATE path can also surface a plain
// errors.New wrapped in our own context. We sniff both.
func isSQLiteBusy(err error) bool {
	if err == nil {
		return false
	}
	// Cheap substring check covering both the typed error message form
	// ("database is locked (5) (SQLITE_BUSY)") and any future driver
	// rewording that still includes the canonical error name.
	s := err.Error()
	return strings.Contains(s, "SQLITE_BUSY") || strings.Contains(s, "database is locked")
}

func (r *repository) assignUIDOnce(ctx context.Context, accountID string, mailboxID int64, messageID int64) (uint32, error) {
	// Pull a single Conn out of the pool for the entire tx. We CANNOT
	// use sqlx.DB.BeginTxx because that begins in DEFERRED mode under
	// modernc.org/sqlite (it does not honour driver.TxOptions for the
	// lock mode). Running BEGIN IMMEDIATE manually on a dedicated Conn
	// gives us the write-lock-from-the-start semantics we want.
	conn, err := r.db.Connx(ctx)
	if err != nil {
		return 0, fmt.Errorf("mailbox: assignUID get conn: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE TRANSACTION"); err != nil {
		return 0, fmt.Errorf("mailbox: assignUID begin immediate: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if _, rbErr := conn.ExecContext(ctx, "ROLLBACK"); rbErr != nil {
			// Driver returns "no transaction is active" if a successful
			// COMMIT already ran — benign, suppress.
			if !errors.Is(rbErr, sql.ErrTxDone) {
				slog.Default().LogAttrs(ctx, slog.LevelWarn,
					"mailbox: assignUID rollback failed",
					slog.String("account_id", accountID),
					slog.Int64("mailbox_id", mailboxID),
					slog.Int64("message_id", messageID),
					slog.Any("err", rbErr),
				)
			}
		}
	}()

	// Confirm the mailbox exists under this account. This is the
	// account-scoping enforcement at this layer (callers should also
	// scope their lookups but the repository is the last line of
	// defence).
	var current uint32
	if err := conn.GetContext(ctx, &current,
		`SELECT uid_next FROM mailboxes WHERE id = ? AND account_id = ?`,
		mailboxID, accountID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrMailboxNotFound
		}
		return 0, fmt.Errorf("mailbox: assignUID read uid_next: %w", err)
	}

	// uint32 overflow guard. uid_next holds the NEXT uid to issue, so
	// the maximum representable issued uid is math.MaxUint32 (0xFFFFFFFF).
	// Once uid_next reaches that value, claiming it is fine but advancing
	// past it would wrap to zero, which would then re-issue UID 0
	// (invalid) on the next call. Refuse to claim the last UID.
	if current == 0 || current == 0xFFFFFFFF {
		return 0, ErrUIDExhausted
	}

	// Verify the message belongs to this account before linking it.
	// Cheap point query; the (account_id, proton_message_id) index makes
	// it O(1).
	var ownerOK int
	if err := conn.GetContext(ctx, &ownerOK,
		`SELECT 1 FROM messages WHERE id = ? AND account_id = ?`,
		messageID, accountID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrMessageNotFound
		}
		return 0, fmt.Errorf("mailbox: assignUID verify message: %w", err)
	}

	const insertQ = `
INSERT INTO message_uids (account_id, mailbox_id, message_id, uid, created_at)
VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`
	if _, err := conn.ExecContext(ctx, insertQ, accountID, mailboxID, messageID, current); err != nil {
		return 0, fmt.Errorf("mailbox: assignUID insert: %w", err)
	}

	const updateQ = `
UPDATE mailboxes SET uid_next = uid_next + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND account_id = ? AND uid_next = ?`
	res, err := conn.ExecContext(ctx, updateQ, mailboxID, accountID, current)
	if err != nil {
		return 0, fmt.Errorf("mailbox: assignUID bump uid_next: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("mailbox: assignUID rows affected: %w", err)
	}
	if n != 1 {
		// Belt-and-suspenders: the BEGIN IMMEDIATE serialization
		// already prevents this branch from firing, but if a future
		// driver weakens it the conditional WHERE clause will refuse
		// the bump and we surface a typed error instead of corrupting
		// the counter.
		return 0, fmt.Errorf("mailbox: assignUID raced on uid_next (got 0 rows updated)")
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return 0, fmt.Errorf("mailbox: assignUID commit: %w", err)
	}
	committed = true
	return current, nil
}

// removeMessageFromMailbox deletes the message_uids row for
// (mailbox, message). Returns true if a row was actually removed.
// The corresponding message row in `messages` is intentionally NOT
// deleted — the same Proton message may live in another mailbox via
// the additive label model.
func (r *repository) removeMessageFromMailbox(ctx context.Context, accountID string, mailboxID, messageID int64) (bool, error) {
	const q = `
DELETE FROM message_uids
WHERE account_id = ? AND mailbox_id = ? AND message_id = ?`
	res, err := r.db.ExecContext(ctx, q, accountID, mailboxID, messageID)
	if err != nil {
		return false, fmt.Errorf("mailbox: remove message: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("mailbox: remove message rows: %w", err)
	}
	return n > 0, nil
}

// findMessageByProtonID returns the message row for (account, proton id).
// Used by Session.Move to translate a Proton message ID coming back from
// the Proton API into a local message ID.
func (r *repository) findMessageByProtonID(ctx context.Context, accountID, protonID string) (*Message, error) {
	const q = `
SELECT id, account_id, proton_message_id, subject, sender, rfc822_size,
       flags, internal_date, created_at
FROM messages
WHERE account_id = ? AND proton_message_id = ?`
	var m Message
	if err := r.db.GetContext(ctx, &m, q, accountID, protonID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrMessageNotFound
		}
		return nil, fmt.Errorf("mailbox: find message: %w", err)
	}
	return &m, nil
}

// listMessagesInMailbox returns every (uid, message) pair for the given
// mailbox, ordered by UID ascending so seqnum assignment is stable.
// Used by Session.Fetch / Session.Status (NumMessages).
func (r *repository) listMessagesInMailbox(ctx context.Context, accountID string, mailboxID int64) ([]*MessageInMailbox, error) {
	const q = `
SELECT mu.uid, mu.message_id, m.proton_message_id, m.subject, m.sender,
       m.rfc822_size, m.flags, m.internal_date
FROM message_uids mu
JOIN messages m ON m.id = mu.message_id
WHERE mu.account_id = ? AND mu.mailbox_id = ?
ORDER BY mu.uid ASC`
	var out []*MessageInMailbox
	if err := r.db.SelectContext(ctx, &out, q, accountID, mailboxID); err != nil {
		return nil, fmt.Errorf("mailbox: list messages in mailbox: %w", err)
	}
	return out, nil
}

// countMessagesInMailbox returns the number of message_uids rows for
// the mailbox. Used by Session.Status (NumMessages).
func (r *repository) countMessagesInMailbox(ctx context.Context, accountID string, mailboxID int64) (uint32, error) {
	const q = `
SELECT COUNT(*) FROM message_uids
WHERE account_id = ? AND mailbox_id = ?`
	var n uint32
	if err := r.db.GetContext(ctx, &n, q, accountID, mailboxID); err != nil {
		return 0, fmt.Errorf("mailbox: count messages: %w", err)
	}
	return n, nil
}
