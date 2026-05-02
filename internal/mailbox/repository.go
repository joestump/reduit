// sqlx-backed CRUD for the mailbox / message / message_uids tables.
//
// Every method takes accountID as the first per-row argument and emits
// a `WHERE account_id = ?` clause. Per SPEC-0001 REQ "Account-Scoped
// Data" no per-account row is reachable without the owning account ID.
//
// Reads use the multi-conn pool (`reads`); writes go through the
// single-conn writer pool (`writes`). The single-conn writer pool is
// the structural answer to the SQLITE_BUSY contention the previous
// retry loop tried to paper over: WAL mode permits exactly one writer
// at a time, so capping MaxOpenConns at 1 makes contention queue at
// the database/sql layer instead of fanning out to driver-level retries.
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
	"time"

	"github.com/jmoiron/sqlx"
)

// repository is the unexported persistence layer; callers go through
// Service.
//
// `reads` is the multi-conn pool used for SELECTs (WAL gives them
// concurrency). `writes` is the single-conn pool that serialises
// transactional writers — assignUID is the canonical hot path. Every
// write that participates in the assignUID-style atomic "read uid_next,
// claim it, bump it" pattern MUST run against `writes` so it queues at
// the connection layer instead of racing the file lock.
type repository struct {
	reads  *sqlx.DB
	writes *sqlx.DB
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
	if err := r.reads.GetContext(ctx, &m, q, accountID, name); err != nil {
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
	if err := r.reads.SelectContext(ctx, &out, q, accountID); err != nil {
		return nil, fmt.Errorf("mailbox: list for account: %w", err)
	}
	return out, nil
}

// insertMailbox persists a new mailbox row and returns the auto-
// generated ID. Used inside EnsureMailbox; callers that want
// idempotent creation should go through Service.EnsureMailbox.
//
// Goes through the writer pool so concurrent EnsureMailbox calls for
// the same (account, name) serialise at the connection layer; the
// (account_id, name) UNIQUE index then forces all but one to receive
// the SQLITE_CONSTRAINT_UNIQUE error EnsureMailbox handles.
func (r *repository) insertMailbox(ctx context.Context, m *Mailbox, now time.Time) (int64, error) {
	const q = `
INSERT INTO mailboxes (
    account_id, name, proton_label_id, kind,
    uid_validity, uid_next, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, 1, ?, ?)`
	res, err := r.writes.ExecContext(ctx, q,
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
//
// Writes go through the writer pool to share the BEGIN-IMMEDIATE
// serialisation lane with assignUID — under heavy seed contention
// (TestAssignUIDIsMonotonicUnderRace seeds 3200 messages then runs
// 3200 concurrent UID claims) routing both through one connection
// removes the cross-statement file-lock race.
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
	if err := r.writes.QueryRowxContext(ctx, q,
		m.AccountID, m.ProtonMessageID, m.Subject, m.Sender,
		m.RFC822Size, m.Flags, m.InternalDate,
	).Scan(&id); err != nil {
		return 0, fmt.Errorf("mailbox: upsert message: %w", err)
	}
	return id, nil
}

// assignUID atomically claims the next UID for (mailbox, message).
//
// The transactional shape: one BeginTxx on the writer pool (which is
// pinned to a single connection so concurrent callers serialise at the
// database/sql layer), read uid_next, INSERT the message_uids row at
// that uid, UPDATE uid_next = uid_next+1. The (mailbox_id, uid) UNIQUE
// index is belt-and-suspenders against any future driver weakening of
// the single-conn invariant.
//
// The previous implementation used BEGIN IMMEDIATE on a fresh pool
// connection and a 32-attempt jittered retry to absorb the SQLITE_BUSY
// returns that fired when many goroutines raced for the file lock.
// That contention is eliminated here: the writer pool's connection cap
// of 1 forces every transactional writer to queue at Go's pool layer
// before the driver ever sees a BEGIN. Worst case is sleep-on-mutex,
// not exponential backoff with eventual exhaustion.
//
// Returns ErrMessageNotFound if message_id does not resolve under
// accountID, ErrMailboxNotFound if the mailbox is missing, and
// ErrUIDExhausted on the (impossible-in-practice) uint32 overflow.
//
// Governing: SPEC-0003 REQ "UID Stability".
//
// TODO(follow-up): migrate account writes to the writer pool for
// consistency. The account.repository.transitionState path runs rarely
// (state transitions, not per-message writes), so the BEGIN IMMEDIATE
// + lock-grab pattern there is not contended enough to need this
// treatment today; a follow-up issue should align both packages.
func (r *repository) assignUID(ctx context.Context, accountID string, mailboxID int64, messageID int64) (uint32, error) {
	tx, err := r.writes.BeginTxx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("mailbox: assignUID begin: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			slog.Default().LogAttrs(ctx, slog.LevelWarn,
				"mailbox: assignUID rollback failed",
				slog.String("account_id", accountID),
				slog.Int64("mailbox_id", mailboxID),
				slog.Int64("message_id", messageID),
				slog.Any("err", rbErr),
			)
		}
	}()

	// Confirm the mailbox exists under this account. This is the
	// account-scoping enforcement at this layer (callers should also
	// scope their lookups but the repository is the last line of
	// defence).
	var current uint32
	if err := tx.GetContext(ctx, &current,
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
	if err := tx.GetContext(ctx, &ownerOK,
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
	if _, err := tx.ExecContext(ctx, insertQ, accountID, mailboxID, messageID, current); err != nil {
		return 0, fmt.Errorf("mailbox: assignUID insert: %w", err)
	}

	const updateQ = `
UPDATE mailboxes SET uid_next = uid_next + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND account_id = ? AND uid_next = ?`
	res, err := tx.ExecContext(ctx, updateQ, mailboxID, accountID, current)
	if err != nil {
		return 0, fmt.Errorf("mailbox: assignUID bump uid_next: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("mailbox: assignUID rows affected: %w", err)
	}
	if n != 1 {
		// Belt-and-suspenders: the single-conn writer pool already
		// prevents this branch from firing, but if a future caller
		// accidentally points the repository at the multi-conn pool
		// the conditional WHERE clause will refuse the bump and we
		// surface a typed error instead of corrupting the counter.
		return 0, fmt.Errorf("mailbox: assignUID raced on uid_next (got 0 rows updated)")
	}
	if err := tx.Commit(); err != nil {
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
	res, err := r.writes.ExecContext(ctx, q, accountID, mailboxID, messageID)
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
	if err := r.reads.GetContext(ctx, &m, q, accountID, protonID); err != nil {
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
	if err := r.reads.SelectContext(ctx, &out, q, accountID, mailboxID); err != nil {
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
	if err := r.reads.GetContext(ctx, &n, q, accountID, mailboxID); err != nil {
		return 0, fmt.Errorf("mailbox: count messages: %w", err)
	}
	return n, nil
}
