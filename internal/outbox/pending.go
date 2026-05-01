// PendingStore persists rows for submissions whose synchronous
// timeout fired but whose background retry continued. The table gives
// the operator a single place to audit timeout-detached sends from the
// admin UI; richer retry policy (exponential backoff, dead-letter)
// lands in #23.
//
// Two implementations:
//
//   - SQLitePendingStore is the production wiring against the
//     `outbox_pending` table created by migration
//     20260502000003_outbox.sql.
//   - DiscardPendingStore is the test default; it logs nothing and
//     returns nil.
//
// Governing: SPEC-0004 REQ "Outbox Handoff and Synchronous Confirmation".

package outbox

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// PendingStore is the persistence interface the worker uses to record
// a timeout-detached submission. Methods are nil-safe: the
// implementation is expected to swallow context-cancelled errors so
// shutdown does not pollute logs.
type PendingStore interface {
	// RecordTimeout writes a row indicating the synchronous send
	// returned 451 to the SMTP client and the upstream call eventually
	// failed (cause).
	RecordTimeout(ctx context.Context, sub Submission, cause error) error

	// RecordTimeoutResolved writes a row indicating the synchronous
	// send returned 451 to the SMTP client BUT the upstream call
	// eventually succeeded. The operator's audit needs to distinguish
	// "client thinks it failed, message was actually sent" from
	// "client thinks it failed and we retried".
	RecordTimeoutResolved(ctx context.Context, sub Submission) error
}

// DiscardPendingStore is a PendingStore that drops every record.
// Test default.
var DiscardPendingStore PendingStore = discardPendingStore{}

type discardPendingStore struct{}

func (discardPendingStore) RecordTimeout(_ context.Context, _ Submission, _ error) error {
	return nil
}

func (discardPendingStore) RecordTimeoutResolved(_ context.Context, _ Submission) error {
	return nil
}

// SQLitePendingStore is the production PendingStore implementation
// backed by the `outbox_pending` table. The schema lives in migration
// 20260502000003_outbox.sql.
type SQLitePendingStore struct {
	DB *sqlx.DB
}

// NewSQLitePendingStore constructs a SQLitePendingStore backed by the
// supplied sqlx.DB.
func NewSQLitePendingStore(db *sqlx.DB) *SQLitePendingStore {
	return &SQLitePendingStore{DB: db}
}

// RecordTimeout writes a row with status=timeout_failed.
func (s *SQLitePendingStore) RecordTimeout(ctx context.Context, sub Submission, cause error) error {
	if s == nil || s.DB == nil {
		return errors.New("outbox: SQLitePendingStore not initialised")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `
		INSERT INTO outbox_pending(id, account_id, mail_from, recipient_count, body_bytes, status, failure_reason, created_at)
		VALUES (?, ?, ?, ?, ?, 'timeout_failed', ?, ?)
	`,
		id.String(), sub.AccountID, sub.MailFrom, len(sub.Recipients), len(sub.Body),
		errString(cause), time.Now().UTC(),
	)
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, sql.ErrConnDone) {
		return err
	}
	return nil
}

// RecordTimeoutResolved writes a row with status=timeout_resolved.
func (s *SQLitePendingStore) RecordTimeoutResolved(ctx context.Context, sub Submission) error {
	if s == nil || s.DB == nil {
		return errors.New("outbox: SQLitePendingStore not initialised")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `
		INSERT INTO outbox_pending(id, account_id, mail_from, recipient_count, body_bytes, status, failure_reason, created_at)
		VALUES (?, ?, ?, ?, ?, 'timeout_resolved', NULL, ?)
	`,
		id.String(), sub.AccountID, sub.MailFrom, len(sub.Recipients), len(sub.Body),
		time.Now().UTC(),
	)
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, sql.ErrConnDone) {
		return err
	}
	return nil
}
