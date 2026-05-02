// PendingStore persists best-effort audit rows for submissions whose
// synchronous timeout fired (Reduit returned 451 4.4.7 to the SMTP
// client). The table gives the operator a single place to audit
// timed-out sends from the admin UI. Reduit does NOT run a server-side
// retry loop after a timeout — recovery is the sender's MTA re-
// attempting the SMTP submission per RFC 5321.
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
// a timeout-abandoned submission. Methods are nil-safe: the
// implementation is expected to swallow context-cancelled errors so
// shutdown does not pollute logs.
//
// As of the Blocker-2 fix in this story, Reduit does NOT run a
// Reduit-side retry loop after a synchronous timeout. The sender's MTA
// retries the SMTP submission per RFC 5321; this table is purely an
// operator-visible audit trail of "Reduit returned 451 to the client
// because the upstream call did not complete in time".
type PendingStore interface {
	// RecordTimeout writes a row indicating the synchronous send
	// returned 451 to the SMTP client because the configured
	// SubmitTimeout elapsed before the upstream call returned. cause
	// is the timeout error (typically ErrSubmissionTimedOut).
	RecordTimeout(ctx context.Context, sub Submission, cause error) error
}

// DiscardPendingStore is a PendingStore that drops every record.
// Test default.
var DiscardPendingStore PendingStore = discardPendingStore{}

type discardPendingStore struct{}

func (discardPendingStore) RecordTimeout(_ context.Context, _ Submission, _ error) error {
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

// RecordTimeout writes a row with status=timeout_failed for an
// audit-visible record of "Reduit returned 451 4.4.7 to the SMTP
// client because the upstream call did not complete in time".
func (s *SQLitePendingStore) RecordTimeout(ctx context.Context, sub Submission, cause error) error {
	if s == nil || s.DB == nil {
		return errors.New("outbox: SQLitePendingStore not initialised")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	reason := ""
	if cause != nil {
		reason = cause.Error()
	}
	_, err = s.DB.ExecContext(ctx, `
		INSERT INTO outbox_pending(id, account_id, mail_from, recipient_count, body_bytes, status, failure_reason, created_at)
		VALUES (?, ?, ?, ?, ?, 'timeout_failed', ?, ?)
	`,
		id.String(), sub.AccountID, sub.MailFrom, len(sub.Recipients), len(sub.Body),
		reason, time.Now().UTC(),
	)
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, sql.ErrConnDone) {
		return err
	}
	return nil
}
