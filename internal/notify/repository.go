// Repository persistence for admin notifications.
//
// Governing: ADR-0006 (SQLite + sqlx), SPEC-0002 REQ "Panic Isolation",
// SPEC-0001 REQ "Account-Scoped Data".
package notify

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

// repository is the sqlx-backed CRUD layer for admin_notifications. It
// is unexported; callers go through Service.
type repository struct {
	db *sqlx.DB
}

// notificationRow mirrors the on-disk schema. Detail and AcknowledgedAt
// are nullable.
type notificationRow struct {
	ID             string         `db:"id"`
	AccountID      string         `db:"account_id"`
	Kind           string         `db:"kind"`
	Message        string         `db:"message"`
	Detail         sql.NullString `db:"detail"`
	CreatedAt      time.Time      `db:"created_at"`
	AcknowledgedAt sql.NullTime   `db:"acknowledged_at"`
}

func (r notificationRow) toNotification() *Notification {
	n := &Notification{
		ID:        r.ID,
		AccountID: r.AccountID,
		Kind:      Kind(r.Kind),
		Message:   r.Message,
		Detail:    r.Detail.String,
		CreatedAt: r.CreatedAt,
	}
	if r.AcknowledgedAt.Valid {
		t := r.AcknowledgedAt.Time
		n.AcknowledgedAt = &t
	}
	return n
}

func (r *repository) insert(ctx context.Context, n *Notification) error {
	const q = `
INSERT INTO admin_notifications (id, account_id, kind, message, detail, created_at)
VALUES (:id, :account_id, :kind, :message, :detail, :created_at)`
	row := notificationRow{
		ID:        n.ID,
		AccountID: n.AccountID,
		Kind:      string(n.Kind),
		Message:   n.Message,
		CreatedAt: n.CreatedAt,
	}
	if n.Detail != "" {
		row.Detail = sql.NullString{String: n.Detail, Valid: true}
	}
	if _, err := r.db.NamedExecContext(ctx, q, row); err != nil {
		return fmt.Errorf("notify: insert: %w", err)
	}
	return nil
}

func (r *repository) listUnacknowledged(ctx context.Context, limit int) ([]*Notification, error) {
	const q = `
SELECT id, account_id, kind, message, detail, created_at, acknowledged_at
FROM admin_notifications
WHERE acknowledged_at IS NULL
ORDER BY created_at DESC, id DESC
LIMIT ?`
	var rows []notificationRow
	if err := r.db.SelectContext(ctx, &rows, q, limit); err != nil {
		return nil, fmt.Errorf("notify: list unacknowledged: %w", err)
	}
	out := make([]*Notification, len(rows))
	for i, row := range rows {
		out[i] = row.toNotification()
	}
	return out, nil
}

func (r *repository) countUnacknowledged(ctx context.Context) (int, error) {
	const q = `SELECT COUNT(*) FROM admin_notifications WHERE acknowledged_at IS NULL`
	var n int
	if err := r.db.GetContext(ctx, &n, q); err != nil {
		return 0, fmt.Errorf("notify: count unacknowledged: %w", err)
	}
	return n, nil
}

// acknowledge stamps acknowledged_at on the row. Idempotent: the WHERE
// clause restricts to still-unacknowledged rows, so re-acknowledging an
// already-dismissed notification affects zero rows but is NOT an error.
// A zero-row result for an id that does not exist at all surfaces as
// ErrNotFound; we distinguish the two with a follow-up existence check
// only when the UPDATE touched nothing.
func (r *repository) acknowledge(ctx context.Context, id string, now time.Time) error {
	const q = `UPDATE admin_notifications SET acknowledged_at = ? WHERE id = ? AND acknowledged_at IS NULL`
	res, err := r.db.ExecContext(ctx, q, now, id)
	if err != nil {
		return fmt.Errorf("notify: acknowledge: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("notify: acknowledge rows affected: %w", err)
	}
	if n > 0 {
		return nil
	}
	// Zero rows: either the row does not exist, or it was already
	// acknowledged. Disambiguate so a double-dismiss is a no-op while a
	// bogus id is a clean ErrNotFound.
	const existsQ = `SELECT 1 FROM admin_notifications WHERE id = ?`
	var one int
	if err := r.db.GetContext(ctx, &one, existsQ, id); err != nil {
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		return fmt.Errorf("notify: acknowledge existence check: %w", err)
	}
	return nil
}
