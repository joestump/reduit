// Repository persistence for accounts.
//
// Governing: ADR-0002 (multi-tenant), ADR-0006 (SQLite + sqlx),
// SPEC-0001 REQ "Account Identity", SPEC-0001 REQ "Per-Account Data Key".
package account

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// repository is the sqlx-backed CRUD layer for the accounts table. It
// is unexported because callers should go through Service, which
// layers crypto and state-machine validation on top.
type repository struct {
	db *sqlx.DB
}

// accountRow mirrors the on-disk schema (including the ciphertext
// columns the public Account struct intentionally hides). The Service
// converts between the two — repository methods that need ciphertext
// access return *accountRow; everything else returns *Account.
type accountRow struct {
	ID                          string         `db:"id"`
	OIDCSubject                 string         `db:"oidc_subject"`
	ProtonUserID                sql.NullString `db:"proton_user_id"`
	Email                       sql.NullString `db:"email"`
	State                       string         `db:"state"`
	IsAdmin                     int64          `db:"is_admin"`
	KeyEnvelope                 []byte         `db:"key_envelope"`
	RefreshTokenCiphertext      []byte         `db:"refresh_token_ciphertext"`
	MailboxPassphraseCiphertext []byte         `db:"mailbox_passphrase_ciphertext"`
	IMAPPasswordCiphertext      []byte         `db:"imap_password_ciphertext"`
	IMAPPasswordHash            sql.NullString `db:"imap_password_hash"`
	LastEventID                 sql.NullString `db:"last_event_id"`
	Crashed                     int64          `db:"crashed"`
	CreatedAt                   time.Time      `db:"created_at"`
	UpdatedAt                   time.Time      `db:"updated_at"`
	DeletedAt                   sql.NullTime   `db:"deleted_at"`
}

func (r accountRow) toAccount() *Account {
	a := &Account{
		ID:                   r.ID,
		OIDCSubject:          r.OIDCSubject,
		ProtonUserID:         r.ProtonUserID.String,
		Email:                r.Email.String,
		State:                State(r.State),
		IsAdmin:              r.IsAdmin != 0,
		KeyEnvelope:          append([]byte(nil), r.KeyEnvelope...),
		HasRefreshToken:      len(r.RefreshTokenCiphertext) > 0,
		HasMailboxPassphrase: len(r.MailboxPassphraseCiphertext) > 0,
		HasIMAPPassword:      len(r.IMAPPasswordCiphertext) > 0,
		IMAPPasswordHash:     r.IMAPPasswordHash.String,
		LastEventID:          r.LastEventID.String,
		Crashed:              r.Crashed != 0,
		CreatedAt:            r.CreatedAt,
		UpdatedAt:            r.UpdatedAt,
	}
	if r.DeletedAt.Valid {
		t := r.DeletedAt.Time
		a.DeletedAt = &t
	}
	return a
}

const accountColumns = `
    id, oidc_subject, proton_user_id, email, state, is_admin,
    key_envelope, refresh_token_ciphertext, mailbox_passphrase_ciphertext,
    imap_password_ciphertext, imap_password_hash, last_event_id,
    crashed, created_at, updated_at, deleted_at
`

// insert persists a brand-new account row. The unique constraint on
// `oidc_subject` is the storage-layer enforcement of SPEC-0001's
// "OIDC subject uniqueness"; we surface that as ErrAccountAlreadyExists.
func (r *repository) insert(ctx context.Context, row *accountRow) error {
	const q = `
    INSERT INTO accounts (
        id, oidc_subject, proton_user_id, email, state, is_admin,
        key_envelope, refresh_token_ciphertext, mailbox_passphrase_ciphertext,
        imap_password_ciphertext, imap_password_hash, last_event_id,
        crashed, created_at, updated_at, deleted_at
    ) VALUES (
        :id, :oidc_subject, :proton_user_id, :email, :state, :is_admin,
        :key_envelope, :refresh_token_ciphertext, :mailbox_passphrase_ciphertext,
        :imap_password_ciphertext, :imap_password_hash, :last_event_id,
        :crashed, :created_at, :updated_at, :deleted_at
    )`
	_, err := r.db.NamedExecContext(ctx, q, row)
	if err != nil {
		// Prefer the typed sqlite error code so this branch survives
		// driver message-text changes. Fall back to a substring match
		// against the unique-constraint message so a future driver swap
		// still has a chance to surface ErrAccountAlreadyExists rather
		// than 500-ing the OIDC login path.
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
			return ErrAccountAlreadyExists
		}
		msg := err.Error()
		if strings.Contains(msg, "UNIQUE constraint failed") &&
			strings.Contains(msg, "accounts.oidc_subject") {
			return ErrAccountAlreadyExists
		}
		return fmt.Errorf("account: insert: %w", err)
	}
	return nil
}

func (r *repository) getByID(ctx context.Context, id string) (*accountRow, error) {
	q := `SELECT ` + accountColumns + ` FROM accounts WHERE id = ?`
	var row accountRow
	if err := r.db.GetContext(ctx, &row, q, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAccountNotFound
		}
		return nil, fmt.Errorf("account: get by id: %w", err)
	}
	return &row, nil
}

func (r *repository) getByOIDCSubject(ctx context.Context, sub string) (*accountRow, error) {
	q := `SELECT ` + accountColumns + ` FROM accounts WHERE oidc_subject = ?`
	var row accountRow
	if err := r.db.GetContext(ctx, &row, q, sub); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAccountNotFound
		}
		return nil, fmt.Errorf("account: get by oidc subject: %w", err)
	}
	return &row, nil
}

// list returns all accounts ordered by created_at ascending. UUIDv7
// IDs sort by creation time, but we sort by created_at explicitly so
// the order is stable even if a future ID scheme changes.
func (r *repository) list(ctx context.Context) ([]*accountRow, error) {
	q := `SELECT ` + accountColumns + ` FROM accounts ORDER BY created_at ASC, id ASC`
	var rows []*accountRow
	if err := r.db.SelectContext(ctx, &rows, q); err != nil {
		return nil, fmt.Errorf("account: list: %w", err)
	}
	return rows, nil
}

// transitionState atomically advances an account from any state in
// `allowedFrom` to `next`. Returns (ok=true, prev) when exactly one
// row was updated (prev is the state the row held immediately before
// the UPDATE landed), (ok=false) when no row matched the WHERE clause
// (meaning another writer raced ahead and changed state since
// validation, or the account does not exist).
//
// Callers that need to distinguish "wrong state" from "missing row"
// must re-read after a false result.
//
// The previous state is captured under a single transaction together
// with the conditional UPDATE so concurrent racers cannot change the
// row between the SELECT and the UPDATE — this is the same atomicity
// guarantee the conditional WHERE clause provides for the write.
//
// Governing: SPEC-0001 REQ "Account Lifecycle States", SPEC-0002 REQ
// "One Worker Per Active Account" (the supervisor needs the prev state
// so it knows whether a transition was INTO or OUT OF active).
func (r *repository) transitionState(ctx context.Context, id string, allowedFrom []State, next State, now time.Time) (ok bool, prev State, err error) {
	if len(allowedFrom) == 0 {
		return false, "", nil
	}
	placeholders := make([]string, len(allowedFrom))
	for i := range allowedFrom {
		placeholders[i] = "?"
	}
	inList := strings.Join(placeholders, ",")

	// Single statement using SQLite's RETURNING clause, so the read of
	// the previous state and the write of the new state happen
	// atomically — there is no window where another writer can sneak
	// in between SELECT and UPDATE. RETURNING reports the row's
	// columns *after* the UPDATE, but it only fires when the UPDATE
	// matched, which only happens when the row was in `allowedFrom`.
	// We therefore know the previous state was one of allowedFrom; we
	// recover the exact value with a CASE expression that snapshots
	// `state` before the SET clause is applied.
	//
	// SQLite evaluates the RETURNING expressions against the post-update
	// row, so we cannot just say `RETURNING state` — that would echo
	// back `next`. Instead the CASE picks the *one* allowedFrom value
	// that the row currently does NOT match (after the SET it matches
	// next). Cleaner alternative: a subquery against the row's old
	// state via OLD.* — but SQLite UPDATE ... RETURNING does not
	// expose OLD/NEW aliases. The transactional fallback below avoids
	// that limitation.
	//
	// Implementation: wrap in BEGIN IMMEDIATE so concurrent transitions
	// serialize at the SQLite write-lock layer (deferred transactions
	// do not prevent two readers from proceeding to conflicting writes
	// under modernc/sqlite). Inside the tx we SELECT the prior state
	// and then UPDATE; both run with the write lock held so no other
	// transition can interleave.
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return false, "", fmt.Errorf("account: begin transition tx: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		// Rollback failures are not actionable from the caller's
		// perspective (we already returned from the operation), but a
		// failure here usually means the underlying connection is in
		// an undefined state — log at WARN so operators can correlate
		// with subsequent driver errors. sql.ErrTxDone is the benign
		// "already rolled back / committed" case and is filtered out.
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			slog.Default().LogAttrs(ctx, slog.LevelWarn,
				"account: transition tx rollback failed",
				slog.String("account_id", id),
				slog.Any("err", rbErr),
			)
		}
	}()

	// Promote the deferred tx to a write transaction immediately so
	// concurrent racers serialize here instead of both observing the
	// same prior state and both running an UPDATE that races at commit.
	// modernc/sqlite (and SQLite generally) allows two deferred
	// transactions to both read, but only one to write — if we don't
	// upgrade up front, the loser's UPDATE can succeed under the
	// fresh post-commit row state if that state still matches a
	// (different) entry in allowedFrom, which is exactly the race
	// TestTransitionIsAtomicUnderConcurrency exercises.
	if _, err := tx.ExecContext(ctx, `UPDATE accounts SET id = id WHERE id = ?`, id); err != nil {
		return false, "", fmt.Errorf("account: acquire write lock: %w", err)
	}

	var prevStr string
	if err := tx.GetContext(ctx, &prevStr, `SELECT state FROM accounts WHERE id = ?`, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, "", nil
		}
		return false, "", fmt.Errorf("account: read prev state: %w", err)
	}

	var (
		q    string
		args []any
	)
	if next == StateSoftDeleted {
		q = `UPDATE accounts SET state = ?, updated_at = ?, deleted_at = ? ` +
			`WHERE id = ? AND state IN (` + inList + `)`
		args = []any{string(next), now, now, id}
	} else {
		q = `UPDATE accounts SET state = ?, updated_at = ? ` +
			`WHERE id = ? AND state IN (` + inList + `)`
		args = []any{string(next), now, id}
	}
	for _, s := range allowedFrom {
		args = append(args, string(s))
	}

	res, err := tx.ExecContext(ctx, q, args...)
	if err != nil {
		return false, "", fmt.Errorf("account: transition state: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, "", fmt.Errorf("account: transition state rows affected: %w", err)
	}
	if n != 1 {
		return false, "", nil
	}
	if err := tx.Commit(); err != nil {
		return false, "", fmt.Errorf("account: commit transition: %w", err)
	}
	committed = true
	return true, State(prevStr), nil
}

// updateRefreshToken stores a sealed refresh token blob.
func (r *repository) updateRefreshToken(ctx context.Context, id string, sealed []byte, now time.Time) error {
	const q = `UPDATE accounts SET refresh_token_ciphertext = ?, updated_at = ? WHERE id = ?`
	res, err := r.db.ExecContext(ctx, q, sealed, now, id)
	if err != nil {
		return fmt.Errorf("account: update refresh token: %w", err)
	}
	return checkOneRow(res, "update refresh token")
}

func (r *repository) updateMailboxPassphrase(ctx context.Context, id string, sealed []byte, now time.Time) error {
	const q = `UPDATE accounts SET mailbox_passphrase_ciphertext = ?, updated_at = ? WHERE id = ?`
	res, err := r.db.ExecContext(ctx, q, sealed, now, id)
	if err != nil {
		return fmt.Errorf("account: update mailbox passphrase: %w", err)
	}
	return checkOneRow(res, "update mailbox passphrase")
}

func (r *repository) updateIMAPPassword(ctx context.Context, id string, sealed []byte, hash string, now time.Time) error {
	const q = `UPDATE accounts SET imap_password_ciphertext = ?, imap_password_hash = ?, updated_at = ? WHERE id = ?`
	res, err := r.db.ExecContext(ctx, q, sealed, hash, now, id)
	if err != nil {
		return fmt.Errorf("account: update imap password: %w", err)
	}
	return checkOneRow(res, "update imap password")
}

func checkOneRow(res sql.Result, op string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("account: %s rows affected: %w", op, err)
	}
	if n == 0 {
		return ErrAccountNotFound
	}
	return nil
}
