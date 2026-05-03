// Repository persistence for users.
//
// Governing: ADR-0006 (SQLite + sqlx), ADR-0010 (multi-Proton-account
// per user), SPEC-0001 REQ "User Identity".
package users

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

// repository is the sqlx-backed CRUD layer for the users table. It is
// unexported because callers should go through Service, which layers
// upsert semantics and OIDC-specific input normalization on top.
type repository struct {
	db *sqlx.DB
}

// userRow mirrors the on-disk schema. sql.NullString is used for the
// optional ID-token claims (email, display_name) so an unset claim
// distinguishes from an empty-string claim in storage.
type userRow struct {
	ID          string         `db:"id"`
	OIDCSubject string         `db:"oidc_subject"`
	Email       sql.NullString `db:"email"`
	DisplayName sql.NullString `db:"display_name"`
	CreatedAt   time.Time      `db:"created_at"`
	LastLoginAt time.Time      `db:"last_login_at"`
}

func (r userRow) toUser() *User {
	return &User{
		ID:          r.ID,
		OIDCSubject: r.OIDCSubject,
		Email:       r.Email.String,
		DisplayName: r.DisplayName.String,
		CreatedAt:   r.CreatedAt,
		LastLoginAt: r.LastLoginAt,
	}
}

const userColumns = `id, oidc_subject, email, display_name, created_at, last_login_at`

// insert persists a brand-new users row. Caller is responsible for
// avoiding races on oidc_subject -- Service.Upsert wraps insert in a
// "lookup-or-insert" pattern that handles the concurrent-first-login
// race.
func (r *repository) insert(ctx context.Context, row *userRow) error {
	const q = `
    INSERT INTO users (id, oidc_subject, email, display_name, created_at, last_login_at)
    VALUES (:id, :oidc_subject, :email, :display_name, :created_at, :last_login_at)`
	if _, err := r.db.NamedExecContext(ctx, q, row); err != nil {
		return fmt.Errorf("users: insert: %w", err)
	}
	return nil
}

// updateLogin advances last_login_at and refreshes any ID-token
// claims (email, display_name) that the caller resolved on this
// callback. Empty claims do NOT clear stored values -- a misbehaving
// IdP that drops the email claim on a subsequent login should not
// silently erase the user's email.
func (r *repository) updateLogin(ctx context.Context, id string, email, displayName string, at time.Time) error {
	const q = `
    UPDATE users
    SET    last_login_at = :last_login_at,
           email = COALESCE(NULLIF(:email, ''), email),
           display_name = COALESCE(NULLIF(:display_name, ''), display_name)
    WHERE  id = :id`
	res, err := r.db.NamedExecContext(ctx, q, map[string]any{
		"id":            id,
		"email":         email,
		"display_name":  displayName,
		"last_login_at": at,
	})
	if err != nil {
		return fmt.Errorf("users: update login: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("users: update login (rows affected): %w", err)
	}
	if n == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (r *repository) getByID(ctx context.Context, id string) (*userRow, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE id = ?`
	var row userRow
	if err := r.db.GetContext(ctx, &row, q, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("users: get by id: %w", err)
	}
	return &row, nil
}

func (r *repository) getByOIDCSubject(ctx context.Context, sub string) (*userRow, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE oidc_subject = ?`
	var row userRow
	if err := r.db.GetContext(ctx, &row, q, sub); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("users: get by oidc subject: %w", err)
	}
	return &row, nil
}

func (r *repository) listAll(ctx context.Context) ([]*userRow, error) {
	const q = `SELECT ` + userColumns + ` FROM users ORDER BY created_at ASC`
	var rows []*userRow
	if err := r.db.SelectContext(ctx, &rows, q); err != nil {
		return nil, fmt.Errorf("users: list: %w", err)
	}
	return rows, nil
}
