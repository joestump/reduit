// Package mcptoken implements per-user MCP bearer-token issuance,
// hash storage, and lookup-by-hash. Plaintext tokens are returned to
// the user exactly once at issuance and never persisted; only the
// SHA-256 hash hits the database. Lookup at request time is O(1) on
// the unique index over `token_hash`.
//
// Issuance UI (POST /accounts/me/mcp-tokens) and revocation UI come
// in a later story; this package owns the storage primitive and the
// hash-lookup validator the bearer middleware (issue #13) consumes.
//
// Governing: SPEC-0006 REQ "Bearer Authentication Required",
// SPEC-0006 REQ "Token Issuance and Revocation".
package mcptoken

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// Plaintext bearer entropy. 32 bytes = 256 bits.
const plaintextEntropyBytes = 32

// Plaintext bearer prefix. Distinguishes Reduit-issued tokens from
// raw OIDC JWTs in transit logs and helps the bearer-validator skip
// cheap JWT detection on obvious MCP tokens. Base64-decodes cleanly
// because we only base64url-encode the random bytes that follow.
const plaintextPrefix = "rdmcp_"

// Token mirrors a row of the mcp_tokens table. Plaintext is set ONLY
// on the result of Issue — every other read path returns a zero
// Plaintext. TokenHash is the 32-byte SHA-256 of the plaintext.
type Token struct {
	ID         string
	AccountID  string
	TokenHash  []byte
	Label      string
	Plaintext  string // populated only by Issue
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
}

// IsActive reports whether the token is usable right now.
func (t *Token) IsActive(now time.Time) bool {
	if t == nil {
		return false
	}
	if t.RevokedAt != nil {
		return false
	}
	if t.ExpiresAt != nil && !t.ExpiresAt.After(now) {
		return false
	}
	return true
}

// Repository is the storage layer for mcp_tokens. The constructor
// accepts a *sqlx.DB so it composes with the rest of internal/store.
type Repository struct {
	db *sqlx.DB
}

// NewRepository wraps db.
func NewRepository(db *sqlx.DB) *Repository {
	return &Repository{db: db}
}

// Errors surfaced to callers.
var (
	ErrTokenNotFound = errors.New("mcptoken: not found")
	ErrTokenInactive = errors.New("mcptoken: revoked or expired")
)

// IssueParams parameterises Issue.
type IssueParams struct {
	AccountID string
	Label     string
	ExpiresAt *time.Time
}

// Issue mints a new plaintext token, hashes it, stores the hash, and
// returns the Token with Plaintext populated. The plaintext is
// returned exactly once — callers MUST surface it to the user
// immediately and discard the in-memory copy after the response is
// written.
//
// Governing: SPEC-0006 REQ "Token Issuance and Revocation" — "the
// plaintext token SHALL be returned exactly once".
func (r *Repository) Issue(ctx context.Context, p IssueParams) (*Token, error) {
	if p.AccountID == "" {
		return nil, errors.New("mcptoken: account_id is required")
	}
	plaintext, err := newPlaintext()
	if err != nil {
		return nil, err
	}
	hash := HashToken(plaintext)
	id := uuid.NewString()
	now := time.Now().UTC()

	const q = `
        INSERT INTO mcp_tokens (id, account_id, token_hash, label, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
    `
	if _, err := r.db.ExecContext(ctx, q, id, p.AccountID, hash, p.Label, now, p.ExpiresAt); err != nil {
		return nil, fmt.Errorf("mcptoken: insert: %w", err)
	}
	return &Token{
		ID:        id,
		AccountID: p.AccountID,
		TokenHash: hash,
		Label:     p.Label,
		Plaintext: plaintext,
		CreatedAt: now,
		ExpiresAt: p.ExpiresAt,
	}, nil
}

// FindByPlaintext looks up an mcp_tokens row by SHA-256(plaintext).
// Returns ErrTokenNotFound when nothing matches the hash. Returns the
// row even if revoked/expired so callers can decide how to surface
// the failure (revocation 401 vs unknown token 401 — same status,
// different log line).
func (r *Repository) FindByPlaintext(ctx context.Context, plaintext string) (*Token, error) {
	if plaintext == "" {
		return nil, ErrTokenNotFound
	}
	hash := HashToken(plaintext)
	return r.findByHash(ctx, hash)
}

func (r *Repository) findByHash(ctx context.Context, hash []byte) (*Token, error) {
	const q = `
        SELECT id, account_id, token_hash, label, created_at, expires_at, revoked_at, last_used_at
          FROM mcp_tokens
         WHERE token_hash = ?
    `
	var row struct {
		ID         string       `db:"id"`
		AccountID  string       `db:"account_id"`
		TokenHash  []byte       `db:"token_hash"`
		Label      string       `db:"label"`
		CreatedAt  time.Time    `db:"created_at"`
		ExpiresAt  sql.NullTime `db:"expires_at"`
		RevokedAt  sql.NullTime `db:"revoked_at"`
		LastUsedAt sql.NullTime `db:"last_used_at"`
	}
	if err := r.db.GetContext(ctx, &row, q, hash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		return nil, fmt.Errorf("mcptoken: lookup: %w", err)
	}
	// Constant-time hash comparison guards against an attacker forcing
	// a collision-search timing oracle on the index. Both buffers are
	// 32 bytes (sha256) so subtle is appropriate.
	if subtle.ConstantTimeCompare(row.TokenHash, hash) != 1 {
		return nil, ErrTokenNotFound
	}
	t := &Token{
		ID:        row.ID,
		AccountID: row.AccountID,
		TokenHash: row.TokenHash,
		Label:     row.Label,
		CreatedAt: row.CreatedAt,
	}
	if row.ExpiresAt.Valid {
		v := row.ExpiresAt.Time
		t.ExpiresAt = &v
	}
	if row.RevokedAt.Valid {
		v := row.RevokedAt.Time
		t.RevokedAt = &v
	}
	if row.LastUsedAt.Valid {
		v := row.LastUsedAt.Time
		t.LastUsedAt = &v
	}
	return t, nil
}

// Revoke marks an MCP token revoked. Subsequent FindByPlaintext calls
// still return the row, but Token.IsActive returns false; the bearer
// middleware MUST therefore check IsActive after a successful lookup.
//
// Idempotent: revoking an already-revoked token returns nil.
//
// Governing: SPEC-0006 REQ "Token Issuance and Revocation" — "subsequent
// MCP requests carrying that token SHALL fail".
func (r *Repository) Revoke(ctx context.Context, id string) error {
	const q = `UPDATE mcp_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`
	res, err := r.db.ExecContext(ctx, q, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("mcptoken: revoke: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mcptoken: revoke rows affected: %w", err)
	}
	if n == 0 {
		return ErrTokenNotFound
	}
	return nil
}

// MarkUsed updates last_used_at for an authenticated token. Best-effort
// — failures here MUST NOT block the request, so callers should log
// the error and continue serving.
func (r *Repository) MarkUsed(ctx context.Context, id string) error {
	const q = `UPDATE mcp_tokens SET last_used_at = ? WHERE id = ?`
	_, err := r.db.ExecContext(ctx, q, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("mcptoken: mark used: %w", err)
	}
	return nil
}

// HashToken returns the 32-byte SHA-256 of the plaintext bearer.
// Exported so the bearer-token middleware can hash an incoming
// Authorization value once before calling FindByHash directly.
func HashToken(plaintext string) []byte {
	sum := sha256.Sum256([]byte(plaintext))
	return sum[:]
}

func newPlaintext() (string, error) {
	buf := make([]byte, plaintextEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("mcptoken: read random: %w", err)
	}
	return plaintextPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// HasPrefix reports whether the supplied bearer string carries the
// Reduit-issued prefix. The bearer-token validator uses this as a
// cheap discriminator to skip the JWT verifier on obvious MCP tokens.
func HasPrefix(bearer string) bool {
	if len(bearer) < len(plaintextPrefix) {
		return false
	}
	return bearer[:len(plaintextPrefix)] == plaintextPrefix
}
