package mcptoken_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/joestump/reduit/internal/auth/mcptoken"
	"github.com/joestump/reduit/internal/store"
)

// TestIssueAndFind issues a fresh token and confirms the plaintext
// resolves back to the same row. The hash on the row MUST equal
// SHA-256(plaintext).
//
// Governing: SPEC-0006 REQ "Token Issuance and Revocation".
func TestIssueAndFind(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	insertAccount(t, st, "acct-1")

	repo := mcptoken.NewRepository(st.DB)
	ctx := context.Background()

	tok, err := repo.Issue(ctx, mcptoken.IssueParams{AccountID: "acct-1", Label: "laptop"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tok.Plaintext == "" {
		t.Fatal("Plaintext empty on Issue")
	}
	if !mcptoken.HasPrefix(tok.Plaintext) {
		t.Fatalf("Plaintext lacks prefix: %q", tok.Plaintext)
	}
	expected := sha256.Sum256([]byte(tok.Plaintext))
	if string(tok.TokenHash) != string(expected[:]) {
		t.Fatalf("TokenHash != sha256(plaintext)")
	}

	got, err := repo.FindByPlaintext(ctx, tok.Plaintext)
	if err != nil {
		t.Fatalf("FindByPlaintext: %v", err)
	}
	if got.ID != tok.ID {
		t.Fatalf("ID = %q, want %q", got.ID, tok.ID)
	}
	if got.Plaintext != "" {
		t.Errorf("FindByPlaintext returned Plaintext (must be zero outside Issue)")
	}
	if !got.IsActive(time.Now()) {
		t.Errorf("issued token reports inactive")
	}
}

// TestRevocationTakesEffect checks an issued token, once revoked, is
// reported as inactive on the very next lookup. The "within 1s of
// revocation" guarantee from issue #13 is enforced by the lack of
// any caching layer between Revoke and FindByPlaintext.
//
// Governing: SPEC-0006 REQ "Token Issuance and Revocation".
func TestRevocationTakesEffect(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	insertAccount(t, st, "acct-1")
	repo := mcptoken.NewRepository(st.DB)
	ctx := context.Background()

	tok, err := repo.Issue(ctx, mcptoken.IssueParams{AccountID: "acct-1"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	start := time.Now()
	if err := repo.Revoke(ctx, tok.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, err := repo.FindByPlaintext(ctx, tok.Plaintext)
	if err != nil {
		t.Fatalf("FindByPlaintext after revoke: %v", err)
	}
	if got.IsActive(time.Now()) {
		t.Fatal("revoked token still IsActive")
	}
	if time.Since(start) > time.Second {
		t.Errorf("revocation took %v, want <1s", time.Since(start))
	}
}

// TestExpiredTokenInactive checks an issued token with ExpiresAt in
// the past reports IsActive(false) — the bearer middleware MUST 401
// on this case (we test that in bearer_test.go).
func TestExpiredTokenInactive(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	insertAccount(t, st, "acct-1")
	repo := mcptoken.NewRepository(st.DB)
	ctx := context.Background()

	past := time.Now().Add(-time.Hour)
	tok, err := repo.Issue(ctx, mcptoken.IssueParams{AccountID: "acct-1", ExpiresAt: &past})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := repo.FindByPlaintext(ctx, tok.Plaintext)
	if err != nil {
		t.Fatalf("FindByPlaintext: %v", err)
	}
	if got.IsActive(time.Now()) {
		t.Fatal("expired token reports IsActive=true")
	}
}

// TestUnknownPlaintextReturnsErrTokenNotFound is the negative path
// the bearer validator relies on to map "unknown bearer" → 401.
func TestUnknownPlaintextReturnsErrTokenNotFound(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	repo := mcptoken.NewRepository(st.DB)
	_, err := repo.FindByPlaintext(context.Background(), "rdmcp_nope")
	if !errors.Is(err, mcptoken.ErrTokenNotFound) {
		t.Fatalf("err = %v, want ErrTokenNotFound", err)
	}
}

// TestRevokeForAccount covers C4 from the round-1 hostile review:
// suspending or soft-deleting an account leaves accounts.id in place
// (state transition, not a DELETE), so the FK cascade does not fire.
// The foundation MUST therefore expose an explicit per-account revoke
// helper.
//
// Governing: SPEC-0005 REQ "Admin Account Management" (suspend /
// soft-delete invalidate MCP tokens).
func TestRevokeForAccount(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	defer st.Close()
	insertAccount(t, st, "acct-victim")
	insertAccount(t, st, "acct-bystander")
	repo := mcptoken.NewRepository(st.DB)
	ctx := context.Background()

	v1, _ := repo.Issue(ctx, mcptoken.IssueParams{AccountID: "acct-victim"})
	v2, _ := repo.Issue(ctx, mcptoken.IssueParams{AccountID: "acct-victim"})
	b1, _ := repo.Issue(ctx, mcptoken.IssueParams{AccountID: "acct-bystander"})

	// Pre-revoke: every token is active.
	now := time.Now()
	for _, tok := range []*mcptoken.Token{v1, v2, b1} {
		got, err := repo.FindByPlaintext(ctx, tok.Plaintext)
		if err != nil {
			t.Fatalf("FindByPlaintext: %v", err)
		}
		if !got.IsActive(now) {
			t.Fatalf("pre-revoke token %s inactive", tok.ID)
		}
	}

	n, err := repo.RevokeForAccount(ctx, "acct-victim")
	if err != nil {
		t.Fatalf("RevokeForAccount: %v", err)
	}
	if n != 2 {
		t.Fatalf("RevokeForAccount = %d, want 2", n)
	}

	// Post-revoke: victim tokens are inactive, bystander still active.
	for _, tok := range []*mcptoken.Token{v1, v2} {
		got, err := repo.FindByPlaintext(ctx, tok.Plaintext)
		if err != nil {
			t.Fatalf("FindByPlaintext (post-revoke): %v", err)
		}
		if got.IsActive(time.Now()) {
			t.Errorf("victim token %s still IsActive after RevokeForAccount", tok.ID)
		}
	}
	got, err := repo.FindByPlaintext(ctx, b1.Plaintext)
	if err != nil {
		t.Fatalf("FindByPlaintext (bystander): %v", err)
	}
	if !got.IsActive(time.Now()) {
		t.Error("bystander token revoked when only victim was suspended")
	}

	// Idempotent: a second call returns 0.
	n, err = repo.RevokeForAccount(ctx, "acct-victim")
	if err != nil {
		t.Fatalf("RevokeForAccount (idempotent): %v", err)
	}
	if n != 0 {
		t.Fatalf("re-revoke = %d, want 0", n)
	}

	// Empty account-id is a guard.
	if _, err := repo.RevokeForAccount(ctx, ""); err == nil {
		t.Error("RevokeForAccount(\"\") returned nil error")
	}
}

// insertAccount minimally satisfies the FK constraint on mcp_tokens.
// The full account.Service is overkill for these table-only tests.
func insertAccount(t *testing.T, st *store.Store, id string) {
	t.Helper()
	// Per ADR-0010, accounts.user_id FK requires a users row first.
	sub := "sub-" + uuid.NewString()
	if _, err := st.DB.ExecContext(context.Background(),
		`INSERT INTO users (id, oidc_subject) VALUES (?, ?)`,
		"user-"+id, sub,
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	const q = `
		INSERT INTO accounts (id, user_id, state, key_envelope)
		VALUES (?, ?, 'pending_proton_setup', X'00')
	`
	if _, err := st.DB.ExecContext(context.Background(), q, id, "user-"+id); err != nil {
		t.Fatalf("insert account: %v", err)
	}
}

// openTempStore mirrors the helper used elsewhere — open + migrate.
func openTempStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir + "/reduit.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Migrate(""); err != nil {
		st.Close()
		t.Fatalf("Migrate: %v", err)
	}
	return st
}
