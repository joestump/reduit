package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// TestAccountsUserIDImmutable proves the storage-layer guard from
// migration 20260506000001: an UPDATE that re-binds accounts.user_id to
// a different tenant is aborted by the database, while an UPDATE of a
// non-ownership column (state) on the same row succeeds. The guard
// backstops application discipline so no code path -- present or future
// -- can violate the invariant.
//
// This test seeds via raw SQL rather than internal/storetest because
// storetest imports this package (store), and importing it back here
// would be a cycle.
//
// Governing: SPEC-0001 REQ "Ownership is immutable".
func TestAccountsUserIDImmutable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "immutable.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(""); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// Two tenants and one account owned by the first.
	for _, u := range []string{"user-A", "user-B"} {
		if _, err := s.DB.ExecContext(ctx,
			`INSERT INTO users (id, oidc_subject) VALUES (?, ?)`,
			u, "sub-"+u,
		); err != nil {
			t.Fatalf("insert user %q: %v", u, err)
		}
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO accounts (id, user_id, state, key_envelope) VALUES (?, ?, 'active', X'00')`,
		"acct-1", "user-A",
	); err != nil {
		t.Fatalf("insert account: %v", err)
	}

	// Re-binding ownership to a different (valid) tenant must be
	// rejected by the trigger, not silently applied.
	_, err = s.DB.ExecContext(ctx,
		`UPDATE accounts SET user_id = ? WHERE id = ?`, "user-B", "acct-1")
	if err == nil {
		t.Fatal("expected UPDATE changing user_id to be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "accounts.user_id is immutable") {
		t.Fatalf("expected abort error mentioning immutable user_id, got: %v", err)
	}

	// The ownership must be unchanged after the rejected UPDATE.
	var owner string
	if err := s.DB.GetContext(ctx, &owner,
		`SELECT user_id FROM accounts WHERE id = ?`, "acct-1"); err != nil {
		t.Fatalf("read user_id: %v", err)
	}
	if owner != "user-A" {
		t.Fatalf("user_id changed despite rejected UPDATE: got %q, want %q", owner, "user-A")
	}

	// A normal UPDATE of a different column on the same row succeeds:
	// the guard is scoped to ownership changes only and does not block
	// legitimate state transitions.
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE accounts SET state = 'suspended' WHERE id = ?`, "acct-1"); err != nil {
		t.Fatalf("UPDATE of state column should succeed, got: %v", err)
	}
	var state string
	if err := s.DB.GetContext(ctx, &state,
		`SELECT state FROM accounts WHERE id = ?`, "acct-1"); err != nil {
		t.Fatalf("read state: %v", err)
	}
	if state != "suspended" {
		t.Fatalf("state update did not apply: got %q, want %q", state, "suspended")
	}

	// A no-op write that mentions user_id without changing it (the
	// repository's write-lock pattern issues `SET id = id`; this is the
	// equivalent for the guarded column) must also pass through.
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE accounts SET user_id = user_id WHERE id = ?`, "acct-1"); err != nil {
		t.Fatalf("no-op user_id self-assignment should succeed, got: %v", err)
	}
}

// TestAccountsUserIDImmutableReplace proves the companion BEFORE INSERT
// guard from migration 20260506000001: an INSERT OR REPLACE (or REPLACE)
// that re-binds an existing account's owner is aborted by the database.
// The BEFORE UPDATE trigger alone does not cover this path because SQLite
// implements REPLACE as DELETE-then-INSERT, so BEFORE UPDATE never fires
// and the upsert would silently flip ownership (and cascade-delete child
// rows). This test also confirms the guard does not break legitimate
// inserts: a brand-new account still inserts, and an upsert preserving
// the same owner still succeeds.
//
// Governing: SPEC-0001 REQ "Ownership is immutable".
func TestAccountsUserIDImmutableReplace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "immutable_replace.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(""); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// Two tenants and one account owned by the first.
	for _, u := range []string{"user-A", "user-B"} {
		if _, err := s.DB.ExecContext(ctx,
			`INSERT INTO users (id, oidc_subject) VALUES (?, ?)`,
			u, "sub-"+u,
		); err != nil {
			t.Fatalf("insert user %q: %v", u, err)
		}
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO accounts (id, user_id, state, key_envelope) VALUES (?, ?, 'active', X'00')`,
		"acct-1", "user-A",
	); err != nil {
		t.Fatalf("insert account: %v", err)
	}

	// (a) INSERT OR REPLACE re-binding ownership to a different tenant
	// must be rejected by the BEFORE INSERT guard. Without it, SQLite's
	// DELETE+INSERT semantics would bypass the BEFORE UPDATE trigger.
	_, err = s.DB.ExecContext(ctx,
		`INSERT OR REPLACE INTO accounts (id, user_id, state, key_envelope) VALUES (?, ?, 'active', X'00')`,
		"acct-1", "user-B")
	if err == nil {
		t.Fatal("expected INSERT OR REPLACE changing user_id to be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "accounts.user_id is immutable") {
		t.Fatalf("expected abort error mentioning immutable user_id, got: %v", err)
	}

	// The bare REPLACE keyword is the same path and must also be rejected.
	_, err = s.DB.ExecContext(ctx,
		`REPLACE INTO accounts (id, user_id, state, key_envelope) VALUES (?, ?, 'active', X'00')`,
		"acct-1", "user-B")
	if err == nil {
		t.Fatal("expected REPLACE changing user_id to be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "accounts.user_id is immutable") {
		t.Fatalf("expected abort error mentioning immutable user_id, got: %v", err)
	}

	// Ownership must be unchanged after the rejected upserts.
	var owner string
	if err := s.DB.GetContext(ctx, &owner,
		`SELECT user_id FROM accounts WHERE id = ?`, "acct-1"); err != nil {
		t.Fatalf("read user_id: %v", err)
	}
	if owner != "user-A" {
		t.Fatalf("user_id changed despite rejected upsert: got %q, want %q", owner, "user-A")
	}

	// (b) A normal INSERT of a brand-new account (new id, no existing
	// row) must still succeed: the BEFORE INSERT guard only fires when a
	// row with the same id but a different owner already exists.
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO accounts (id, user_id, state, key_envelope) VALUES (?, ?, 'active', X'00')`,
		"acct-2", "user-B"); err != nil {
		t.Fatalf("INSERT of brand-new account should succeed, got: %v", err)
	}

	// (c) An INSERT OR REPLACE that preserves the same owner must still
	// succeed: the guard's `user_id <> NEW.user_id` clause is false, so
	// the legitimate upsert path is not blocked.
	if _, err := s.DB.ExecContext(ctx,
		`INSERT OR REPLACE INTO accounts (id, user_id, state, key_envelope) VALUES (?, ?, 'suspended', X'00')`,
		"acct-1", "user-A"); err != nil {
		t.Fatalf("INSERT OR REPLACE preserving owner should succeed, got: %v", err)
	}
	if err := s.DB.GetContext(ctx, &owner,
		`SELECT user_id FROM accounts WHERE id = ?`, "acct-1"); err != nil {
		t.Fatalf("read user_id after same-owner upsert: %v", err)
	}
	if owner != "user-A" {
		t.Fatalf("owner changed after same-owner upsert: got %q, want %q", owner, "user-A")
	}
}
