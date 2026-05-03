// Tests for SQLitePendingStore. Spins up a real on-disk SQLite via
// internal/store so the schema check in migration
// 20260502000003_outbox.sql is exercised end-to-end.

package outbox

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/store"
)

func TestSQLitePendingStore_RecordTimeout(t *testing.T) {
	t.Parallel()
	s := openMigratedStore(t)
	insertAccount(t, s, "acct-pending")

	ps := NewSQLitePendingStore(s.DB)
	sub := Submission{
		AccountID:  "acct-pending",
		MailFrom:   "joe@reduit.example",
		Recipients: []string{"alice@proton.me", "bob@example.com"},
		Body:       []byte("From: joe\r\nSubject: hi\r\n\r\nbody"),
	}
	cause := errors.New("simulated upstream 502")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := ps.RecordTimeout(ctx, sub, cause); err != nil {
		t.Fatalf("RecordTimeout: %v", err)
	}

	var got struct {
		Status         string
		FailureReason  string `db:"failure_reason"`
		RecipientCount int    `db:"recipient_count"`
		BodyBytes      int    `db:"body_bytes"`
		MailFrom       string `db:"mail_from"`
	}
	if err := s.DB.GetContext(ctx, &got, `
		SELECT status, COALESCE(failure_reason, '') AS failure_reason,
		       recipient_count, body_bytes, mail_from
		FROM outbox_pending
		WHERE account_id = ?`, "acct-pending"); err != nil {
		t.Fatalf("query: %v", err)
	}
	if got.Status != "timeout_failed" {
		t.Errorf("status = %q, want timeout_failed", got.Status)
	}
	if got.FailureReason != cause.Error() {
		t.Errorf("failure_reason = %q, want %q", got.FailureReason, cause.Error())
	}
	if got.RecipientCount != 2 {
		t.Errorf("recipient_count = %d, want 2", got.RecipientCount)
	}
	if got.BodyBytes != len(sub.Body) {
		t.Errorf("body_bytes = %d, want %d", got.BodyBytes, len(sub.Body))
	}
	if got.MailFrom != sub.MailFrom {
		t.Errorf("mail_from = %q, want %q", got.MailFrom, sub.MailFrom)
	}
}

func TestSQLitePendingStore_AccountCascade(t *testing.T) {
	t.Parallel()
	s := openMigratedStore(t)
	insertAccount(t, s, "acct-doomed")

	ps := NewSQLitePendingStore(s.DB)
	if err := ps.RecordTimeout(context.Background(), Submission{
		AccountID:  "acct-doomed",
		MailFrom:   "joe@reduit.example",
		Recipients: []string{"alice@proton.me"},
		Body:       []byte("body"),
	}, errors.New("boom")); err != nil {
		t.Fatalf("RecordTimeout: %v", err)
	}
	// Hard-delete the account; ON DELETE CASCADE on the FK should
	// remove our row too.
	if _, err := s.DB.Exec(`DELETE FROM accounts WHERE id = ?`, "acct-doomed"); err != nil {
		t.Fatalf("delete account: %v", err)
	}
	var n int
	if err := s.DB.Get(&n,
		`SELECT COUNT(*) FROM outbox_pending WHERE account_id = ?`, "acct-doomed"); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("outbox_pending rows after account delete = %d, want 0", n)
	}
}

// openMigratedStore opens a fresh SQLite database with the embedded
// migrations applied.
func openMigratedStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "outbox.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(""); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}

// insertAccount writes the minimum row the FK constraint requires.
// We don't go through internal/account because that pulls in the
// envelope crypto and adds noise to the test. Per ADR-0010 the
// accounts table requires a user_id FK, so we mint a users row
// inline as well.
func insertAccount(t *testing.T, s *store.Store, id string) {
	t.Helper()
	if _, err := s.DB.Exec(
		`INSERT INTO users(id, oidc_subject) VALUES (?, ?)`,
		"user-"+id, "sub-"+id,
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	_, err := s.DB.Exec(`
		INSERT INTO accounts(id, user_id, state, key_envelope)
		VALUES (?, ?, 'active', x'00')`, id, "user-"+id)
	if err != nil {
		t.Fatalf("insert account: %v", err)
	}
}
