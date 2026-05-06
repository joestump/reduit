// Tests for the users.Service public surface. The upsert path is the
// hot one (OIDC callback hits it on every login), so the tests here
// concentrate on its semantics: idempotent first-then-second insert,
// claim-preservation when a subsequent login drops the email/displayname,
// and last_login_at advancing on every successful call.
//
// Governing: ADR-0010, SPEC-0001 REQ "User Identity", SPEC-0001 REQ
// "User Lifecycle".

package users_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/store"
	"github.com/joestump/reduit/internal/users"
)

// migrateMu serializes goose package-level state across parallel
// tests in this package; mirrors the same guard used elsewhere in
// the codebase.
var migrateMu sync.Mutex

func newTestService(t *testing.T) (users.Service, *store.Store) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "reduit-test.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	migrateMu.Lock()
	err = st.Migrate("")
	migrateMu.Unlock()
	if err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}
	return users.New(st), st
}

func TestUpsertCreatesNewUser(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t)
	ctx := context.Background()

	u, err := svc.Upsert(ctx, users.UpsertParams{
		OIDCSubject: "sub-new",
		Email:       "joe@example.com",
		DisplayName: "Joe",
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if u.ID == "" {
		t.Fatal("Upsert returned empty ID")
	}
	if u.OIDCSubject != "sub-new" {
		t.Errorf("OIDCSubject = %q, want sub-new", u.OIDCSubject)
	}
	if u.Email != "joe@example.com" {
		t.Errorf("Email = %q, want joe@example.com", u.Email)
	}
	if u.DisplayName != "Joe" {
		t.Errorf("DisplayName = %q, want Joe", u.DisplayName)
	}
	if u.CreatedAt.IsZero() || u.LastLoginAt.IsZero() {
		t.Errorf("CreatedAt/LastLoginAt must be populated; got %v / %v", u.CreatedAt, u.LastLoginAt)
	}
}

func TestUpsertIsIdempotentForSameSubject(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t)
	ctx := context.Background()

	first, err := svc.Upsert(ctx, users.UpsertParams{OIDCSubject: "sub-idem", Email: "a@example.com"})
	if err != nil {
		t.Fatalf("first Upsert: %v", err)
	}

	// Second Upsert with the same subject MUST return the same row
	// (collapsed via the unique constraint on oidc_subject).
	second, err := svc.Upsert(ctx, users.UpsertParams{OIDCSubject: "sub-idem", Email: "a@example.com"})
	if err != nil {
		t.Fatalf("second Upsert: %v", err)
	}
	if first.ID != second.ID {
		t.Errorf("Upsert returned different IDs for same subject: %q vs %q", first.ID, second.ID)
	}
}

func TestUpsertPreservesClaimsWhenSubsequentLoginDropsThem(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Upsert(ctx, users.UpsertParams{
		OIDCSubject: "sub-claims",
		Email:       "joe@example.com",
		DisplayName: "Joe",
	}); err != nil {
		t.Fatalf("first Upsert: %v", err)
	}

	// Subsequent login by the same subject drops both optional claims.
	// A misbehaving IdP MUST NOT erase the user's email or display name
	// just because it stopped issuing the claim.
	got, err := svc.Upsert(ctx, users.UpsertParams{OIDCSubject: "sub-claims"})
	if err != nil {
		t.Fatalf("second Upsert: %v", err)
	}
	if got.Email != "joe@example.com" {
		t.Errorf("Email = %q, want preserved joe@example.com", got.Email)
	}
	if got.DisplayName != "Joe" {
		t.Errorf("DisplayName = %q, want preserved Joe", got.DisplayName)
	}
}

func TestUpsertAdvancesLastLoginAt(t *testing.T) {
	t.Parallel()

	// Driven by an injected clock instead of time.Sleep: the
	// repository persists s.now() on every login, so two calls
	// against a clock that ticks deterministically between them
	// give us exact, race-free assertions. This avoids the prior
	// 2ms time.Sleep that flaked under contended CI runners.
	//
	// Governing: issue #66 (clock injection so the test doesn't
	// need a real-time pause to clear SQLite's timestamp resolution).
	dbPath := filepath.Join(t.TempDir(), "reduit-test.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	migrateMu.Lock()
	err = st.Migrate("")
	migrateMu.Unlock()
	if err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}

	t0 := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	t1 := t0.Add(5 * time.Second)
	calls := 0
	clock := func() time.Time {
		calls++
		if calls == 1 {
			return t0
		}
		return t1
	}
	svc := users.NewWithClock(st, clock)
	ctx := context.Background()

	first, err := svc.Upsert(ctx, users.UpsertParams{OIDCSubject: "sub-login-time"})
	if err != nil {
		t.Fatalf("first Upsert: %v", err)
	}
	if !first.LastLoginAt.Equal(t0) {
		t.Errorf("first LastLoginAt = %v, want %v", first.LastLoginAt, t0)
	}
	second, err := svc.Upsert(ctx, users.UpsertParams{OIDCSubject: "sub-login-time"})
	if err != nil {
		t.Fatalf("second Upsert: %v", err)
	}
	if !second.LastLoginAt.Equal(t1) {
		t.Errorf("second LastLoginAt = %v, want %v", second.LastLoginAt, t1)
	}
	if !second.LastLoginAt.After(first.LastLoginAt) {
		t.Errorf("LastLoginAt did not advance: first=%v second=%v", first.LastLoginAt, second.LastLoginAt)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("CreatedAt drifted on a re-login: first=%v second=%v", first.CreatedAt, second.CreatedAt)
	}
}

func TestGetByOIDCSubjectAndID(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t)
	ctx := context.Background()

	created, err := svc.Upsert(ctx, users.UpsertParams{OIDCSubject: "sub-lookup"})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	bySub, err := svc.GetByOIDCSubject(ctx, "sub-lookup")
	if err != nil {
		t.Fatalf("GetByOIDCSubject: %v", err)
	}
	if bySub.ID != created.ID {
		t.Errorf("GetByOIDCSubject ID mismatch: got %q want %q", bySub.ID, created.ID)
	}

	byID, err := svc.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if byID.OIDCSubject != "sub-lookup" {
		t.Errorf("GetByID OIDCSubject = %q, want sub-lookup", byID.OIDCSubject)
	}

	if _, err := svc.GetByOIDCSubject(ctx, "sub-missing"); !errors.Is(err, users.ErrUserNotFound) {
		t.Errorf("missing subject error = %v, want ErrUserNotFound", err)
	}
	if _, err := svc.GetByID(ctx, "missing-id"); !errors.Is(err, users.ErrUserNotFound) {
		t.Errorf("missing id error = %v, want ErrUserNotFound", err)
	}
	// Empty inputs MUST also return ErrUserNotFound rather than 500ing.
	if _, err := svc.GetByOIDCSubject(ctx, ""); !errors.Is(err, users.ErrUserNotFound) {
		t.Errorf("empty subject error = %v, want ErrUserNotFound", err)
	}
	if _, err := svc.GetByID(ctx, ""); !errors.Is(err, users.ErrUserNotFound) {
		t.Errorf("empty id error = %v, want ErrUserNotFound", err)
	}
}

func TestUpsertRejectsEmptySubject(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Upsert(ctx, users.UpsertParams{}); err == nil {
		t.Fatal("Upsert with empty OIDCSubject should error")
	}
	if _, err := svc.Upsert(ctx, users.UpsertParams{OIDCSubject: "   "}); err == nil {
		t.Fatal("Upsert with whitespace-only OIDCSubject should error")
	}
}

func TestList(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(t)
	ctx := context.Background()

	for _, sub := range []string{"sub-a", "sub-b", "sub-c"} {
		if _, err := svc.Upsert(ctx, users.UpsertParams{OIDCSubject: sub}); err != nil {
			t.Fatalf("Upsert %s: %v", sub, err)
		}
	}
	got, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("List len = %d, want 3", len(got))
	}
}
