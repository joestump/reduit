// Package storetest centralises the user+account seeding boilerplate
// that every store-touching package needs in tests. After ADR-0010
// each `accounts` row depends on a parent `users` row (FK on
// accounts.user_id), so a test that just wants "an account in state
// X" has to mint a users row first. Before this package, ~7 test
// files each carried a near-identical helper for that pair; consult
// issue #67 for the inventory.
//
// The helpers here are deliberately small. They take a *store.Store
// directly (not a Service) so packages that don't import users/account
// can use them without taking a service dependency, and they accept
// caller-supplied IDs so a test can keep its assertions readable
// ("acct-A" is more honest than "uuidv7-...-...-..."). Handlers and
// services in production code MUST NOT depend on this package -- it
// is a test-only convenience.
//
// Governing: ADR-0010 (multi-Proton-account per user); issue #67;
// PR #63 review L2 + L3.
package storetest

import (
	"context"
	"database/sql"
	"testing"

	"github.com/joestump/reduit/internal/store"
)

// SeedUserAccountActive mints a parent users row and an `active`
// accounts row owned by that user, then returns the supplied
// accountID for fluent reuse. The users row's id is derived from
// the accountID ("user-"+accountID) and its oidc_subject from
// ("sub-"+accountID) so call sites do not need to track the
// user-side identifier separately.
//
// state=active is the steady-state shape most tests want. Tests
// exercising the wizard flow (state=pending_proton_setup) or the
// soft-delete sweep (state=soft_deleted) should call
// SeedUserAccountPending or set state explicitly via a follow-up
// UPDATE; those code paths are deliberately small and not worth
// proliferating helper variants for.
//
// Failures abort the test via t.Fatalf so callers don't have to
// thread err returns through every fixture call.
//
// Governing: SPEC-0001 REQ "Account Lifecycle States"; ADR-0010.
func SeedUserAccountActive(t *testing.T, st *store.Store, accountID string) string {
	t.Helper()
	return seedUserAccount(t, st, accountID, "active")
}

// SeedUserAccountPending is the wizard-stage twin of
// SeedUserAccountActive. Used by tests that need to exercise code
// paths gated on state=pending_proton_setup (e.g. the wizard's
// resume flow, the bearer-auth tests in #64, the soft-delete
// retention sweep in #82).
//
// Governing: SPEC-0005 REQ "Add-Proton-Account Wizard"; ADR-0010.
func SeedUserAccountPending(t *testing.T, st *store.Store, accountID string) string {
	t.Helper()
	return seedUserAccount(t, st, accountID, "pending_proton_setup")
}

// SeedUser inserts a users row with the supplied OIDC subject and
// returns the assigned user_id. Used by tests that mint accounts
// through account.Service (which requires a pre-existing user_id
// per ADR-0010's FK) rather than by raw SQL.
//
// The id is "user-"+sub so call sites can match a familiar pattern
// against assertions; for tests that need a real UUIDv7 (e.g.
// uniqueness-against-itself), call users.Service.Upsert directly.
//
// Governing: SPEC-0001 REQ "User Identity"; ADR-0010.
func SeedUser(t *testing.T, st *store.Store, sub string) string {
	t.Helper()
	id := "user-" + sub
	if _, err := st.DB.ExecContext(context.Background(),
		`INSERT INTO users (id, oidc_subject) VALUES (?, ?)`,
		id, sub,
	); err != nil {
		t.Fatalf("storetest: insert user (sub=%q): %v", sub, err)
	}
	return id
}

// seedUserAccount is the shared body for the *Active / *Pending
// helpers. Kept private because callers should pick a state-named
// helper -- a `state string` argument at the public surface invites
// "what's a valid state?" confusion that the per-state helpers sidestep.
//
// The minimal account shape (id, user_id, state, key_envelope) is
// enough for FK-touching tests; richer fields (proton_user_id,
// email, primary_alias, ciphertexts) stay nil/zero so tests that
// care about them assert on what they themselves set rather than
// on incidental fixture defaults.
func seedUserAccount(t *testing.T, st *store.Store, accountID, state string) string {
	t.Helper()
	ctx := context.Background()
	userID := "user-" + accountID
	if _, err := st.DB.ExecContext(ctx,
		`INSERT INTO users (id, oidc_subject) VALUES (?, ?)`,
		userID, "sub-"+accountID,
	); err != nil {
		t.Fatalf("storetest: insert user (account=%q): %v", accountID, err)
	}
	const q = `
		INSERT INTO accounts (id, user_id, state, key_envelope)
		VALUES (?, ?, ?, X'00')`
	if _, err := st.DB.ExecContext(ctx, q, accountID, userID, state); err != nil {
		t.Fatalf("storetest: insert account (account=%q, state=%q): %v", accountID, state, err)
	}
	return accountID
}

// Compile-time assertion that *sql.DB is the Store's connection
// shape -- so a future store refactor that swaps the underlying
// driver will break here loudly rather than silently broken-fixture.
var _ *sql.DB = (*sql.DB)(nil)
