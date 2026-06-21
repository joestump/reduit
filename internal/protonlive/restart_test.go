// Simulated-daemon-restart re-unlock tests (#34).
//
// These exercise the full restart path against a REAL account.Service
// (SQLite + the master-key envelope), not a fake SecretSource/UIDSource:
// the session UID, refresh token, and mailbox passphrase are sealed via
// the same accessors the wizard uses, then a FRESH Lifecycle — modelling
// a new process that has only the on-disk sealed secrets — re-auths +
// re-unlocks the account and registers a working client.
//
// The "restart" is modelled by discarding the Lifecycle/registry the
// secrets were sealed through and building a brand-new
// Registry+Lifecycle wired with account.Service as BOTH the SecretSource
// and the UIDSource (account.Service satisfies UIDSource via
// OpenSessionUID). Nothing but the SQLite file + master key crosses the
// boundary, which is exactly what survives a daemon restart.
//
// Governing: ADR-0003 (sealed secrets unsealed only for the re-unlock
// call), ADR-0001 (the session UID is required by /auth/v4/refresh),
// SPEC-0002 REQ "One Worker Per Active Account"; #28, #34.
package protonlive

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/store"
	"github.com/joestump/reduit/internal/storetest"
)

// migrateMu serializes store.Migrate against goose's global config, the
// same way the account package's test harness does.
var migrateMu sync.Mutex

// newRestartAccountService spins up a fresh on-disk SQLite under
// t.TempDir, runs the embedded migrations, and returns an
// account.Service plus the store so the test can seed a user.
func newRestartAccountService(t *testing.T) (account.Service, *store.Store) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "reduit-restart.db")
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

	master, err := cryptenv.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	return account.New(st, master), st
}

// sealActiveAccount creates an account, seals the three credentials the
// boot re-unlock consumes (session UID, refresh token, mailbox
// passphrase), and transitions it to active — i.e. exactly the on-disk
// state a successful wizard run leaves behind. Returns the account ID.
func sealActiveAccount(t *testing.T, svc account.Service, st *store.Store, sub, uid string) string {
	t.Helper()
	ctx := context.Background()
	userID := storetest.SeedUser(t, st, sub)
	a, err := svc.Create(ctx, account.CreateParams{UserID: userID})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := svc.SetProtonIdentity(ctx, a.ID, userID, "proton-user-"+sub, sub+"@proton.test"); err != nil {
		t.Fatalf("SetProtonIdentity: %v", err)
	}
	if uid != "" {
		if err := svc.SealSessionUID(ctx, a.ID, []byte(uid)); err != nil {
			t.Fatalf("SealSessionUID: %v", err)
		}
	}
	if err := svc.SealRefreshToken(ctx, a.ID, []byte("sealed-refresh-token")); err != nil {
		t.Fatalf("SealRefreshToken: %v", err)
	}
	if err := svc.SealMailboxPassphrase(ctx, a.ID, []byte("mailbox-passphrase")); err != nil {
		t.Fatalf("SealMailboxPassphrase: %v", err)
	}
	if _, err := svc.Transition(ctx, a.ID, account.StateActive); err != nil {
		t.Fatalf("Transition active: %v", err)
	}
	return a.ID
}

// TestRestart_ReUnlocksActiveAccountFromSealedSecrets is the headline
// test for #34: after a simulated restart, a fresh Lifecycle re-auths +
// re-unlocks an active account purely from its sealed secrets and the
// resolver yields the working client the authenticator produced.
func TestRestart_ReUnlocksActiveAccountFromSealedSecrets(t *testing.T) {
	svc, st := newRestartAccountService(t)
	const wantUID = "restart-session-uid-abc123"
	acctID := sealActiveAccount(t, svc, st, "restart-success", wantUID)

	// --- simulate the restart: brand-new registry + lifecycle, wired
	// only to the on-disk-backed account.Service. ---
	keyID := "primary-key"
	user, salts := userWithPrimaryKey(keyID)
	fc := &fakeClient{user: user, salts: salts}
	auth := &fakeAuth{client: fc, auth: &proton.Auth{UID: wantUID}}

	reg := New(nil)
	// account.Service is the SecretSource AND the UIDSource (it satisfies
	// both via OpenRefreshToken/OpenMailboxPassphrase + OpenSessionUID).
	lc := NewLifecycle(reg, auth, svc, svc, svc, nil)

	actives, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	lc.RegisterActiveAccounts(context.Background(), actives)

	// The unsealed session UID must have reached the authenticator —
	// proving OpenSessionUID round-tripped the sealed value through
	// /auth/v4/refresh.
	if auth.gotUID != wantUID {
		t.Fatalf("authenticator got uid=%q, want the sealed %q", auth.gotUID, wantUID)
	}
	if auth.gotRef != "sealed-refresh-token" {
		t.Fatalf("authenticator got refresh=%q, want the sealed token", auth.gotRef)
	}

	// The resolver (what IMAP/MCP/outbox use) must now hand out the live
	// client for the account.
	got, err := reg.Resolver().ProtonForAccount(context.Background(), acctID)
	if err != nil {
		t.Fatalf("ProtonForAccount: %v", err)
	}
	if got != fc {
		t.Fatalf("resolver returned %v, want the re-unlocked client %v", got, fc)
	}
}

// TestRestart_PreMigrationAccountSkippedNotFailed is the backward-compat
// case: an account whose row predates the session-UID column (modelled
// by sealing no UID) MUST be SKIPPED on boot — left active, no client
// registered, and crucially NOT transitioned to pending_proton_setup.
// The missing UID is the not-yet-persisted gap, not a credential
// failure.
func TestRestart_PreMigrationAccountSkippedNotFailed(t *testing.T) {
	svc, st := newRestartAccountService(t)
	acctID := sealActiveAccount(t, svc, st, "restart-no-uid", "" /* no sealed UID */)

	auth := &fakeAuth{} // must never be called
	reg := New(nil)
	lc := NewLifecycle(reg, auth, svc, svc, svc, nil)

	actives, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	lc.RegisterActiveAccounts(context.Background(), actives)

	if auth.calls != 0 {
		t.Fatalf("missing-UID account must not attempt refresh auth: calls=%d", auth.calls)
	}
	if _, ok := reg.Get(acctID); ok {
		t.Fatal("missing-UID account must not register a client")
	}
	// The account must remain active (not kicked to pending).
	a, err := svc.GetByID(context.Background(), acctID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if a.State != account.StateActive {
		t.Fatalf("missing-UID account state = %q, want still active", a.State)
	}
	if a.HasSessionUID {
		t.Fatal("account modelling a pre-migration row should report HasSessionUID=false")
	}
}
