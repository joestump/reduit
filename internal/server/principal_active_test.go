// Unit tests for issue #52's session re-check (principalActiveChecker).
// These exercise the ADR-0010 reconciliation directly against real
// users/account services backed by a temp store:
//
//   - sessions bind to users.id, so the user-scoped check enforces only
//     that the bound user still EXISTS (a hard-deleted/unknown user is
//     denied); per-account suspend/soft-delete is the route handlers'
//     job (409), NOT a gate lockout -- a gate lockout would break
//     self-service reactivation and the 409 conflict contract;
//   - admins are admissible (subject to user existence);
//   - an account-scoped session (AccountID set) is the #52 enforcement
//     point: it is denied when the named account is suspended or
//     soft-deleted, admitted otherwise (active / pending).
//
// Governing: ADR-0004 (OIDC control-plane auth), ADR-0010 (sessions
// bind to users.id; AccountID optional), SPEC-0001 REQ "Account
// Lifecycle States", SPEC-0005 REQ "Admin Account Management".

package server_test

import (
	"context"
	"testing"

	"github.com/joestump/reduit/internal/account"
	authsession "github.com/joestump/reduit/internal/auth/session"
	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/server"
	"github.com/joestump/reduit/internal/users"
)

func TestPrincipalActiveChecker(t *testing.T) {
	t.Parallel()
	st := openTempStore(t)
	master, err := cryptenv.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	usrSvc := users.New(st)
	accSvc := account.New(st, master)
	ctx := context.Background()

	check := server.PrincipalActiveChecker(usrSvc, accSvc)

	u, err := usrSvc.Upsert(ctx, users.UpsertParams{OIDCSubject: "sub-joe", Email: "joe@stump.rocks"})
	if err != nil {
		t.Fatalf("Upsert user: %v", err)
	}
	acct, err := accSvc.Create(ctx, account.CreateParams{UserID: u.ID, Email: "joe@proton.me"})
	if err != nil {
		t.Fatalf("Create account: %v", err)
	}

	id := authsession.Identity{Subject: "sub-joe", UserID: u.ID}

	// User-scoped session: admissible across every owned-account state,
	// because account-state enforcement lives in the route handlers. The
	// gate only cares that the user exists.
	for _, st := range []account.State{
		account.StatePendingProtonSetup, // mid-wizard
		account.StateActive,
		account.StateSuspended,   // owner can self-reactivate
		account.StateSoftDeleted, // handlers return 409
	} {
		if st != account.StatePendingProtonSetup {
			if _, err := accSvc.Transition(ctx, acct.ID, st); err != nil {
				t.Fatalf("Transition %s: %v", st, err)
			}
		}
		if ok, err := check(ctx, id); err != nil || !ok {
			t.Fatalf("user-scoped with account in %s: ok=%v err=%v, want ok=true", st, ok, err)
		}
	}

	// Admin principal is admissible.
	adminID := authsession.Identity{Subject: "sub-joe", UserID: u.ID, IsAdmin: true}
	if ok, err := check(ctx, adminID); err != nil || !ok {
		t.Fatalf("admin: ok=%v err=%v, want ok=true", ok, err)
	}

	// User who owns no accounts (pre-wizard / first-run) is admissible.
	u2, err := usrSvc.Upsert(ctx, users.UpsertParams{OIDCSubject: "sub-newbie"})
	if err != nil {
		t.Fatalf("Upsert user2: %v", err)
	}
	if ok, err := check(ctx, authsession.Identity{Subject: "sub-newbie", UserID: u2.ID}); err != nil || !ok {
		t.Fatalf("no-accounts user: ok=%v err=%v, want ok=true", ok, err)
	}

	// Unknown user id -> denied (user-scoped revocation), not an error.
	if ok, err := check(ctx, authsession.Identity{Subject: "ghost", UserID: "no-such-user"}); err != nil || ok {
		t.Fatalf("unknown user: ok=%v err=%v, want ok=false err=nil", ok, err)
	}

	// Empty UserID (malformed shape) -> denied.
	if ok, err := check(ctx, authsession.Identity{Subject: "joe"}); err != nil || ok {
		t.Fatalf("empty UserID: ok=%v err=%v, want ok=false err=nil", ok, err)
	}

	// Account-scoped session: the #52 enforcement point. Give the user a
	// fresh active account and scope the session to it.
	acct2, err := accSvc.Create(ctx, account.CreateParams{UserID: u.ID, ProtonUserID: "pu-2", Email: "joe2@proton.me"})
	if err != nil {
		t.Fatalf("Create account2: %v", err)
	}
	if _, err := accSvc.Transition(ctx, acct2.ID, account.StateActive); err != nil {
		t.Fatalf("Transition active acct2: %v", err)
	}
	scoped := authsession.Identity{Subject: "sub-joe", UserID: u.ID, AccountID: acct2.ID}
	if ok, err := check(ctx, scoped); err != nil || !ok {
		t.Fatalf("account-scoped active: ok=%v err=%v, want ok=true", ok, err)
	}

	// Suspend the scoped account -> denied on the next request (#52).
	if _, err := accSvc.Transition(ctx, acct2.ID, account.StateSuspended); err != nil {
		t.Fatalf("Transition suspended acct2: %v", err)
	}
	if ok, err := check(ctx, scoped); err != nil || ok {
		t.Fatalf("account-scoped suspended: ok=%v err=%v, want ok=false err=nil", ok, err)
	}

	// Soft-delete the scoped account -> still denied.
	if _, err := accSvc.Transition(ctx, acct2.ID, account.StateSoftDeleted); err != nil {
		t.Fatalf("Transition soft_deleted acct2: %v", err)
	}
	if ok, err := check(ctx, scoped); err != nil || ok {
		t.Fatalf("account-scoped soft-deleted: ok=%v err=%v, want ok=false err=nil", ok, err)
	}

	// Account-scoped session referencing a non-existent account -> denied.
	ghostScoped := authsession.Identity{Subject: "sub-joe", UserID: u.ID, AccountID: "no-such-account"}
	if ok, err := check(ctx, ghostScoped); err != nil || ok {
		t.Fatalf("account-scoped unknown account: ok=%v err=%v, want ok=false err=nil", ok, err)
	}
}
