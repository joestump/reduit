// OIDC-callback session-bind orchestration. The login/callback HTTP
// handler in #23 calls BindFromOIDC after validating the ID token; this
// file puts the policy "upsert user, bind session, compute admin from
// allowlist, write Identity" in one place rather than expecting every
// future callback variant (RP-Initiated re-login, mid-session refresh)
// to re-implement it.
//
// Governing: ADR-0010 (multi-Proton-account per user), SPEC-0005 REQ
// "OIDC Login Flow", SPEC-0005 REQ "Session admin tag is computed at
// bind time", SPEC-0001 REQ "User Identity", SPEC-0001 REQ "User
// Lifecycle".

package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/alexedwards/scs/v2"

	"github.com/joestump/reduit/internal/auth/session"
	"github.com/joestump/reduit/internal/users"
)

// OIDCClaims is the subset of validated ID-token claims the bind
// orchestration consumes. The /auth/callback handler builds this
// after the OIDC client has verified signature, issuer, audience, and
// nonce; BindFromOIDC trusts the values verbatim.
//
// Subject is the OIDC `sub` -- the identity key for the users row.
// Email and DisplayName are optional and may be empty; empty values
// preserve any prior stored value (the users.Service.Upsert
// COALESCE-NULLIF guard handles this).
type OIDCClaims struct {
	Subject     string
	Email       string
	DisplayName string
}

// BindFromOIDC is the post-callback workhorse: it upserts the users
// row, binds the SCS session to the resolved user_id, computes the
// admin tag from the supplied allowlist (typically OIDC_ADMIN_SUBS
// loaded at boot), and writes the Identity onto the session.
//
// Returns the bound Identity so the caller can render it (or use
// Identity.UserID as the ?return_to redirect's owner).
//
// Caller MUST already have wrapped the request through
// scs.LoadAndSave; BindFromOIDC handles the explicit Commit before
// the user-bind so the SCS sessions row exists for the FK target.
//
// Errors flow as wrapped errors with a stable prefix so the callback
// handler can surface them as 500 Internal Server Error without
// leaking implementation detail.
//
// Governing: ADR-0010, SPEC-0005 REQ "OIDC Login Flow",
// SPEC-0005 REQ "Session admin tag is computed at bind time",
// SPEC-0001 REQ "User Identity".
func BindFromOIDC(
	ctx context.Context,
	mgr *scs.SessionManager,
	db *sql.DB,
	usrSvc users.Service,
	claims OIDCClaims,
	adminSubs []string,
) (session.Identity, error) {
	if mgr == nil {
		return session.Identity{}, errors.New("auth: nil session manager")
	}
	if db == nil {
		return session.Identity{}, errors.New("auth: nil db")
	}
	if usrSvc == nil {
		return session.Identity{}, errors.New("auth: nil users service")
	}
	sub := strings.TrimSpace(claims.Subject)
	if sub == "" {
		return session.Identity{}, errors.New("auth: empty OIDC subject")
	}

	u, err := usrSvc.Upsert(ctx, users.UpsertParams{
		OIDCSubject: sub,
		Email:       claims.Email,
		DisplayName: claims.DisplayName,
	})
	if err != nil {
		return session.Identity{}, fmt.Errorf("auth: upsert user: %w", err)
	}

	// Compute admin tag from the allowlist at bind time, against the
	// validated OIDC subject (NOT against email/display_name, which
	// callers can choose; subject is the OIDC-specified stable
	// identifier). Empty entries in adminSubs are deliberately not
	// matched -- a stray empty entry in OIDC_ADMIN_SUBS (e.g. from
	// "OIDC_ADMIN_SUBS=,sub-foo") MUST NOT promote a user with an
	// empty subject (defense in depth; sub is non-empty here anyway).
	isAdmin := sub != "" && slices.Contains(adminSubs, sub)

	// Email written to Identity is the resolved-from-DB email after
	// upsert (which may have preserved a prior claim value), not the
	// raw claim. That keeps the session view consistent with what
	// /accounts and other handlers see when they re-read the user row.
	id := session.Identity{
		Subject: sub,
		UserID:  u.ID,
		Email:   u.Email,
		IsAdmin: isAdmin,
	}
	if err := session.PutIdentity(ctx, mgr, id); err != nil {
		return session.Identity{}, fmt.Errorf("auth: put identity: %w", err)
	}

	// Force the SCS session row to disk so the session_owners FK has
	// a target. BindSessionToUser is the primary write; account-level
	// scoping (BindSessionToAccount) happens later when the handler
	// narrows to a specific account.
	if _, _, err := mgr.Commit(ctx); err != nil {
		return session.Identity{}, fmt.Errorf("auth: commit session: %w", err)
	}
	if err := session.BindSessionToUser(ctx, mgr, db, u.ID); err != nil {
		return session.Identity{}, fmt.Errorf("auth: bind session to user: %w", err)
	}

	return id, nil
}
