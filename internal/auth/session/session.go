// Package session wraps github.com/alexedwards/scs/v2 with Reduit's
// cookie + storage conventions. It exposes:
//
//   - New: builds a configured *scs.SessionManager backed by the
//     scs/sqlite3store package (the v0.3 sessions table is created
//     by migration 20260502000004).
//   - Get/Put helpers for the authenticated subject and admin flag.
//
// The login/callback handlers (issue #23) consume Put. The middleware
// in package auth consumes Get to gate routes per SPEC-0005's
// "Authentication Gating" requirement.
//
// Governing: ADR-0004 (OIDC sessions in SCS over SQLite), ADR-0006
// (single-process SQLite store), SPEC-0005 REQ "Authentication
// Gating", SPEC-0005 REQ "OIDC Login Flow".
package session

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/alexedwards/scs/sqlite3store"
	"github.com/alexedwards/scs/v2"
)

// CookieName is the canonical session cookie name. Wired from the
// design plugin's "reduit_session" choice in SPEC-0005.
const CookieName = "reduit_session"

// DefaultLifetime caps a single session at 12 hours. Reduit is a
// home-infra control plane; most real sessions are minutes, not
// days. Forcing a re-login each morning is a deliberate trade-off
// against the cost of a stolen-cookie window.
const DefaultLifetime = 12 * time.Hour

// DefaultIdleTimeout boots a session after 30 minutes of inactivity.
const DefaultIdleTimeout = 30 * time.Minute

// Options tweaks New. Zero values fall back to safe defaults.
type Options struct {
	// Lifetime is the absolute upper bound on a session, regardless of
	// activity. Defaults to DefaultLifetime.
	Lifetime time.Duration
	// IdleTimeout is the rolling inactivity timeout. Defaults to
	// DefaultIdleTimeout.
	IdleTimeout time.Duration
	// Insecure clears the Secure cookie attribute. ONLY use in tests
	// against an httptest server (which is plain HTTP). Production code
	// MUST leave this false.
	Insecure bool
}

// New returns a *scs.SessionManager backed by sqlite3store using the
// supplied *sql.DB (typically store.Store.DB). The session table is
// created by goose migration 20260502000004 — callers MUST run
// migrations before calling New, or queries will fail at first
// session write.
//
// The caller is responsible for invoking the returned cleanup func
// at shutdown to stop the store's background sweep goroutine. The
// cleanup is safe to call multiple times.
func New(db *sql.DB, opts Options) (*scs.SessionManager, func(), error) {
	if db == nil {
		return nil, nil, errors.New("session: nil db")
	}
	store := sqlite3store.New(db)
	mgr := scs.New()
	mgr.Store = store
	mgr.Lifetime = opts.Lifetime
	if mgr.Lifetime == 0 {
		mgr.Lifetime = DefaultLifetime
	}
	mgr.IdleTimeout = opts.IdleTimeout
	if mgr.IdleTimeout == 0 {
		mgr.IdleTimeout = DefaultIdleTimeout
	}
	mgr.Cookie.Name = CookieName
	mgr.Cookie.HttpOnly = true
	mgr.Cookie.Path = "/"
	mgr.Cookie.SameSite = http.SameSiteLaxMode
	mgr.Cookie.Secure = !opts.Insecure
	mgr.Cookie.Persist = false

	cleanup := func() {
		store.StopCleanup()
	}
	return mgr, cleanup, nil
}

// Session-data keys. Defined as constants so handlers in different
// packages cannot disagree on the spelling.
const (
	keySubject  = "auth.subject"
	keyAccount  = "auth.account_id"
	keyIsAdmin  = "auth.is_admin"
	keyEmail    = "auth.email"
	keyReturnTo = "auth.return_to"
)

// Identity is the subset of authenticated-user state Reduit caches in
// the session. Admin promotion comes either from
// SPEC-0005 first-run-bootstrap or from the OIDC_ADMIN_SUBS env at
// callback time; once set on the session it is sticky for the
// session's lifetime (re-login refreshes it).
type Identity struct {
	Subject   string
	AccountID string
	Email     string
	IsAdmin   bool
}

// PutIdentity stores the identity in the current request's session.
// Login/callback handlers call this once, after they've validated the
// ID token and resolved (or created) the local account row.
//
// Callers MUST have wrapped the request through scs.LoadAndSave (the
// session middleware) before calling this — outside that scope, scs
// panics.
func PutIdentity(ctx context.Context, mgr *scs.SessionManager, id Identity) error {
	if mgr == nil {
		return errors.New("session: nil manager")
	}
	mgr.Put(ctx, keySubject, id.Subject)
	mgr.Put(ctx, keyAccount, id.AccountID)
	mgr.Put(ctx, keyEmail, id.Email)
	mgr.Put(ctx, keyIsAdmin, id.IsAdmin)
	// Renew the session token on identity establishment so a
	// pre-login fixated cookie cannot survive into the post-login
	// session — standard session-fixation guard.
	if err := mgr.RenewToken(ctx); err != nil {
		return err
	}
	return nil
}

// GetIdentity returns the cached identity. Subject is empty when no
// authenticated user is bound to the session, which is the canonical
// "unauthenticated" signal middleware uses.
func GetIdentity(ctx context.Context, mgr *scs.SessionManager) Identity {
	if mgr == nil {
		return Identity{}
	}
	return Identity{
		Subject:   mgr.GetString(ctx, keySubject),
		AccountID: mgr.GetString(ctx, keyAccount),
		Email:     mgr.GetString(ctx, keyEmail),
		IsAdmin:   mgr.GetBool(ctx, keyIsAdmin),
	}
}

// IsAuthenticated reports whether the session currently carries an
// identity. A non-empty Subject is the source of truth.
func IsAuthenticated(ctx context.Context, mgr *scs.SessionManager) bool {
	if mgr == nil {
		return false
	}
	return mgr.GetString(ctx, keySubject) != ""
}

// Clear removes the identity from the session. Logout handlers (#23)
// MUST call Destroy on the manager to fully invalidate; Clear alone
// keeps the session record alive minus identity, which is rarely
// what you want.
func Clear(ctx context.Context, mgr *scs.SessionManager) {
	if mgr == nil {
		return
	}
	mgr.Remove(ctx, keySubject)
	mgr.Remove(ctx, keyAccount)
	mgr.Remove(ctx, keyEmail)
	mgr.Remove(ctx, keyIsAdmin)
	mgr.Remove(ctx, keyReturnTo)
}

// PutReturnTo stashes the post-login redirect target. Login init
// stores it on the session before redirecting to the IdP; the
// callback handler consumes it (or "/accounts" by default).
func PutReturnTo(ctx context.Context, mgr *scs.SessionManager, target string) {
	if mgr == nil || target == "" {
		return
	}
	mgr.Put(ctx, keyReturnTo, target)
}

// TakeReturnTo reads-and-clears the post-login target. Returns ""
// when none was stashed.
func TakeReturnTo(ctx context.Context, mgr *scs.SessionManager) string {
	if mgr == nil {
		return ""
	}
	v := mgr.GetString(ctx, keyReturnTo)
	if v != "" {
		mgr.Remove(ctx, keyReturnTo)
	}
	return v
}
