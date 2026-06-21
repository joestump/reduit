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
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
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
	keyUserID   = "auth.user_id"
	keyAccount  = "auth.account_id"
	keyIsAdmin  = "auth.is_admin"
	keyEmail    = "auth.email"
	keyReturnTo = "auth.return_to"
	keyCSRF     = "auth.csrf"
)

// Identity is the subset of authenticated-user state Reduit caches in
// the session. Per ADR-0010, sessions bind primarily to UserID (the
// `users` row resolved from the OIDC subject at callback time);
// AccountID is OPTIONAL and only set when handlers scope a request
// to a specific Proton account.
//
// IsAdmin is computed at session-bind time from OIDC_ADMIN_SUBS
// against Subject -- per SPEC-0005 REQ "Session admin tag is computed
// at bind time" -- and cached here for the session's lifetime (a
// re-login recomputes it).
type Identity struct {
	Subject   string
	UserID    string
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
//
// PutIdentity does NOT mirror id.AccountID into the sessions.account_id
// column itself, because the row is not durably written until SCS
// commits on the response path. Callers that need a queryable
// account-id link (for the SPEC-0005 "drop sessions on suspend"
// scenario) MUST follow up with BindSessionToAccount once the
// response has flushed; the typical place for that is the same
// /auth/callback handler that calls PutIdentity, just after a
// successful redirect-write.
//
// Governing: SPEC-0005 REQ "OIDC Login Flow"; SPEC-0005 REQ "Admin
// Account Management" (drop sessions on suspend).
func PutIdentity(ctx context.Context, mgr *scs.SessionManager, id Identity) error {
	if mgr == nil {
		return errors.New("session: nil manager")
	}
	mgr.Put(ctx, keySubject, id.Subject)
	mgr.Put(ctx, keyUserID, id.UserID)
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

// BindSessionToUser records the (token, user_id) pair in the
// session_owners sidecar table so a future RevokeSessionsForUser
// call can drop every session belonging to a soft-deleted user in
// O(log n) on the idx_session_owners_user_id index.
//
// Per ADR-0010 this is the PRIMARY bind path -- a session is owned
// by a user; the optional account_id scoping comes later via
// BindSessionToAccount when a handler narrows the request to a
// specific account.
//
// A sidecar (rather than extra columns on `sessions`) is required
// because SCS's sqlite3store commits via `REPLACE INTO sessions(...)`
// which clobbers any other column on every request. CASCADE on
// `users(id)` and `accounts(id)` drives the revocation paths;
// session_owners.token deliberately lacks a FK to sessions(token)
// because the same REPLACE-on-commit would cascade-drop the owner
// row mid-handler (see the schema migration's comment for detail).
//
// Callers SHOULD invoke mgr.Commit before BindSessionToUser so a live
// `sessions.token` row exists when downstream lookups (e.g. revoke
// by user) join on it, but BindSessionToUser does not enforce that
// ordering -- the session_owners row stands on its own.
//
// On re-login through the same browser the SCS token is renewed
// inside PutIdentity, so this INSERT lands on a fresh primary key
// rather than upserting the prior row. The prior token's owner row
// is left orphaned in session_owners until a scheduled sweep cleans
// it up (tracked as a known follow-up; the rows are tiny and revoke
// paths key on user_id/account_id, so the orphan does not affect
// correctness).
//
// Governing: ADR-0010, SPEC-0005 REQ "OIDC Login Flow", SPEC-0001
// REQ "User Lifecycle".
func BindSessionToUser(ctx context.Context, mgr *scs.SessionManager, db *sql.DB, userID string) error {
	if mgr == nil {
		return errors.New("session: nil manager")
	}
	if db == nil {
		return errors.New("session: nil db")
	}
	if userID == "" {
		return errors.New("session: empty user id")
	}
	token := mgr.Token(ctx)
	if token == "" {
		// No session token yet (the caller forgot to wrap with
		// LoadAndSave, or Commit has not happened). Nothing to bind.
		return nil
	}
	const q = `INSERT INTO session_owners (token, user_id) VALUES (?, ?)
	           ON CONFLICT(token) DO UPDATE SET user_id = excluded.user_id, bound_at = CURRENT_TIMESTAMP`
	if _, err := db.ExecContext(ctx, q, token, userID); err != nil {
		return fmt.Errorf("session: bind to user: %w", err)
	}
	return nil
}

// BindSessionToAccount sets the OPTIONAL account_id scope on an
// already-user-bound session row. This is the narrow form used when a
// handler scopes a request to a specific Proton account (e.g.
// /accounts/{id}/messages -- per SPEC-0006); the broader user binding
// is established earlier in the OIDC callback via BindSessionToUser.
//
// Errors with a clear "session not bound to a user" message if no
// session_owners row exists for the current token. Callers MUST call
// BindSessionToUser before BindSessionToAccount; the schema's
// `user_id NOT NULL` constraint enforces this at the storage layer
// even if a future caller tries to skip the user-bind step.
//
// Governing: ADR-0010, SPEC-0005 REQ "Admin Account Management"
// (drop sessions on suspend / soft-delete -- per-account fan-out).
func BindSessionToAccount(ctx context.Context, mgr *scs.SessionManager, db *sql.DB, accountID string) error {
	if mgr == nil {
		return errors.New("session: nil manager")
	}
	if db == nil {
		return errors.New("session: nil db")
	}
	if accountID == "" {
		return errors.New("session: empty account id")
	}
	token := mgr.Token(ctx)
	if token == "" {
		return nil
	}
	const q = `UPDATE session_owners SET account_id = ?, bound_at = CURRENT_TIMESTAMP WHERE token = ?`
	res, err := db.ExecContext(ctx, q, accountID, token)
	if err != nil {
		return fmt.Errorf("session: bind to account: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("session: bind to account rows affected: %w", err)
	}
	if n == 0 {
		return errors.New("session: bind to account: session not bound to a user (call BindSessionToUser first)")
	}
	return nil
}

// RevokeSessionsForAccount drops every session row owned by the
// supplied account, returning the number of rows affected. The
// implementation is a single DELETE FROM sessions keyed by the join
// to session_owners through the idx_session_owners_account_id index,
// so cost is O(rows-deleted) regardless of the total session count.
//
// Sessions written before the #23 callback handler is in service
// (i.e. without a corresponding session_owners row) are NOT revoked
// by this function — they have no recorded owner, by definition
// cannot have authorised any account-scoped traffic yet, and will
// expire naturally via the SCS sweep within DefaultLifetime.
//
// Idempotent: calling on an account with zero live sessions returns
// (0, nil).
//
// Governing: SPEC-0005 REQ "Admin Account Management" (drop sessions
// on suspend / soft-delete).
func RevokeSessionsForAccount(ctx context.Context, db *sql.DB, accountID string) (int64, error) {
	if db == nil {
		return 0, errors.New("session: nil db")
	}
	if accountID == "" {
		return 0, errors.New("session: empty account id")
	}
	const deleteSessions = `DELETE FROM sessions WHERE token IN (SELECT token FROM session_owners WHERE account_id = ?)`
	res, err := db.ExecContext(ctx, deleteSessions, accountID)
	if err != nil {
		return 0, fmt.Errorf("session: revoke for account: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("session: rows affected: %w", err)
	}
	// Drop the now-orphaned owner rows in passing. A leftover row is
	// harmless (the sessions row it points at is gone, so SCS misses
	// on Find), but cleaning up keeps the index small and the schema
	// honest.
	const deleteOwners = `DELETE FROM session_owners WHERE account_id = ?`
	if _, err := db.ExecContext(ctx, deleteOwners, accountID); err != nil {
		return n, fmt.Errorf("session: cleanup session_owners: %w", err)
	}
	return n, nil
}

// RevokeSessionsForUser drops every session row owned by the supplied
// user, returning the number of rows affected. Symmetric to
// RevokeSessionsForAccount but scoped to user_id -- the primary
// revocation primitive used when a users row is removed (per
// SPEC-0001 REQ "User Lifecycle") or on operator-initiated
// "log everyone out" actions.
//
// Sessions written before the OIDC callback handler is in service
// (i.e. without a corresponding session_owners row) are NOT revoked
// by this function -- they have no recorded owner, by definition
// cannot have authorised any user-scoped traffic yet, and will
// expire naturally via the SCS sweep within DefaultLifetime.
//
// Idempotent: calling on a user with zero live sessions returns
// (0, nil).
//
// Governing: ADR-0010, SPEC-0001 REQ "User Lifecycle".
func RevokeSessionsForUser(ctx context.Context, db *sql.DB, userID string) (int64, error) {
	if db == nil {
		return 0, errors.New("session: nil db")
	}
	if userID == "" {
		return 0, errors.New("session: empty user id")
	}
	const deleteSessions = `DELETE FROM sessions WHERE token IN (SELECT token FROM session_owners WHERE user_id = ?)`
	res, err := db.ExecContext(ctx, deleteSessions, userID)
	if err != nil {
		return 0, fmt.Errorf("session: revoke for user: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("session: rows affected: %w", err)
	}
	const deleteOwners = `DELETE FROM session_owners WHERE user_id = ?`
	if _, err := db.ExecContext(ctx, deleteOwners, userID); err != nil {
		return n, fmt.Errorf("session: cleanup session_owners: %w", err)
	}
	return n, nil
}

// SweepOrphanSessionOwners deletes session_owners rows whose token
// no longer exists in the sessions table. Returns the number of rows
// affected.
//
// Why this exists: when a user re-logs in through the same browser,
// PutIdentity calls mgr.RenewToken inside SCS, which mints a fresh
// token for subsequent writes. The prior token's session_owners row
// is left orphaned -- the SCS sweep only drops `sessions` rows, not
// the linked sidecar entries. We deliberately can NOT bolt this on
// as a CASCADE foreign key because SCS commits via
// `REPLACE INTO sessions` (i.e. DELETE + INSERT), which would fire
// the cascade on every commit and clobber the bind mid-handler. See
// migration 20260502000005_sessions_account_id.sql for the long form.
//
// Not a correctness bug: revocation paths key on user_id / account_id
// (see RevokeSessionsForUser, RevokeSessionsForAccount), not on
// token, so an orphaned row cannot keep a revoked user's session
// alive. It only bloats the index. A periodic sweep keeps it bounded.
//
// Single bulk DELETE -- the index on session_owners(token) plus the
// PK lookup on sessions(token) make the NOT IN subquery cheap even
// with thousands of rows. Idempotent: running twice in a row affects
// 0 rows the second time.
//
// Governing: ADR-0010, SPEC-0005 REQ "OIDC Login Flow"; issue #70;
// PR #69 review M1 / C1.
func SweepOrphanSessionOwners(ctx context.Context, db *sql.DB) (int64, error) {
	if db == nil {
		return 0, errors.New("session: nil db")
	}
	const q = `DELETE FROM session_owners WHERE token NOT IN (SELECT token FROM sessions)`
	res, err := db.ExecContext(ctx, q)
	if err != nil {
		return 0, fmt.Errorf("session: sweep orphan owners: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("session: sweep orphan owners rows affected: %w", err)
	}
	return n, nil
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
		UserID:    mgr.GetString(ctx, keyUserID),
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
	mgr.Remove(ctx, keyUserID)
	mgr.Remove(ctx, keyAccount)
	mgr.Remove(ctx, keyEmail)
	mgr.Remove(ctx, keyIsAdmin)
	mgr.Remove(ctx, keyReturnTo)
	mgr.Remove(ctx, keyCSRF)
}

// CSRFToken returns the session's per-session CSRF token, minting and
// persisting a fresh one on first call. The token is a 256-bit random
// value, base64url-encoded, stored on the SCS session payload so it
// rides the same HttpOnly cookie as the rest of the identity and is
// renewed (via PutIdentity's RenewToken) on each login.
//
// State-changing form handlers (currently only POST /auth/logout) embed
// this value as a hidden field and validate it with ValidCSRF on
// submission. Because the token lives in the SCS session and not in a
// readable cookie, a cross-site attacker cannot read it to forge a
// matching field.
//
// Pattern choice: SPEC-0005 design "Content security and CSRF"
// illustrates the double-submit-cookie pattern. We use the
// synchronizer-token pattern instead -- the token is stored server-side
// on the SCS session rather than mirrored into a readable cookie. The
// two are equivalent in defence; synchronizer is marginally stronger
// (the secret never leaves the server in a JS-readable form, sidestepping
// the cookie-tossing / subdomain-injection edge cases double-submit
// must reason about) and it fits naturally because Reduit already keeps
// an SCS session. The design section's intent (an unforgeable per-
// session token on every state-changing form) is satisfied.
//
// Callers MUST be inside an scs.LoadAndSave scope (the session
// middleware) before calling this -- outside that scope, scs panics.
//
// Governing: SPEC-0005 design "Content security and CSRF".
func CSRFToken(ctx context.Context, mgr *scs.SessionManager) string {
	if mgr == nil {
		return ""
	}
	if tok := mgr.GetString(ctx, keyCSRF); tok != "" {
		return tok
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failure is catastrophic and effectively never
		// happens on a healthy host; returning "" yields a form whose
		// token never validates (fails closed) rather than a guessable
		// constant.
		return ""
	}
	tok := base64.RawURLEncoding.EncodeToString(buf)
	mgr.Put(ctx, keyCSRF, tok)
	return tok
}

// ValidCSRF reports whether the supplied token matches the session's
// stored CSRF token. Comparison is constant-time. An empty stored
// token (CSRFToken never minted, or a rand failure) never validates --
// fail closed.
//
// Governing: SPEC-0005 design "Content security and CSRF".
func ValidCSRF(ctx context.Context, mgr *scs.SessionManager, token string) bool {
	if mgr == nil || token == "" {
		return false
	}
	stored := mgr.GetString(ctx, keyCSRF)
	if stored == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(token)) == 1
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
