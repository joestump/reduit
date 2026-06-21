// Service is the public face of the account package. It composes a
// repository, the service master key, and the admin allowlist; it
// validates state transitions and owns per-account secret seal/open.
//
// Governing: ADR-0002 (multi-tenant), ADR-0003 (envelope encryption),
// SPEC-0001 (Account Model).
package account

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/store"
)

// TransitionCallback is invoked by Service.Transition (and by
// convenience wrappers like Service.Delete) AFTER a state change has
// successfully committed. Callbacks fire synchronously, in registration
// order, with the previous state, the next state, and a snapshot of
// the account post-transition. They MUST NOT block for long: keep the
// work bounded and offload anything heavy to a goroutine.
//
// A panic in a callback is recovered by the dispatcher so a single
// misbehaving subscriber cannot poison the rest of the chain or fail
// the surrounding Transition call (which has already committed).
//
// Governing: SPEC-0002 REQ "One Worker Per Active Account" — the sync
// supervisor subscribes here so worker start/stop is driven by an
// in-process event, not a DB poll loop.
type TransitionCallback func(ctx context.Context, prev, next State, account *Account)

// Service is the contract every consumer (HTTP handlers, sync worker,
// IMAP/SMTP servers, MCP tools) talks to.
type Service interface {
	// Create mints a new account row for the given user. It generates
	// a fresh per-account data key, seals it under the master key, and
	// persists the envelope. Returns ErrAccountAlreadyExists when the
	// (user_id, proton_user_id) pair is already taken (i.e., the user
	// already owns an account for that Proton user).
	//
	// Per ADR-0010 the caller resolves UserID from the bound session
	// before calling Create -- account.Service does not look up users
	// itself. ProtonUserID is optional at create time; the wizard
	// fills it in once Proton login completes.
	Create(ctx context.Context, params CreateParams) (*Account, error)

	// GetByID returns the account with the given ID, or
	// ErrAccountNotFound.
	GetByID(ctx context.Context, id string) (*Account, error)

	// Transition validates and persists a state change. Illegal
	// transitions return ErrInvalidTransition.
	Transition(ctx context.Context, id string, next State) (*Account, error)

	// List returns every account, ordered by creation time ascending.
	// Used by admin views and by the sync supervisor's startup scan;
	// per-user views SHOULD use ListByUser instead.
	List(ctx context.Context) ([]*Account, error)

	// ListByUser returns every account owned by the given user,
	// ordered by creation time ascending. This is the hot path for
	// the per-user account dashboard (SPEC-0005) and ownership
	// enumeration (SPEC-0001).
	ListByUser(ctx context.Context, userID string) ([]*Account, error)

	// Delete is a convenience for `Transition(ctx, id, StateSoftDeleted)`.
	// Hard deletion is the responsibility of the retention sweep job.
	Delete(ctx context.Context, id string) (*Account, error)

	// SealRefreshToken seals plaintext under the account's data key
	// (fresh nonce per call) and persists the ciphertext.
	SealRefreshToken(ctx context.Context, accountID string, plaintext []byte) error

	// OpenRefreshToken returns the plaintext refresh token for the
	// account, or an error if no token has been stored.
	OpenRefreshToken(ctx context.Context, accountID string) ([]byte, error)

	// UpdateRefreshToken is an alias for SealRefreshToken named for the
	// shape that external callers (e.g. internal/proton's
	// RefreshTokenSaver callback) read most naturally. Plaintext in,
	// sealed-on-disk out — the data key never leaves the account package.
	UpdateRefreshToken(ctx context.Context, accountID string, plaintext []byte) error

	SealMailboxPassphrase(ctx context.Context, accountID string, plaintext []byte) error
	OpenMailboxPassphrase(ctx context.Context, accountID string) ([]byte, error)

	// SealSessionUID seals the ephemeral Proton session UID under the
	// account's data key (fresh nonce per call) and persists the
	// ciphertext. Captured at wizard-commit time from auth.UID so the
	// daemon can re-auth (/auth/v4/refresh) and re-unlock the account on
	// restart without an interactive wizard run.
	//
	// Governing: ADR-0003, ADR-0001, SPEC-0001 REQ "Encrypted Secret
	// Storage"; #28, #34.
	SealSessionUID(ctx context.Context, accountID string, plaintext []byte) error

	// OpenSessionUID returns the plaintext Proton session UID, or
	// ErrSecretNotPresent when no UID has been sealed (every account
	// created before #34's migration, and any whose wizard last ran
	// before #34). account.Service satisfies protonlive.UIDSource via
	// this method; the not-present case maps to protonlive's existing
	// "skip boot re-unlock with a WARN" missing-UID path.
	//
	// Governing: ADR-0003, SPEC-0002 REQ "One Worker Per Active
	// Account"; #34.
	OpenSessionUID(ctx context.Context, accountID string) (string, error)

	SealIMAPPassword(ctx context.Context, accountID string, plaintext []byte) error
	OpenIMAPPassword(ctx context.Context, accountID string) ([]byte, error)

	// RotateIMAPPassword generates a fresh per-user IMAP/SMTP password,
	// seals it under the account's data key, persists ciphertext + a
	// bcrypt hash for SASL lookups, and returns the plaintext for
	// one-time display in the admin UI.
	RotateIMAPPassword(ctx context.Context, accountID string) (string, error)

	// VerifyIMAPPassword compares a candidate plaintext against the
	// stored bcrypt hash. Returns nil on match, an error otherwise.
	VerifyIMAPPassword(ctx context.Context, accountID string, candidate []byte) error

	// OnTransition registers cb to be invoked after every successful
	// state transition. Returns an unsubscribe func; callers SHOULD
	// invoke it on shutdown to free the slot. Multiple callbacks are
	// supported and fired in registration order.
	//
	// Governing: SPEC-0002 REQ "One Worker Per Active Account".
	OnTransition(cb TransitionCallback) (unsubscribe func())

	// GetByPrimaryAlias resolves a SASL PLAIN `local@host` identity
	// to the owning account. Returns ErrAccountNotFound if no row
	// matches. Lookup is case-insensitive and whitespace-trimmed —
	// the wire form supplied by the IMAP/SMTP client is normalised
	// before comparison so "Joe@Example.COM" and "joe@example.com "
	// both resolve to the same row.
	//
	// Governing: SPEC-0003 REQ "SASL PLAIN With user@host Identity".
	GetByPrimaryAlias(ctx context.Context, alias string) (*Account, error)

	// SetPrimaryAlias stores (or clears, when alias is empty) the
	// canonical local@host SASL identity for the account. Returns
	// ErrAccountAlreadyExists when another account already owns the
	// alias. The alias is normalised (trim + lower-case) before
	// storage so lookups are reliable.
	//
	// Governing: SPEC-0003 REQ "SASL PLAIN With user@host Identity".
	SetPrimaryAlias(ctx context.Context, accountID, alias string) error

	// SetProtonIdentity stamps the persistent Proton account
	// identifier and login email onto an existing account row. Called
	// once by the add-account wizard after the SRP login completes;
	// the row is created with these columns NULL because ADR-0010
	// pushes Proton identity discovery into the wizard flow rather
	// than the OIDC callback. Returns ErrAccountAlreadyExists when
	// the same Proton user is already bound to a different row owned
	// by the same Reduit user (the unique index on (user_id,
	// proton_user_id) enforces this). Returns ErrProtonIdentityMismatch
	// when THIS row already carries a different non-empty
	// proton_user_id: per SPEC-0001 a Proton user ID mismatch on a
	// subsequent login is an error and MUST NOT silently overwrite the
	// stored value. Re-stamping the identical id is idempotent.
	//
	// userID is included as a WHERE predicate (defense in depth) so
	// a future caller bug that passes the wrong accountID cannot
	// re-stamp another user's row -- the wizard handler verifies
	// session-bound user ownership upstream, but the storage layer
	// gets to check too.
	//
	// Governing: ADR-0010, SPEC-0005 REQ "Add-Proton-Account Wizard".
	SetProtonIdentity(ctx context.Context, accountID, userID, protonUserID, email string) error

	// GetSyncState returns the persisted Proton event cursor for the
	// account, or ErrNoSyncState if no successful sync has ever
	// committed. The sync worker calls this on startup to decide
	// whether to resume from a persisted cursor or to bootstrap from
	// proton.Client.GetLatestEventID.
	//
	// Governing: SPEC-0002 REQ "Event Cursor Persistence" — "Resume on
	// startup uses persisted cursor".
	GetSyncState(ctx context.Context, accountID string) (*SyncState, error)

	// SetSyncState commits a cursor advance atomically with any
	// caller-supplied derived-state writes. The txWork callback (which
	// may be nil) is invoked with the open *sqlx.Tx; returning a
	// non-nil error rolls back the entire transaction (cursor +
	// derived state).
	//
	// The signature is strict (single nilable parameter, not variadic)
	// so a misuse like passing two callbacks is a compile-time error,
	// not a runtime panic. Callers with no derived work pass nil.
	//
	// Governing: SPEC-0002 REQ "Event Cursor Persistence" — atomic
	// commit of cursor and state changes derived from the same batch.
	SetSyncState(ctx context.Context, accountID, cursor string, txWork SyncStateTxWork) error

	// SoftDeleteOldPending soft-deletes every account row stuck in
	// state pending_proton_setup whose created_at is older than
	// `olderThan` ago. Returns the number of rows affected. Intended
	// to be called periodically (hourly) by a retention sweep so
	// orphan pending rows -- created when a wizard session expires
	// from the in-memory store before Proton login completes -- do
	// not accumulate forever.
	//
	// The cutoff is computed against the service clock (s.now) so
	// tests that inject a fake clock can exercise the sweep without
	// real-time waits.
	//
	// Governing: SPEC-0001 REQ "Account Lifecycle States"; ADR-0010,
	// SPEC-0005 REQ "Add-Proton-Account Wizard"; issue #82.
	SoftDeleteOldPending(ctx context.Context, olderThan time.Duration) (int64, error)

	// MarkCrashed sets the `crashed` flag on the account row. The sync
	// supervisor calls this from the panic-recovery defer after a worker
	// goroutine crashes so the admin UI can surface "needs manual reset"
	// without polling. The flag is independent of the lifecycle State —
	// a crashed worker leaves the account in StateActive so reactivation
	// is a single bit-flip rather than a state transition. Manual reset
	// happens via SPEC-0005 admin actions.
	//
	// Governing: SPEC-0002 REQ "Panic Isolation".
	MarkCrashed(ctx context.Context, accountID string) error
}

// CreateParams collects the inputs to Service.Create. ProtonUserID
// and Email are optional at create time — they are filled in by the
// Proton login wizard once it completes. UserID MUST reference an
// existing users row (the FK is enforced at the storage layer).
type CreateParams struct {
	UserID       string
	ProtonUserID string
	Email        string
}

type service struct {
	repo   *repository
	master cryptenv.MasterKey
	now    func() time.Time
	newID  func() (string, error)

	// transitionCBs holds the live set of transition subscribers. A
	// pointer-keyed registration cell is used so unsubscribe is O(1)
	// without needing every caller to track a numeric ID.
	transitionMu sync.RWMutex
	transitionCB map[*transitionReg]struct{}
}

// transitionReg is the registration cell for a TransitionCallback.
// We key the map by *transitionReg (not the func value) because
// function values are not comparable in Go.
type transitionReg struct {
	cb TransitionCallback
}

// New constructs a Service backed by the given store and master key.
// The Service does not take ownership of the store — the caller
// closes it. Per ADR-0010, admin status is no longer an account
// attribute, so the admin allowlist is not passed here -- it lives
// at the session layer (computed at session-bind time from
// OIDC_ADMIN_SUBS per SPEC-0001 REQ "Admin Status").
//
// Panics if s or s.DB is nil. New is a boot-time call (wiring in
// main); a missing store is a programmer error the caller cannot
// meaningfully recover from, so this returns no error and crashes
// loudly at startup rather than threading a (Service, error) pair
// through every call site.
func New(s *store.Store, master cryptenv.MasterKey) Service {
	if s == nil || s.DB == nil {
		panic("account: New called with nil store")
	}
	return &service{
		repo:         &repository{db: s.DB},
		master:       master,
		now:          time.Now,
		newID:        newUUIDv7,
		transitionCB: make(map[*transitionReg]struct{}),
	}
}

func newUUIDv7() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("account: uuidv7: %w", err)
	}
	return id.String(), nil
}

// Create implements Service.Create.
//
// Governing: ADR-0010 (multi-Proton-account per user), SPEC-0001 REQ
// "Account Identity", SPEC-0001 REQ "Per-Account Data Key".
func (s *service) Create(ctx context.Context, params CreateParams) (*Account, error) {
	params.UserID = strings.TrimSpace(params.UserID)
	if params.UserID == "" {
		return nil, errors.New("account: UserID is required")
	}

	id, err := s.newID()
	if err != nil {
		return nil, err
	}

	dk, err := cryptenv.GenerateDataKey()
	if err != nil {
		return nil, fmt.Errorf("account: generate data key: %w", err)
	}
	envelope, err := cryptenv.SealEnvelope(s.master, dk)
	if err != nil {
		// Zero out dk before returning even on error.
		zeroDataKey(&dk)
		return nil, fmt.Errorf("account: seal envelope: %w", err)
	}
	zeroDataKey(&dk)

	now := s.now().UTC()
	row := &accountRow{
		ID:          id,
		UserID:      params.UserID,
		State:       string(StatePendingProtonSetup),
		KeyEnvelope: envelope,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if params.ProtonUserID != "" {
		row.ProtonUserID = sql.NullString{String: params.ProtonUserID, Valid: true}
	}
	if params.Email != "" {
		row.Email = sql.NullString{String: params.Email, Valid: true}
	}

	if err := s.repo.insert(ctx, row); err != nil {
		return nil, err
	}
	return row.toAccount(), nil
}

func (s *service) ListByUser(ctx context.Context, userID string) ([]*Account, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, errors.New("account: userID is required")
	}
	rows, err := s.repo.listByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]*Account, len(rows))
	for i, r := range rows {
		out[i] = r.toAccount()
	}
	return out, nil
}

func (s *service) GetByID(ctx context.Context, id string) (*Account, error) {
	row, err := s.repo.getByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return row.toAccount(), nil
}

// normalisePrimaryAlias trims surrounding whitespace and lower-cases
// the supplied SASL identity. Returns the normalised string and a
// flag indicating whether the result is non-empty. Invalid format
// (empty, missing or multi-`@`, embedded NUL/CR/LF) is the caller's
// responsibility — this helper only normalises; it does not validate.
//
// Governing: SPEC-0003 REQ "SASL PLAIN With user@host Identity".
// Case-insensitive comparison matches what most consumer mail clients
// expect (Apple Mail, Thunderbird treat email addresses as case-folded
// in the local part, even though RFC 5321 technically lets the local
// part be case-sensitive). For Reduit's use case — the operator owns
// the alias namespace — case-folding is the safe default.
func normalisePrimaryAlias(alias string) (string, bool) {
	trimmed := strings.TrimSpace(alias)
	if trimmed == "" {
		return "", false
	}
	return strings.ToLower(trimmed), true
}

// GetByPrimaryAlias implements Service.GetByPrimaryAlias.
func (s *service) GetByPrimaryAlias(ctx context.Context, alias string) (*Account, error) {
	norm, ok := normalisePrimaryAlias(alias)
	if !ok {
		return nil, ErrAccountNotFound
	}
	row, err := s.repo.getByPrimaryAlias(ctx, norm)
	if err != nil {
		return nil, err
	}
	return row.toAccount(), nil
}

// SetProtonIdentity implements Service.SetProtonIdentity. Empty
// protonUserID is treated as a programmer error (the wizard always
// has a value at the call site); empty email is permitted because
// some Proton accounts use a non-email login name.
//
// The read-compare guard that rejects a mismatching overwrite lives in
// the repository so the compare and the write share one transaction.
//
// Governing: SPEC-0001 REQ "Account Identity".
func (s *service) SetProtonIdentity(ctx context.Context, accountID, userID, protonUserID, email string) error {
	protonUserID = strings.TrimSpace(protonUserID)
	if protonUserID == "" {
		return errors.New("account: empty protonUserID")
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return errors.New("account: empty userID")
	}
	var emailNS sql.NullString
	if email = strings.TrimSpace(email); email != "" {
		emailNS = sql.NullString{String: email, Valid: true}
	}
	return s.repo.setProtonIdentity(ctx, accountID, userID, sql.NullString{String: protonUserID, Valid: true}, emailNS, s.now().UTC())
}

// SetPrimaryAlias implements Service.SetPrimaryAlias.
//
// Empty alias clears the column (NULL). The unique partial index on
// `primary_alias` permits multiple NULL values so unprovisioned
// accounts coexist freely.
func (s *service) SetPrimaryAlias(ctx context.Context, accountID, alias string) error {
	var stored sql.NullString
	if norm, ok := normalisePrimaryAlias(alias); ok {
		stored = sql.NullString{String: norm, Valid: true}
	}
	return s.repo.setPrimaryAlias(ctx, accountID, stored, s.now().UTC())
}

func (s *service) List(ctx context.Context) ([]*Account, error) {
	rows, err := s.repo.list(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*Account, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.toAccount())
	}
	return out, nil
}

// allowedTransitions is the explicit table of legal state changes per
// SPEC-0001's lifecycle diagram. Any pair not listed here returns
// ErrInvalidTransition. Soft-delete is reachable from every non-deleted
// state (see canSoftDelete below).
//
// Governing: SPEC-0001 REQ "Account Lifecycle States".
var allowedTransitions = map[State]map[State]bool{
	StatePendingProtonSetup: {
		StateActive:      true,
		StateSoftDeleted: true,
	},
	StateActive: {
		StateSuspended:   true,
		StateSoftDeleted: true,
		// SPEC-0002 REQ "Backoff on Failure" — refresh-token-revoked
		// kicks the account back to pending so the wizard can re-prompt
		// for credentials. Not present in the SPEC-0001 lifecycle
		// diagram; SPEC-0002 explicitly mandates this edge.
		StatePendingProtonSetup: true,
	},
	StateSuspended: {
		StateActive:      true,
		StateSoftDeleted: true,
	},
	StateSoftDeleted: {
		// terminal — no further transitions; retention sweep hard-deletes
	},
}

func transitionAllowed(from, to State) bool {
	allowed, ok := allowedTransitions[from]
	if !ok {
		return false
	}
	return allowed[to]
}

// Transition validates and persists a state change atomically. Validation
// is encoded as a `state IN (<allowed-prev-states>)` clause on the UPDATE
// so two racing callers cannot both move the same account from a single
// source state to two different targets — only one will see RowsAffected=1.
//
// Governing: SPEC-0001 REQ "Account Lifecycle States". The conditional
// UPDATE collapses read-validate-write into one atomic step, removing the
// TOCTOU window the original Go-side validation had.
func (s *service) Transition(ctx context.Context, id string, next State) (*Account, error) {
	if !next.Valid() {
		return nil, fmt.Errorf("%w: target state %q is not valid", ErrInvalidTransition, next)
	}
	allowedFrom := allowedPrevStates(next)
	if len(allowedFrom) == 0 {
		// next is a known state but unreachable (e.g. nothing transitions
		// INTO pending_proton_setup). We could short-circuit, but we still
		// want to distinguish missing-account from invalid-transition, so
		// fall through to the read below for the error message.
		if _, err := s.repo.getByID(ctx, id); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: target state %q has no legal predecessor", ErrInvalidTransition, next)
	}

	ok, prev, err := s.repo.transitionState(ctx, id, allowedFrom, next, s.now().UTC())
	if err != nil {
		return nil, err
	}
	if !ok {
		// Either the account does not exist, or its current state is not
		// a legal predecessor of `next`. Re-read to disambiguate.
		row, getErr := s.repo.getByID(ctx, id)
		if getErr != nil {
			return nil, getErr
		}
		current := State(row.State)
		if current == next {
			return nil, fmt.Errorf("%w: already in state %q", ErrInvalidTransition, current)
		}
		return nil, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, current, next)
	}
	updated, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	// Fire post-commit subscribers. Failures are logged-and-swallowed by
	// the dispatcher so a misbehaving subscriber cannot fail the
	// surrounding caller (whose write has already committed).
	//
	// Governing: SPEC-0002 REQ "One Worker Per Active Account" — the
	// sync supervisor consumes these notifications.
	s.fireTransition(ctx, prev, next, updated)
	return updated, nil
}

// allowedPrevStates is the inverse of allowedTransitions: given a
// target state, return every state legally allowed to precede it.
// Used by the conditional UPDATE in Transition.
func allowedPrevStates(next State) []State {
	var prev []State
	for from, tos := range allowedTransitions {
		if tos[next] {
			prev = append(prev, from)
		}
	}
	return prev
}

func (s *service) Delete(ctx context.Context, id string) (*Account, error) {
	return s.Transition(ctx, id, StateSoftDeleted)
}

// MarkCrashed flips the `crashed` flag on the account row. Idempotent:
// calling it on an already-crashed account is a no-op (the UPDATE
// matches the row but the column is already 1). Returns
// ErrAccountNotFound if no row matches the supplied ID.
//
// MarkCrashed deliberately does NOT change the lifecycle State; the
// account stays in whatever state it was in (typically StateActive)
// so an admin reset is a flag clear, not a state transition.
//
// Governing: SPEC-0002 REQ "Panic Isolation".
func (s *service) MarkCrashed(ctx context.Context, accountID string) error {
	return s.repo.markCrashed(ctx, accountID, s.now().UTC())
}

// SoftDeleteOldPending implements Service.SoftDeleteOldPending. The
// underlying repository UPDATE is unconditional on previous state
// other than `pending_proton_setup`, so it bypasses the per-row
// transitionState helper -- the sweep is a maintenance op that
// reasons in bulk and never needs to know the prior state of each
// row. We do NOT fire transition callbacks for swept rows: the
// supervisor only cares about transitions out of `active`, and
// pending rows have no worker to stop.
//
// Governing: SPEC-0001 REQ "Account Lifecycle States" (pending ->
// soft_deleted is a legal terminal transition); issue #82.
func (s *service) SoftDeleteOldPending(ctx context.Context, olderThan time.Duration) (int64, error) {
	if olderThan <= 0 {
		return 0, errors.New("account: SoftDeleteOldPending: olderThan must be positive")
	}
	now := s.now().UTC()
	cutoff := now.Add(-olderThan)
	return s.repo.softDeleteOldPending(ctx, cutoff, now)
}

// zeroDataKey best-effort wipes a data key from memory after use. Go
// gives us no hard guarantee against compiler reuse, but explicitly
// zeroing reduces the residency window.
func zeroDataKey(dk *cryptenv.DataKey) {
	for i := range dk {
		dk[i] = 0
	}
}

// OnTransition implements Service.OnTransition. The returned
// unsubscribe func is idempotent.
func (s *service) OnTransition(cb TransitionCallback) func() {
	if cb == nil {
		return func() {}
	}
	reg := &transitionReg{cb: cb}
	s.transitionMu.Lock()
	s.transitionCB[reg] = struct{}{}
	s.transitionMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			s.transitionMu.Lock()
			delete(s.transitionCB, reg)
			s.transitionMu.Unlock()
		})
	}
}

// fireTransition snapshots the current callback set under the read
// lock, releases the lock, and then invokes each callback synchronously.
// Snapshotting first means a callback that re-enters Service (e.g. by
// calling Get/Transition) cannot deadlock against the dispatcher's lock.
//
// Each callback is wrapped in a recover so a panicking subscriber can
// neither crash the caller of Transition nor prevent later subscribers
// from running.
func (s *service) fireTransition(ctx context.Context, prev, next State, account *Account) {
	s.transitionMu.RLock()
	if len(s.transitionCB) == 0 {
		s.transitionMu.RUnlock()
		return
	}
	cbs := make([]TransitionCallback, 0, len(s.transitionCB))
	for reg := range s.transitionCB {
		cbs = append(cbs, reg.cb)
	}
	s.transitionMu.RUnlock()

	for _, cb := range cbs {
		s.invokeTransitionCB(ctx, cb, prev, next, account)
	}
}

// invokeTransitionCB is split out so the deferred recover is per-cb and
// a panicking callback only cancels its own invocation.
func (s *service) invokeTransitionCB(ctx context.Context, cb TransitionCallback, prev, next State, account *Account) {
	defer func() {
		if r := recover(); r != nil {
			slog.Default().LogAttrs(ctx, slog.LevelError,
				"account transition callback panicked",
				slog.String("account_id", account.ID),
				slog.String("prev", string(prev)),
				slog.String("next", string(next)),
				slog.Any("panic", r),
				slog.String("stack", string(debug.Stack())),
			)
		}
	}()
	cb(ctx, prev, next, account)
}
