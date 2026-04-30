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
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/store"
)

// Service is the contract every consumer (HTTP handlers, sync worker,
// IMAP/SMTP servers, MCP tools) talks to.
type Service interface {
	// Create mints a new account row for the given OIDC subject. It
	// generates a fresh per-account data key, seals it under the master
	// key, and persists the envelope. Returns ErrAccountAlreadyExists
	// when the OIDC subject is already taken.
	Create(ctx context.Context, params CreateParams) (*Account, error)

	// GetByOIDCSubject returns the account for the given OIDC `sub`
	// claim, or ErrAccountNotFound.
	GetByOIDCSubject(ctx context.Context, sub string) (*Account, error)

	// GetByID returns the account with the given ID, or
	// ErrAccountNotFound.
	GetByID(ctx context.Context, id string) (*Account, error)

	// Transition validates and persists a state change. Illegal
	// transitions return ErrInvalidTransition.
	Transition(ctx context.Context, id string, next State) (*Account, error)

	// List returns every account, ordered by creation time ascending.
	List(ctx context.Context) ([]*Account, error)

	// Delete is a convenience for `Transition(ctx, id, StateSoftDeleted)`.
	// Hard deletion is the responsibility of the retention sweep job.
	Delete(ctx context.Context, id string) (*Account, error)

	// IsAdmin reports whether the given account's OIDC subject is on
	// the configured admin allowlist.
	IsAdmin(a *Account) bool

	// SealRefreshToken seals plaintext under the account's data key
	// (fresh nonce per call) and persists the ciphertext.
	SealRefreshToken(ctx context.Context, accountID string, plaintext []byte) error

	// OpenRefreshToken returns the plaintext refresh token for the
	// account, or an error if no token has been stored.
	OpenRefreshToken(ctx context.Context, accountID string) ([]byte, error)

	// UpdateRefreshToken is an alias for SealRefreshToken intended for
	// external callers (e.g. internal/proton's RefreshTokenSaver
	// callback) that already have the freshly-sealed bytes — except in
	// our case we always seal here so that the data key never leaves
	// the account package. Plaintext in, sealed-on-disk out.
	UpdateRefreshToken(ctx context.Context, accountID string, plaintext []byte) error

	SealMailboxPassphrase(ctx context.Context, accountID string, plaintext []byte) error
	OpenMailboxPassphrase(ctx context.Context, accountID string) ([]byte, error)

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
}

// CreateParams collects the inputs to Service.Create. ProtonUserID
// and Email are optional at create time — they are filled in by the
// Proton login wizard once it completes.
type CreateParams struct {
	OIDCSubject  string
	ProtonUserID string
	Email        string
}

type service struct {
	repo      *repository
	master    cryptenv.MasterKey
	adminSubs []string
	now       func() time.Time
	newID     func() (string, error)
}

// New constructs a Service backed by the given store, master key, and
// admin allowlist. The Service does not take ownership of the store —
// the caller closes it.
func New(s *store.Store, master cryptenv.MasterKey, adminSubs []string) Service {
	if s == nil || s.DB == nil {
		panic("account: New called with nil store")
	}
	subs := make([]string, len(adminSubs))
	copy(subs, adminSubs)
	return &service{
		repo:      &repository{db: s.DB},
		master:    master,
		adminSubs: subs,
		now:       time.Now,
		newID:     newUUIDv7,
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
// Governing: SPEC-0001 REQ "Account Identity" (UUIDv7 + OIDC uniqueness),
// SPEC-0001 REQ "Per-Account Data Key" (fresh data key, sealed envelope),
// SPEC-0001 REQ "Admin Flag" (is_admin set from allowlist at create time).
func (s *service) Create(ctx context.Context, params CreateParams) (*Account, error) {
	if params.OIDCSubject == "" {
		return nil, errors.New("account: OIDCSubject is required")
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
		OIDCSubject: params.OIDCSubject,
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
	if slices.Contains(s.adminSubs, params.OIDCSubject) {
		row.IsAdmin = 1
	}

	if err := s.repo.insert(ctx, row); err != nil {
		return nil, err
	}
	return row.toAccount(), nil
}

func (s *service) GetByOIDCSubject(ctx context.Context, sub string) (*Account, error) {
	row, err := s.repo.getByOIDCSubject(ctx, sub)
	if err != nil {
		return nil, err
	}
	return row.toAccount(), nil
}

func (s *service) GetByID(ctx context.Context, id string) (*Account, error) {
	row, err := s.repo.getByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return row.toAccount(), nil
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

func (s *service) Transition(ctx context.Context, id string, next State) (*Account, error) {
	if !next.Valid() {
		return nil, fmt.Errorf("%w: target state %q is not valid", ErrInvalidTransition, next)
	}
	row, err := s.repo.getByID(ctx, id)
	if err != nil {
		return nil, err
	}
	current := State(row.State)
	if current == next {
		return nil, fmt.Errorf("%w: already in state %q", ErrInvalidTransition, current)
	}
	if !transitionAllowed(current, next) {
		return nil, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, current, next)
	}
	if err := s.repo.updateState(ctx, id, next, s.now().UTC()); err != nil {
		return nil, err
	}
	return s.GetByID(ctx, id)
}

func (s *service) Delete(ctx context.Context, id string) (*Account, error) {
	return s.Transition(ctx, id, StateSoftDeleted)
}

func (s *service) IsAdmin(a *Account) bool {
	if a == nil {
		return false
	}
	return slices.Contains(s.adminSubs, a.OIDCSubject)
}

// zeroDataKey best-effort wipes a data key from memory after use. Go
// gives us no hard guarantee against compiler reuse, but explicitly
// zeroing reduces the residency window.
func zeroDataKey(dk *cryptenv.DataKey) {
	for i := range dk {
		dk[i] = 0
	}
}
