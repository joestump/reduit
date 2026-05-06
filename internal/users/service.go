// Service is the public face of the users package. It composes a
// repository and the ID + clock factories that tests need to swap.
//
// Governing: ADR-0010 (multi-Proton-account per user), SPEC-0001 REQ
// "User Identity", SPEC-0001 REQ "User Lifecycle".
package users

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/joestump/reduit/internal/store"
)

// UpsertParams collects the inputs to Service.Upsert. Email and
// DisplayName are optional ID-token claims -- empty values are
// preserved on update (the existing column value is kept) so a
// misbehaving IdP cannot silently erase user data by dropping a
// claim on a subsequent login.
type UpsertParams struct {
	OIDCSubject string
	Email       string
	DisplayName string
}

// Service is the contract OIDC callback handlers and account
// service callers depend on.
type Service interface {
	// Upsert returns the user for the given OIDC subject, creating it
	// on first sight and refreshing last_login_at + claim fields on
	// every subsequent call. Concurrent first logins for the same
	// subject collapse to a single row -- the second caller observes
	// the row created by the first.
	//
	// May return ErrUserNotFound if a concurrent caller deletes the
	// user row between Upsert's internal lookup and update. This is
	// the only situation where Upsert -- whose contract is "create
	// or refresh" -- can surface a not-found error; the window is
	// narrow (operator-initiated mid-login deletion runs under
	// SQLite's per-DB write lock) but real, and handlers that see
	// it SHOULD retry once before propagating the error to the
	// caller.
	//
	// Governing: SPEC-0005 REQ "OIDC Login Flow" (callback upsert),
	// SPEC-0001 REQ "User Identity".
	Upsert(ctx context.Context, params UpsertParams) (*User, error)

	// GetByOIDCSubject returns the user for the given OIDC `sub`
	// claim, or ErrUserNotFound. Used by handlers that need to
	// resolve a session's OIDC subject back to a user_id without
	// taking the upsert write path.
	GetByOIDCSubject(ctx context.Context, sub string) (*User, error)

	// GetByID returns the user with the given ID, or ErrUserNotFound.
	// Used by handlers that already know the user_id from the bound
	// session.
	GetByID(ctx context.Context, id string) (*User, error)

	// List returns every user, ordered by creation time ascending.
	// Used by the admin "manage users" view (when one exists) and
	// by tests that need a deterministic enumeration.
	List(ctx context.Context) ([]*User, error)
}

type service struct {
	repo  *repository
	now   func() time.Time
	newID func() (string, error)
}

// New constructs a Service backed by the given store. The Service
// does not take ownership of the store -- the caller closes it.
func New(s *store.Store) Service {
	if s == nil || s.DB == nil {
		panic("users: New called with nil store")
	}
	return &service{
		repo:  &repository{db: s.DB},
		now:   time.Now,
		newID: newUUIDv7,
	}
}

// uuid.NewV7 returns (UUID, error); wrapped here so the service holds
// a single-arity factory that's easy to swap in tests.
func newUUIDv7() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("users: uuidv7: %w", err)
	}
	return id.String(), nil
}

func (s *service) Upsert(ctx context.Context, params UpsertParams) (*User, error) {
	sub := strings.TrimSpace(params.OIDCSubject)
	if sub == "" {
		return nil, errors.New("users: OIDCSubject is required")
	}
	email := strings.TrimSpace(params.Email)
	displayName := strings.TrimSpace(params.DisplayName)
	now := s.now().UTC()

	// Lookup-then-insert. The window between the SELECT and INSERT is
	// the race surface; the unique constraint on oidc_subject is the
	// safety net. On constraint failure we fall back to a re-read of
	// the row the racing caller wrote, which collapses concurrent
	// first logins for the same subject to a single canonical row.
	if existing, err := s.repo.getByOIDCSubject(ctx, sub); err == nil {
		if err := s.repo.updateLogin(ctx, existing.ID, email, displayName, now); err != nil {
			return nil, err
		}
		// Re-read so the caller sees the merged claim set the
		// repository's COALESCE produced.
		updated, err := s.repo.getByID(ctx, existing.ID)
		if err != nil {
			return nil, err
		}
		return updated.toUser(), nil
	} else if !errors.Is(err, ErrUserNotFound) {
		return nil, err
	}

	id, err := s.newID()
	if err != nil {
		return nil, err
	}
	row := &userRow{
		ID:          id,
		OIDCSubject: sub,
		CreatedAt:   now,
		LastLoginAt: now,
	}
	if email != "" {
		row.Email = sql.NullString{String: email, Valid: true}
	}
	if displayName != "" {
		row.DisplayName = sql.NullString{String: displayName, Valid: true}
	}
	if err := s.repo.insert(ctx, row); err != nil {
		// Race lost -- another caller inserted between our SELECT
		// and INSERT. Re-read the canonical row and apply the login
		// update against it so the timestamps reflect this attempt
		// rather than the racer's.
		if existing, lookupErr := s.repo.getByOIDCSubject(ctx, sub); lookupErr == nil {
			if upErr := s.repo.updateLogin(ctx, existing.ID, email, displayName, now); upErr != nil {
				return nil, upErr
			}
			refreshed, refreshErr := s.repo.getByID(ctx, existing.ID)
			if refreshErr != nil {
				return nil, refreshErr
			}
			return refreshed.toUser(), nil
		}
		return nil, err
	}
	return row.toUser(), nil
}

func (s *service) GetByOIDCSubject(ctx context.Context, sub string) (*User, error) {
	sub = strings.TrimSpace(sub)
	if sub == "" {
		return nil, ErrUserNotFound
	}
	row, err := s.repo.getByOIDCSubject(ctx, sub)
	if err != nil {
		return nil, err
	}
	return row.toUser(), nil
}

func (s *service) GetByID(ctx context.Context, id string) (*User, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, ErrUserNotFound
	}
	row, err := s.repo.getByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return row.toUser(), nil
}

func (s *service) List(ctx context.Context) ([]*User, error) {
	rows, err := s.repo.listAll(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*User, len(rows))
	for i, r := range rows {
		out[i] = r.toUser()
	}
	return out, nil
}
