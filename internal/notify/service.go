// Service implementation for the admin-notification surface.
//
// Governing: SPEC-0002 REQ "Panic Isolation", SPEC-0002 REQ "Backoff on
// Failure", SPEC-0001 REQ "Account-Scoped Data".
package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/joestump/reduit/internal/store"
)

// ErrNotFound is returned by Acknowledge when no notification row
// matches the supplied id.
var ErrNotFound = errors.New("notify: notification not found")

// DefaultListLimit caps ListUnacknowledged when the caller passes a
// non-positive limit. The admin surface shows a short, scannable list;
// a runaway crash loop should not render thousands of rows.
const DefaultListLimit = 50

type service struct {
	repo  *repository
	now   func() time.Time
	newID func() (string, error)
}

// New constructs a notify.Service backed by the given store. Panics if
// the store (or its DB) is nil -- this is a boot-time wiring call and a
// missing store is a programmer error the caller cannot recover from,
// matching account.New's contract.
func New(s *store.Store) Service {
	if s == nil || s.DB == nil {
		panic("notify: New called with nil store")
	}
	return &service{
		repo:  &repository{db: s.DB},
		now:   time.Now,
		newID: newUUIDv7,
	}
}

func newUUIDv7() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("notify: uuidv7: %w", err)
	}
	return id.String(), nil
}

// Record implements Recorder.
func (s *service) Record(ctx context.Context, accountID string, kind Kind, message, detail string) (*Notification, error) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return nil, errors.New("notify: accountID is required")
	}
	if !kind.Valid() {
		return nil, fmt.Errorf("notify: invalid kind %q", kind)
	}
	id, err := s.newID()
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	n := &Notification{
		ID:        id,
		AccountID: accountID,
		Kind:      kind,
		Message:   message,
		Detail:    detail,
		CreatedAt: now,
	}
	if err := s.repo.insert(ctx, n); err != nil {
		return nil, err
	}
	return n, nil
}

// ListUnacknowledged implements Service.
func (s *service) ListUnacknowledged(ctx context.Context, limit int) ([]*Notification, error) {
	if limit <= 0 {
		limit = DefaultListLimit
	}
	return s.repo.listUnacknowledged(ctx, limit)
}

// CountUnacknowledged implements Service.
func (s *service) CountUnacknowledged(ctx context.Context) (int, error) {
	return s.repo.countUnacknowledged(ctx)
}

// Acknowledge implements Service.
func (s *service) Acknowledge(ctx context.Context, id string) error {
	return s.repo.acknowledge(ctx, id, s.now().UTC())
}
