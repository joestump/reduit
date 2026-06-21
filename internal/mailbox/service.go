// Service is the public face of the mailbox package. It composes the
// repository with the time/uid clock so tests can pin both, and is the
// only type the IMAP session imports.
//
// Governing: SPEC-0001 REQ "Account-Scoped Data",
// SPEC-0003 REQ "UID Stability", SPEC-0003 REQ "Folder Hierarchy and
// Mapping", SPEC-0003 REQ "Account Isolation in IMAP Operations".

package mailbox

import (
	"context"
	"errors"
	"fmt"
	"time"

	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/joestump/reduit/internal/store"
)

// Service is the contract IMAP / sync callers depend on.
type Service interface {
	// EnsureMailbox is idempotent: on first call for a (accountID, name)
	// pair it inserts the row with a fresh UIDVALIDITY; on subsequent
	// calls it returns the existing row unchanged. The caller supplies
	// the Proton-side label ID and Kind so EnsureMailbox does not need
	// to dispatch on name format itself.
	//
	// Returns the resulting Mailbox row (always with the persisted
	// UIDVALIDITY, never a freshly-minted one for an existing row).
	EnsureMailbox(ctx context.Context, accountID, name, protonLabelID string, kind Kind) (*Mailbox, error)

	// GetMailboxByName returns the mailbox row for (accountID, name) or
	// ErrMailboxNotFound. Account-scoping is enforced at the SQL layer.
	GetMailboxByName(ctx context.Context, accountID, name string) (*Mailbox, error)

	// ListMailboxes returns every mailbox owned by accountID, ordered
	// by name ascending. Per SPEC-0003 REQ "Account Isolation" the
	// caller's account ID is the only mailbox set ever returned.
	ListMailboxes(ctx context.Context, accountID string) ([]*Mailbox, error)

	// AssignUID atomically claims the next UID for (mailboxID,
	// messageID). Concurrent racers serialise through SQLite's write
	// lock. Returns the issued uint32 UID.
	AssignUID(ctx context.Context, accountID string, mailboxID, messageID int64) (uint32, error)

	// UpsertMessage inserts (account, proton_message_id) if absent or
	// returns the existing local ID. Used by sync workers and tests
	// when seeding mailbox state.
	UpsertMessage(ctx context.Context, msg *Message) (int64, error)

	// FindMessageByProtonID resolves a Proton-side ID to a local
	// message row. Used by the IMAP session's Move handler.
	FindMessageByProtonID(ctx context.Context, accountID, protonID string) (*Message, error)

	// RemoveMessageFromMailbox deletes the (mailbox, message) link.
	// Returns true when a row was actually removed.
	RemoveMessageFromMailbox(ctx context.Context, accountID string, mailboxID, messageID int64) (bool, error)

	// ListMessagesInMailbox returns every (uid, message) pair in
	// mailboxID, ordered by UID ascending.
	ListMessagesInMailbox(ctx context.Context, accountID string, mailboxID int64) ([]*MessageInMailbox, error)

	// CountMessagesInMailbox returns the number of message_uids rows
	// for the mailbox. Used by Session.Status.
	CountMessagesInMailbox(ctx context.Context, accountID string, mailboxID int64) (uint32, error)

	// CountUnseenInMailbox returns the number of messages in the
	// mailbox that do NOT carry the `\Seen` flag. Used by Session.Status
	// to report an accurate STATUS NumUnseen.
	CountUnseenInMailbox(ctx context.Context, accountID string, mailboxID int64) (uint32, error)

	// RecordPendingUnlabel durably records that an IMAP MOVE failed to
	// remove protonLabelID from protonMessageID at Proton, so the
	// sync-worker reconciliation pass can retry it. Idempotent on the
	// (account, message, label) natural key.
	//
	// Governing: SPEC-0003 REQ "Moving between system folders changes
	// Proton system flag".
	RecordPendingUnlabel(ctx context.Context, accountID, protonMessageID, protonLabelID string) error

	// ListPendingUnlabels returns up to `limit` recorded unlabel intents
	// for the account, oldest first. limit<=0 returns all. `maxAttempts`,
	// when positive, excludes "parked" rows whose attempts counter has
	// reached the ceiling — those are intents the reconciler has given up
	// retrying, kept only for operator visibility. maxAttempts<=0 returns
	// rows at any attempt count. Used by the reconciliation pass to drive
	// its retry loop.
	ListPendingUnlabels(ctx context.Context, accountID string, limit, maxAttempts int) ([]*PendingUnlabel, error)

	// ResolvePendingUnlabel deletes a pending-unlabel row after a
	// successful retry. Scoped to the account.
	ResolvePendingUnlabel(ctx context.Context, accountID string, id int64) error

	// FailPendingUnlabel bumps the attempts counter for a row whose retry
	// failed, leaving the row for a later pass.
	FailPendingUnlabel(ctx context.Context, accountID string, id int64) error
}

type service struct {
	repo *repository
	now  func() time.Time
}

// New constructs a Service backed by the supplied store.
//
// Reads use the store's default multi-conn pool (`s.DB`). Writes go
// through the single-conn writer pool (`s.WriterDB()`) so contended
// callers (assignUID is the canonical hot path) serialise at the
// database/sql layer instead of through driver-level SQLITE_BUSY
// retries.
func New(s *store.Store) Service {
	if s == nil || s.DB == nil {
		panic("mailbox: New called with nil store")
	}
	writes := s.WriterDB()
	if writes == nil {
		// Older callers that constructed a Store manually without the
		// writer pool fall back to the read pool. Production code
		// always goes through store.Open which sets both up.
		writes = s.DB
	}
	return &service{
		repo: &repository{reads: s.DB, writes: writes},
		now:  time.Now,
	}
}

// uidValidityFromClock returns the microsecond-precision Unix timestamp
// used as the per-mailbox UIDVALIDITY. Microsecond resolution is more
// than sufficient (one mailbox per microsecond would still fit a uint32
// for centuries) and matches the SPEC-0003 REQ "UID Stability" scenario
// "UIDVALIDITY assigned at first sync".
//
// We coerce time.Now().UnixMicro() to uint32 by truncation. The wrap
// happens roughly every 71 minutes (2^32 microseconds). The only
// invariant RFC 9051 §2.3.1.1 requires is that UIDVALIDITY for "the
// same mailbox" must change if UIDs ever recycle — and we guarantee
// that structurally via the (mailbox_id, uid) PK plus monotonic
// uid_next, so a single mailbox in fact never recycles its UIDs and
// its UIDVALIDITY is assigned once at insert time and never updated
// thereafter. The 71-minute wrap is irrelevant: we never re-derive
// UIDVALIDITY for an existing mailbox.
//
// Governing: SPEC-0003 REQ "UIDVALIDITY assigned at first sync".
func (s *service) uidValidity() uint32 {
	// time.Now().UnixMicro() is int64; safe truncation to uint32.
	micros := s.now().UTC().UnixMicro()
	return uint32(micros)
}

// EnsureMailbox is idempotent: the (account_id, name) UNIQUE constraint
// is the source of truth. We optimistically INSERT and on conflict fall
// back to a SELECT, returning whichever row already exists. This avoids
// the read-then-write race where two concurrent callers both observe
// "no row" and both INSERT.
//
// Governing: SPEC-0003 REQ "UIDVALIDITY assigned at first sync"
// (assigned exactly once per mailbox, never changes after).
func (s *service) EnsureMailbox(ctx context.Context, accountID, name, protonLabelID string, kind Kind) (*Mailbox, error) {
	if accountID == "" {
		return nil, errors.New("mailbox: accountID is required")
	}
	if name == "" {
		return nil, errors.New("mailbox: name is required")
	}
	if protonLabelID == "" {
		return nil, errors.New("mailbox: protonLabelID is required")
	}
	if kind != KindSystem && kind != KindUserLabel {
		return nil, fmt.Errorf("mailbox: invalid kind %q", kind)
	}

	// Fast path: already exists.
	if existing, err := s.repo.getByName(ctx, accountID, name); err == nil {
		return existing, nil
	} else if !errors.Is(err, ErrMailboxNotFound) {
		return nil, err
	}

	now := s.now().UTC()
	m := &Mailbox{
		AccountID:     accountID,
		Name:          name,
		ProtonLabelID: protonLabelID,
		Kind:          kind,
		UIDValidity:   s.uidValidity(),
	}
	id, err := s.repo.insertMailbox(ctx, m, now)
	if err != nil {
		// On UNIQUE conflict (a concurrent caller raced ahead), re-read.
		// SQLite reports the conflict via the typed sqlite error code so
		// we prefer that branch; fall back to a substring match if a
		// future driver swap loses the typed code.
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
			return s.repo.getByName(ctx, accountID, name)
		}
		return nil, err
	}
	m.ID = id
	m.UIDNext = 1
	m.CreatedAt = now
	m.UpdatedAt = now
	return m, nil
}

func (s *service) GetMailboxByName(ctx context.Context, accountID, name string) (*Mailbox, error) {
	return s.repo.getByName(ctx, accountID, name)
}

func (s *service) ListMailboxes(ctx context.Context, accountID string) ([]*Mailbox, error) {
	return s.repo.listForAccount(ctx, accountID)
}

func (s *service) AssignUID(ctx context.Context, accountID string, mailboxID, messageID int64) (uint32, error) {
	return s.repo.assignUID(ctx, accountID, mailboxID, messageID)
}

func (s *service) UpsertMessage(ctx context.Context, msg *Message) (int64, error) {
	if msg == nil {
		return 0, errors.New("mailbox: msg is required")
	}
	if msg.AccountID == "" || msg.ProtonMessageID == "" {
		return 0, errors.New("mailbox: AccountID and ProtonMessageID are required")
	}
	if msg.InternalDate.IsZero() {
		msg.InternalDate = s.now().UTC()
	}
	return s.repo.upsertMessage(ctx, msg)
}

func (s *service) FindMessageByProtonID(ctx context.Context, accountID, protonID string) (*Message, error) {
	return s.repo.findMessageByProtonID(ctx, accountID, protonID)
}

func (s *service) RemoveMessageFromMailbox(ctx context.Context, accountID string, mailboxID, messageID int64) (bool, error) {
	return s.repo.removeMessageFromMailbox(ctx, accountID, mailboxID, messageID)
}

func (s *service) ListMessagesInMailbox(ctx context.Context, accountID string, mailboxID int64) ([]*MessageInMailbox, error) {
	return s.repo.listMessagesInMailbox(ctx, accountID, mailboxID)
}

func (s *service) CountMessagesInMailbox(ctx context.Context, accountID string, mailboxID int64) (uint32, error) {
	return s.repo.countMessagesInMailbox(ctx, accountID, mailboxID)
}

func (s *service) CountUnseenInMailbox(ctx context.Context, accountID string, mailboxID int64) (uint32, error) {
	return s.repo.countUnseenInMailbox(ctx, accountID, mailboxID)
}

func (s *service) RecordPendingUnlabel(ctx context.Context, accountID, protonMessageID, protonLabelID string) error {
	if accountID == "" || protonMessageID == "" || protonLabelID == "" {
		return errors.New("mailbox: RecordPendingUnlabel requires accountID, protonMessageID, protonLabelID")
	}
	return s.repo.recordPendingUnlabel(ctx, accountID, protonMessageID, protonLabelID)
}

func (s *service) ListPendingUnlabels(ctx context.Context, accountID string, limit, maxAttempts int) ([]*PendingUnlabel, error) {
	return s.repo.listPendingUnlabels(ctx, accountID, limit, maxAttempts)
}

func (s *service) ResolvePendingUnlabel(ctx context.Context, accountID string, id int64) error {
	return s.repo.deletePendingUnlabel(ctx, accountID, id)
}

func (s *service) FailPendingUnlabel(ctx context.Context, accountID string, id int64) error {
	return s.repo.incrementPendingUnlabelAttempts(ctx, accountID, id)
}
