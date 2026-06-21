// Package notify implements Reduit's admin-notification surface: a
// minimal, persisted per-account record of operator-facing events the
// sync worker (or any future subsystem) needs to actively surface
// rather than burying in a log line.
//
// The motivating cases are SPEC-0002's silent-failure paths: a sync
// worker panic (which sets the account's `crashed` flag) and the
// permanent-error auto-revert to pending_proton_setup. Both already
// change account state, but nothing tells the operator WHY. A
// notification row carries that "why" to the admin UI.
//
// Governing: SPEC-0002 REQ "Panic Isolation" (worker crash must surface
// to an operator), SPEC-0002 REQ "Backoff on Failure" (permanent-error
// auto-revert emits an admin notification), SPEC-0001 REQ
// "Account-Scoped Data".
package notify

import (
	"context"
	"time"
)

// Kind enumerates the operator-facing events recorded as notifications.
// The set is mirrored by the CHECK constraint in the
// admin_notifications migration; adding a Kind requires a migration.
type Kind string

const (
	// KindWorkerCrashed records that a sync worker goroutine panicked and
	// was recovered. The account's `crashed` flag is set in the same
	// recovery path; this notification carries the panic detail so the
	// operator knows what to investigate before clearing the flag.
	//
	// Governing: SPEC-0002 REQ "Panic Isolation".
	KindWorkerCrashed Kind = "worker_crashed"

	// KindAutoReverted records that the sync worker automatically
	// reverted the account to pending_proton_setup after a permanent
	// authorization failure (refresh token revoked / 401, or an
	// unrecoverable 403). The operator must re-run the wizard.
	//
	// Governing: SPEC-0002 REQ "Backoff on Failure"
	// ("Permanent errors do not retry indefinitely").
	KindAutoReverted Kind = "auto_reverted"
)

// Valid reports whether k is one of the canonical kinds.
func (k Kind) Valid() bool {
	switch k {
	case KindWorkerCrashed, KindAutoReverted:
		return true
	}
	return false
}

// Notification is the in-memory projection of one admin_notifications
// row. AcknowledgedAt is nil until an operator dismisses it.
type Notification struct {
	ID             string
	AccountID      string
	Kind           Kind
	Message        string
	Detail         string
	CreatedAt      time.Time
	AcknowledgedAt *time.Time
}

// Recorder is the narrow write surface a producer (the sync worker)
// needs: append one notification. It is split out from the full Service
// so producers depend only on the verb they use, and so the sync
// package can accept a one-method interface that a test can stub
// without a database.
//
// Governing: SPEC-0002 REQ "Panic Isolation", REQ "Backoff on Failure".
type Recorder interface {
	// Record appends a notification for accountID. A non-Valid kind or
	// empty accountID returns an error. The returned *Notification
	// carries the generated ID and CreatedAt.
	Record(ctx context.Context, accountID string, kind Kind, message, detail string) (*Notification, error)
}

// Service is the full notification surface: the write verb plus the
// read/acknowledge verbs the admin UI consumes.
type Service interface {
	Recorder

	// ListUnacknowledged returns every unacknowledged notification,
	// newest first, capped at limit (<= 0 means a sane default). Backs
	// the admin UI's notification list + badge.
	ListUnacknowledged(ctx context.Context, limit int) ([]*Notification, error)

	// CountUnacknowledged returns the number of unacknowledged
	// notifications across all accounts. Backs the admin nav badge.
	CountUnacknowledged(ctx context.Context) (int, error)

	// Acknowledge marks a single notification acknowledged (dismissed).
	// Idempotent: acknowledging an already-acknowledged row is a no-op.
	// Returns ErrNotFound when no row matches.
	Acknowledge(ctx context.Context, id string) error
}
