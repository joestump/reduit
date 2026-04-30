// Package account implements Reduit's account model.
//
// Governing: ADR-0002 (multi-tenant), ADR-0003 (envelope encryption),
// SPEC-0001 (Account Model).
package account

import (
	"slices"
	"time"
)

// State is the lifecycle state of an account, persisted as the `state`
// column. The set of legal values matches the SQLite CHECK constraint
// in the v0.1 accounts migration.
//
// Governing: SPEC-0001 REQ "Account Lifecycle States".
type State string

const (
	// StatePendingProtonSetup is the initial state after OIDC login but
	// before the Proton login wizard completes.
	StatePendingProtonSetup State = "pending_proton_setup"
	// StateActive means the account is fully provisioned and the sync
	// worker is running (or eligible to run).
	StateActive State = "active"
	// StateSuspended means an admin has paused the account; sync is
	// stopped and IMAP/SMTP authentication fails.
	StateSuspended State = "suspended"
	// StateSoftDeleted means the account is awaiting hard-delete by the
	// retention sweep job; ciphertexts are preserved for audit.
	StateSoftDeleted State = "soft_deleted"
)

// Valid reports whether s is one of the four canonical states.
func (s State) Valid() bool {
	switch s {
	case StatePendingProtonSetup, StateActive, StateSuspended, StateSoftDeleted:
		return true
	}
	return false
}

// Account is the in-memory projection of one row of the `accounts`
// table. Sensitive ciphertext columns are NOT exposed on this struct —
// callers must round-trip through the Service's Seal*/Open* helpers,
// which take care of unsealing the per-account data key from
// `KeyEnvelope` and discarding it after the operation.
//
// Governing: SPEC-0001 REQ "Per-Account Data Key" (data key never
// persists in plaintext), SPEC-0001 REQ "Encrypted Secret Storage".
type Account struct {
	ID                   string
	OIDCSubject          string
	ProtonUserID         string
	Email                string
	State                State
	IsAdmin              bool
	KeyEnvelope          []byte
	HasRefreshToken      bool
	HasMailboxPassphrase bool
	HasIMAPPassword      bool
	IMAPPasswordHash     string
	LastEventID          string
	Crashed              bool
	CreatedAt            time.Time
	UpdatedAt            time.Time
	DeletedAt            *time.Time
}

// IsAdmin reports whether the given OIDC subject appears in the admin
// allowlist (the `OIDC_ADMIN_SUBS` config). Comparison is exact and
// case-sensitive — Pocket ID and most OIDC providers issue opaque
// subjects so case-insensitivity would be unsafe.
//
// Governing: SPEC-0001 REQ "Admin Flag".
func (a Account) AdminBy(adminSubs []string) bool {
	if a.OIDCSubject == "" {
		return false
	}
	return slices.Contains(adminSubs, a.OIDCSubject)
}
