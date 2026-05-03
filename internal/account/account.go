// Package account implements Reduit's account model.
//
// Governing: ADR-0002 (multi-tenant), ADR-0003 (envelope encryption),
// ADR-0010 (multi-Proton-account per user), SPEC-0001 (Account Model).
package account

import (
	"time"
)

// State is the lifecycle state of an account, persisted as the `state`
// column. The set of legal values matches the SQLite CHECK constraint
// in the v0.1 accounts migration.
//
// Governing: SPEC-0001 REQ "Account Lifecycle States".
type State string

const (
	// StatePendingProtonSetup is the initial state after the wizard
	// creates the row but before Proton login completes.
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
// Per ADR-0010, ownership flows through UserID (FK to users.id). The
// previous shape carried oidc_subject directly on the account row;
// callers that need the OIDC subject for an account now resolve it via
// users.GetByID(account.UserID). Admin status is NOT a property of the
// account -- it is computed at session-bind time from OIDC_ADMIN_SUBS
// per SPEC-0001 REQ "Admin Status".
//
// Governing: SPEC-0001 REQ "Account Identity", SPEC-0001 REQ
// "Per-Account Data Key", SPEC-0001 REQ "Encrypted Secret Storage".
type Account struct {
	ID                   string
	UserID               string
	ProtonUserID         string
	Email                string
	State                State
	KeyEnvelope          []byte
	HasRefreshToken      bool
	HasMailboxPassphrase bool
	HasIMAPPassword      bool
	IMAPPasswordHash     string
	// PrimaryAlias is the canonical `local@host` form clients use as
	// the SASL PLAIN identity. NULL/empty means the account has not
	// yet been provisioned with an alias and SASL lookups will fail.
	//
	// Governing: SPEC-0003 REQ "SASL PLAIN With user@host Identity".
	PrimaryAlias string
	LastEventID  string
	Crashed      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time
}
