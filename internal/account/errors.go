// Package account implements Reduit's account model and the service +
// repository that own its persistence and crypto.
//
// Governing: ADR-0002 (multi-tenant), ADR-0003 (envelope encryption),
// ADR-0010 (multi-Proton-account per user), SPEC-0001 (Account Model).
package account

import "errors"

// ErrAccountAlreadyExists is returned by Service.Create when a user
// already owns an account for the supplied Proton user id. The
// underlying constraint is `UNIQUE (user_id, proton_user_id)` in the
// accounts migration -- per-user, not global. Two users may relay the
// same Proton mailbox from different deployments; one user MUST NOT
// add the same Proton account twice.
//
// At create time `proton_user_id` may be NULL (the wizard creates the
// row in `pending_proton_setup` before the Proton login completes);
// SQLite treats NULL as distinct under UNIQUE, so two pending wizards
// for the same user are allowed. The collision becomes observable
// when the wizard updates `proton_user_id` against an active row that
// already carries the same Proton id for the user.
//
// Governing: ADR-0010, SPEC-0001 REQ "Account Identity".
var ErrAccountAlreadyExists = errors.New("account: already exists")

// ErrAccountNotFound is returned when a lookup matches no row. It
// distinguishes "not present" from generic database errors so callers
// can render 404s and avoid leaking detail.
var ErrAccountNotFound = errors.New("account: not found")

// ErrInvalidTransition is returned by Service.Transition when the
// requested next state is not reachable from the account's current
// state per the SPEC-0001 lifecycle diagram.
//
// Governing: SPEC-0001 REQ "Account Lifecycle States".
var ErrInvalidTransition = errors.New("account: invalid state transition")

// ErrProtonIdentityMismatch is returned by SetProtonIdentity when the
// account row already carries a non-empty proton_user_id that differs
// from the incoming value. SPEC-0001 REQ "Account Identity" mandates
// that a subsequent login observing a different Proton user ID is an
// error and MUST NOT silently overwrite the stored value -- otherwise
// a re-login against the wrong Proton mailbox could silently re-point
// an existing account at a different identity. Setting the column from
// empty (first login) or to the identical value (idempotent re-login)
// is allowed and does NOT return this error.
//
// This is distinct from ErrAccountAlreadyExists: the latter fires when
// the SAME Proton id is already bound to ANOTHER row owned by the user
// (the unique index trips); this fires when a DIFFERENT Proton id is
// being written over THIS row's existing identity.
//
// Governing: SPEC-0001 REQ "Account Identity".
var ErrProtonIdentityMismatch = errors.New("account: proton identity mismatch")

// ErrMasterKeyMismatch is returned by RewrapEnvelopes when the supplied
// "old" master key fails to unseal an existing account's key_envelope.
// It is the mismatched-key guard for `master-key rotate`: rotation
// refuses to proceed (and rolls back) if the key it loaded from disk is
// not the key the stored envelopes were actually sealed under, so a
// stale or wrong key file can never corrupt the envelope column.
//
// Governing: ADR-0003 (service-master-key envelope encryption); #50.
var ErrMasterKeyMismatch = errors.New("account: master key does not match stored envelopes")
