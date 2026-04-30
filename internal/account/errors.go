// Package account implements Reduit's account model and the service +
// repository that own its persistence and crypto.
//
// Governing: ADR-0002 (multi-tenant), ADR-0003 (envelope encryption),
// SPEC-0001 (Account Model).
package account

import "errors"

// ErrAccountAlreadyExists is returned by Service.Create when a row for
// the given OIDC subject already exists. The unique constraint on
// `accounts(oidc_subject)` is enforced at the SQLite layer (see the
// v0.1 migration); this sentinel surfaces that constraint to callers.
//
// Governing: SPEC-0001 REQ "Account Identity".
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
