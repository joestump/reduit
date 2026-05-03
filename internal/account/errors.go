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
