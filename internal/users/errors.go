package users

import "errors"

// ErrUserNotFound is returned by GetByOIDCSubject and GetByID when
// no matching row exists. Callers MUST check for this error
// explicitly so the OIDC callback can distinguish "first login by
// this subject" (upsert path) from "lookup miss for an existing
// session" (operator-revoked path).
//
// Governing: SPEC-0005 REQ "OIDC Login Flow".
var ErrUserNotFound = errors.New("users: not found")

// ErrUserAlreadyExists is returned by repository.insert when the
// users.oidc_subject UNIQUE constraint trips. Service.Upsert uses
// this as the explicit signal to take the lookup-and-update race
// fallback path -- any OTHER insert error is a real driver/FK
// problem and propagates directly so logs distinguish "race lost"
// (expected, frequent during concurrent first logins) from "real
// failure" (alert-worthy).
//
// Governing: SPEC-0005 REQ "OIDC Login Flow"; mirrors the typed
// error pattern in internal/account/repository.go.
var ErrUserAlreadyExists = errors.New("users: already exists")
