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
