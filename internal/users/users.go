// Package users implements Reduit's user model.
//
// A user is the OIDC-sourced identity that owns zero or more Proton
// accounts (per ADR-0010 / SPEC-0001 "User Identity"). Sessions bind
// to user_id; account ownership flows through accounts.user_id. Admin
// status is NOT carried here -- it is computed at session-bind time
// from OIDC_ADMIN_SUBS per SPEC-0001 "Admin Status".
//
// Governing: ADR-0010 (multi-Proton-account per user), SPEC-0001 REQ
// "User Identity", SPEC-0001 REQ "User Lifecycle".
package users

import "time"

// User is the in-memory projection of one row of the `users` table.
//
// Governing: SPEC-0001 REQ "User Identity".
type User struct {
	ID          string
	OIDCSubject string
	Email       string
	DisplayName string
	CreatedAt   time.Time
	LastLoginAt time.Time
}
