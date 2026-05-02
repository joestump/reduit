// Package-level sentinels.
package mailbox

import "errors"

// ErrMailboxNotFound is returned when a (account, name) lookup misses.
// Per SPEC-0003 REQ "Account Isolation in IMAP Operations" callers MUST
// surface this as the same `NO Mailbox does not exist` IMAP response
// the empty-backend stub returns, so a malicious client cannot
// distinguish "not yours" from "does not exist for anybody".
var ErrMailboxNotFound = errors.New("mailbox: not found")

// ErrMessageNotFound is returned by AssignUID and friends when the
// message_id passed in does not resolve to a row in `messages`. Almost
// always indicates a sync-worker bug (caller must Insert the message
// before assigning it a UID); kept distinct from ErrMailboxNotFound so
// the test failure message is unambiguous.
var ErrMessageNotFound = errors.New("mailbox: message not found")

// ErrUIDExhausted is returned (in theory) if a mailbox's uid_next
// overflows uint32. In practice this would require >4 billion UID
// assignments per (account, mailbox) and is impossible during the
// service's expected lifetime; we still surface a typed error rather
// than panic so a future bulk-import bug does not silently wrap.
var ErrUIDExhausted = errors.New("mailbox: uid_next exhausted")
