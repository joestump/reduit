// Package mailbox owns the IMAP-side mailbox state: UIDVALIDITY
// assignment per (account, mailbox), monotonic per-mailbox UID
// assignment, and the IMAP↔Proton folder/label name mapping.
//
// Responsibilities (per SPEC-0003):
//
//   - EnsureMailbox: idempotent per-(account, name) upsert that assigns
//     a fresh UIDVALIDITY (microsecond Unix timestamp) on first call.
//   - AssignUID: atomic per-mailbox monotonic counter that issues one
//     UID per (mailbox, Proton message) pair. Concurrent racers
//     serialize through SQLite's BEGIN IMMEDIATE write lock; reused
//     Proton message IDs (re-added after expunge) get a fresh UID,
//     never the prior one — the (mailbox_id, uid) UNIQUE index plus the
//     monotonic increment proves the SPEC-0003 "UIDs never reuse"
//     property.
//   - ResolveSystemFolder/ParseUserLabel: hard-coded IMAP↔Proton system
//     folder mapping (INBOX↔Inbox, Sent↔Sent, etc.) and the additive
//     `Labels/<name>` user-label namespace.
//
// Account scoping: every public method takes an explicit accountID and
// every query in the repository carries a `WHERE account_id = ?` clause.
// Per SPEC-0001 REQ "Account-Scoped Data" no per-account row is ever
// reachable without the owning account ID.
//
// Governing: ADR-0006 (SQLite + sqlx + goose), SPEC-0001 REQ
// "Account-Scoped Data", SPEC-0003 REQs "UID Stability", "Folder
// Hierarchy and Mapping", "Account Isolation in IMAP Operations".
package mailbox
