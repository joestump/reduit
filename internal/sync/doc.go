// Package sync owns the per-account Proton event-stream consumers
// (the "sync workers") and the Supervisor that starts/stops them in
// response to account-state transitions.
//
// As of issue #16 the worker is functional plumbing: each tick
// resolves a proton.Client via the configured ClientFactory, calls
// GetEvent under the process-wide concurrency semaphore, and persists
// the new cursor atomically via account.Service.SetSyncState. On
// startup the worker resumes from the persisted cursor (or bootstraps
// from GetLatestEventID on first-ever boot via the ErrNoSyncState
// sentinel). The actual mailbox/UID materialisation derived from
// events is deferred to issue #19's IMAP work; #16 wires the cursor
// pipeline so #19 has somewhere to plug its derived-state writes via
// the SyncStateTxWork callback supported by SetSyncState.
//
// Subsequent stories fill in the remaining SPEC-0002 surface:
//
//   - Issue #17 layers backoff-with-jitter, IMAP IDLE pubsub
//     publication, and permanent-error account-state transitions
//     (SPEC-0002 REQ "Backoff on Failure", "IMAP Update Notification",
//     refresh-token-revoked handling).
//   - Issue #19 lands the mailbox/UID materialisation that consumes
//     the cursor pipeline plumbed here.
//
// Wiring into cmd/reduit's serve command is intentionally deferred to
// the v0.2 consolidation PR per the design doc; this package is fully
// exercised by its own unit tests against a stub Proton client.
//
// Governing: ADR-0001 (go-proton-api as Proton client), SPEC-0002
// (Sync Worker), specifically the REQs:
//
//   - "One Worker Per Active Account" — Supervisor.OnAccountStateChange
//     spawns/stops workers on transitions into/out of StateActive.
//   - "Graceful Shutdown" — Supervisor.Stop drains workers within a
//     configurable graceful deadline (default 5s), then hard-cancels
//     survivors via context up to a hard deadline (default 30s).
//   - "Concurrency Limits" — every Proton call site acquires a slot on
//     a process-wide buffered semaphore (default cap 8).
//   - "Panic Isolation" — each worker goroutine runs under a deferred
//     recover that logs the panic value + stack and marks the worker
//     crashed without taking down the supervisor.
package sync
