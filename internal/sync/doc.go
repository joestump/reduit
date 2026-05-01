// Package sync owns the per-account Proton event-stream consumers
// (the "sync workers") and the Supervisor that starts/stops them in
// response to account-state transitions.
//
// This package is the v0.1 foundation laid by issue #15: it implements
// the supervisor and the worker lifecycle harness, but the worker body
// itself is a stub that loops on a tick. Subsequent stories fill in
// the body:
//
//   - Issue #16 wires the worker's tick to client.GetEvent and the
//     event-cursor persistence path (SPEC-0002 REQ "Event Cursor
//     Persistence").
//   - Issue #17 layers backoff-with-jitter, IMAP IDLE pubsub
//     publication, and crash isolation/admin-clear semantics
//     (SPEC-0002 REQ "Backoff on Failure", "IMAP Update Notification",
//     "Panic Isolation").
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
