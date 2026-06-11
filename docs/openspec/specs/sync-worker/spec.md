# SPEC-0002: Sync Worker

## Overview

A **sync worker** is a per-account goroutine that consumes Proton's
event stream, materializes local IMAP state in SQLite, and pushes
updates to live IMAP IDLE sessions. Exactly one sync worker runs per
active account. Crashes in one worker MUST NOT affect other workers
or the parent process.

Governing: ADR-0001 (go-proton-api), ADR-0002 (multi-tenant), SPEC-0001
(Account Model), SPEC-0003 (IMAP Server).

## Requirements

### Requirement: One Worker Per Active Account

The system MUST maintain exactly one running sync worker for every
account in `state = active`. Workers for accounts in any other state
MUST NOT be running.

#### Scenario: Worker starts on account activation

- **WHEN** an account transitions to `active`
- **THEN** the system SHALL start a sync worker for that account
  within 1 second

#### Scenario: Worker stops on suspension or deletion

- **WHEN** an account transitions out of `active`
- **THEN** the system SHALL stop the sync worker within 5 seconds (a
  graceful drain interval), or kill it after 30 seconds (hard
  cancel via context cancellation)

#### Scenario: Worker duplicates are prevented

- **WHEN** a request arrives to start a worker for an account that
  already has a running worker
- **THEN** the system SHALL no-op and log at DEBUG level. The system
  MUST NOT spawn a second worker

### Requirement: Event Cursor Persistence

Each worker MUST persist Proton's event cursor (event ID) after every
successful batch. On restart the worker MUST resume from the persisted
cursor.

#### Scenario: Cursor persisted after each batch

- **WHEN** a worker completes processing of an event batch from
  Proton
- **THEN** the worker SHALL update `accounts.last_event_id` (or a
  dedicated `sync_state` table) with the cursor returned by Proton,
  in the same transaction as any state changes derived from that
  batch

#### Scenario: Cursor advances atomically with state changes

- **WHEN** a worker's transaction commits a batch of state changes
- **THEN** the cursor and the state changes SHALL commit together;
  partial commits MUST NOT be possible

#### Scenario: Resume on startup uses persisted cursor

- **WHEN** a worker starts (process boot or account activation) and
  the account has a non-null `last_event_id`
- **THEN** the worker SHALL request events from Proton starting at
  that cursor, not from the beginning

### Requirement: Backoff on Failure

When the worker encounters a transient error (network failure, Proton
5xx, 429 rate limit), it MUST back off using exponential backoff with
full jitter, capped at a maximum delay.

#### Scenario: Exponential backoff with jitter

- **WHEN** the worker's last attempt failed transiently
- **THEN** the next attempt SHALL be delayed by a duration drawn
  uniformly from `[0, min(maxDelay, baseDelay * 2^attempt))` where
  `baseDelay = 1s` and `maxDelay = 5min`. Failure counter resets on
  success

#### Scenario: 429 honors Retry-After

- **WHEN** Proton returns HTTP 429 with a `Retry-After` header
- **THEN** the worker SHALL wait at least the requested duration
  before retrying. `go-proton-api` handles this in its transport
  layer; the worker SHALL NOT bypass

#### Scenario: Permanent errors do not retry indefinitely

- **WHEN** Proton returns an error indicating the auth refresh has
  failed (e.g., refresh token revoked) or the account has been
  deleted
- **THEN** the worker SHALL transition the account state to
  `pending_proton_setup` (refresh-token-revoked) or `suspended` (other
  permanent failure), stop, and emit a notification to the admin UI

### Requirement: Panic Isolation

A panic inside a sync worker goroutine MUST NOT crash the parent
process or affect other workers.

#### Scenario: Panic recovery with logged context

- **WHEN** a worker goroutine panics
- **THEN** the system SHALL recover the panic, log at ERROR level
  with the account ID, panic value, and stack trace, mark the
  account's worker as `crashed`, and SHALL NOT restart the worker
  automatically. An admin SHALL manually clear the crashed flag via
  the admin UI to retry

#### Scenario: Other workers unaffected by sibling crash

- **WHEN** a worker for account A panics and is recovered
- **THEN** workers for accounts B, C, etc. SHALL continue running
  without interruption

### Requirement: IMAP Update Notification

After applying a batch of changes, the worker MUST notify any live
IMAP IDLE sessions for the same account so clients see new mail
without polling.

#### Scenario: Worker pushes EXISTS update on new message

- **WHEN** a worker processes an event that adds a new message to a
  mailbox
- **THEN** the worker SHALL publish a notification to the in-process
  pubsub channel keyed by `(account_id, mailbox_id)`. The IMAP IDLE
  session subscribed to that channel SHALL emit an `EXISTS` untagged
  response within 1 second

#### Scenario: Worker pushes EXPUNGE update on deletion

- **WHEN** a worker processes an event that removes a message
- **THEN** the worker SHALL publish a notification, and the IDLE
  session SHALL emit an `EXPUNGE` untagged response

#### Scenario: Flag changes emit FETCH

- **WHEN** a worker processes a flag change (read/unread, starred,
  label add/remove)
- **THEN** the worker SHALL publish a notification, and the IDLE
  session SHALL emit a `FETCH` untagged response with the updated
  flags

### Requirement: Graceful Shutdown

On process shutdown signal (SIGTERM, SIGINT), all sync workers MUST
drain in-flight work, persist their cursor, and exit before the
process terminates.

#### Scenario: Drain completes within shutdown deadline

- **WHEN** the process receives a shutdown signal and the configured
  shutdown deadline is 30 seconds
- **THEN** all sync workers SHALL stop accepting new work, finish
  any in-flight batch, persist their cursor, and exit. Workers
  unable to finish within the deadline SHALL be canceled via context

#### Scenario: Cursor is consistent at shutdown

- **WHEN** the process exits cleanly
- **THEN** every account's persisted cursor SHALL reflect the last
  successfully-committed batch; the next start MUST not re-process
  already-committed events

### Requirement: Concurrency Limits

The system MUST cap the total number of concurrent in-flight Proton
API requests across all workers to avoid overwhelming Proton.

#### Scenario: Global concurrency cap enforced

- **WHEN** the configured concurrency cap is `N` and `N` workers are
  in flight to Proton
- **THEN** additional workers requesting Proton API access SHALL
  block until a slot is available. Default cap: 8 concurrent requests
  for the entire process

## Out of Scope

- Cross-account event ordering guarantees.
- Real-time push from Proton (Proton uses long-polling; the worker
  uses periodic poll).
- Backfill of historical messages on first sync (deferred to v0.2;
  v0.1 starts from the current Proton event cursor and only
  materializes new messages from that point forward).

## Implementation Status (v0.1)

Accepted but **deferred** on a tracked roadmap (not drift until landed):

- **IMAP update notification** (EXISTS/EXPUNGE/FETCH push) — depends on
  the sync→pubsub→IMAP live-update pipeline (epic #5).
- **Permanent-error state transition** (revoked token / deleted account
  → suspend, no infinite retry) — partial in #119; admin notification
  in #118.
- **Crashed-flag + admin notify on panic** — tracked in #135.
- **Cursor advances atomically with derived state changes** — cursor
  persistence is implemented; the atomic-with-materialized-state path is
  pending message materialization (v0.2 backfill).
- **Backoff retry-gap correction** — tracked in #136.
