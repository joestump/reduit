# SPEC-0002: Sync & Local Cache

## Overview

**Sync** is the incremental pull of mail from Proton's event stream into
the local SQLite cache (ADR-0006). The cache is the source every other
Reduit surface reads from — keyword search, semantic search, RAG, fact
extraction, the MCP server, the CLI, and the loopback UI. Proton remains
the source of truth; the cache is derived state that sync keeps
fresh-enough against it. Sync writes only to the cache; it never writes
back to Proton.

A single install serves the local OS user's N Proton mailboxes. Each
mailbox syncs independently: one sync routine per active mailbox, each
advancing its own persisted Proton event cursor in `sync_state`. The
first sync of a mailbox performs a bounded historical backfill; every
run after that tails the event stream and applies the delta. Bodies and
attachment metadata are decrypted in the pipeline using the mailbox
passphrase fetched from the OS keychain (ADR-0013), so what lands in the
cache is plaintext, ready to index. Messages are keyed by a stable
content identity so re-import and overlapping windows converge without
duplicates, and derived data (embeddings, facts, extracted text) hangs
off the same hash and is never orphaned by re-sync.

Sync is triggered, not daemonized: `reduit sync` runs as a CLI verb
suited to cron / launchd / systemd-timer, with an optional foreground
watch loop. There is no always-on network service. The operator chooses
the cadence, bounded to respect Proton's rate limits.

Governing: ADR-0014 (sync-and-cache), ADR-0001 (go-proton-api),
ADR-0006 (SQLite store), ADR-0013 (secrets in OS keychain), SPEC-0001
(Mailbox Model).

## Requirements

### Requirement: Per-Mailbox Sync Isolation

The system MUST run at most one sync routine per active mailbox, and a
crash, panic, or authentication failure in one mailbox's sync MUST NOT
affect the sync of any other mailbox.

#### Scenario: One routine per active mailbox

- **WHEN** a `reduit sync` invocation targets all active mailboxes
- **THEN** the system SHALL run exactly one sync routine for each active
  mailbox, each scoped to its own `mailbox_id` and its own
  `sync_state` cursor

#### Scenario: Failure in one mailbox does not stall others

- **WHEN** one mailbox's sync fails (network error, decrypt failure,
  panic, or revoked credentials)
- **THEN** the system SHALL record that failure against that mailbox
  only and SHALL continue and complete sync for every other mailbox

#### Scenario: Auth failure isolates to its mailbox

- **WHEN** the keychain passphrase or refresh token for one mailbox is
  missing or rejected by Proton
- **THEN** the system SHALL mark that mailbox's run as failed with a
  cause and SHALL NOT abort sibling mailbox syncs or the process

### Requirement: Bootstrap Then Tail

The first sync of a mailbox MUST perform a bounded historical backfill;
subsequent syncs MUST advance the persisted Proton event cursor and
apply only the delta.

#### Scenario: First sync backfills a bounded window

- **WHEN** a mailbox has no persisted event cursor in `sync_state`
- **THEN** the system SHALL backfill historical messages over the
  configured window (a time bound, e.g. the last N months, or the full
  mailbox when so configured), then record the current Proton event
  cursor as the resume point

#### Scenario: Subsequent sync tails the event stream

- **WHEN** a mailbox has a persisted event cursor
- **THEN** the system SHALL request events from Proton starting at that
  cursor, apply the returned creates / updates / deletes, and persist
  the advanced cursor — it SHALL NOT re-backfill

#### Scenario: Full rescan on demand

- **WHEN** `reduit sync --full` is invoked for a mailbox
- **THEN** the system SHALL re-run the bounded backfill and re-apply
  messages idempotently against the existing cache without producing
  duplicates

### Requirement: Idempotent Stable-Hash Keying

Messages MUST be keyed by a stable content identity (Proton message id +
content hash) so that re-import and overlapping windows converge with no
duplicates, and derived data MUST be keyed by that same hash so re-sync
never orphans or wipes it.

#### Scenario: Re-importing a message converges

- **WHEN** sync encounters a message whose stable hash already exists in
  the cache
- **THEN** the system SHALL upsert that one row rather than insert a
  duplicate; the message count SHALL NOT grow for an unchanged message

#### Scenario: Overlapping windows do not duplicate

- **WHEN** a backfill window and a subsequent tail both cover the same
  message
- **THEN** the cache SHALL hold exactly one row for that message, keyed
  by its stable hash

#### Scenario: Derived data survives re-sync

- **WHEN** a message is re-synced and its stable hash is unchanged
- **THEN** the system SHALL leave embeddings, contact facts, and
  attachment extracted text keyed by that hash intact — re-sync SHALL
  NOT delete or orphan derived rows

### Requirement: Decrypt In The Pipeline

Message bodies and attachment metadata MUST be decrypted via
go-proton-api using the mailbox passphrase fetched from the OS keychain;
the decrypted plaintext is what is written to the cache.

#### Scenario: Passphrase fetched from the keychain

- **WHEN** sync begins for a mailbox
- **THEN** the system SHALL retrieve the mailbox passphrase from the OS
  keychain entry `reduit / mailbox/<mailbox_id>/mailbox_passphrase`
  (ADR-0013) and use it to unlock the mailbox's OpenPGP keys

#### Scenario: Plaintext lands in the cache

- **WHEN** a message is decrypted in the pipeline
- **THEN** the system SHALL write the decrypted body, headers, and
  attachment metadata to the cache as plaintext; no cache column is
  app-layer encrypted (ADR-0006)

#### Scenario: Decrypt failure does not poison the cache

- **WHEN** a single message fails to decrypt
- **THEN** the system SHALL log the failure with the Proton message id,
  skip that message without writing a partial row, and continue the run

### Requirement: Crash-Safety And Resumability

An interrupted sync MUST resume from the last persisted cursor, and
partial application MUST NOT corrupt the cache.

#### Scenario: Cursor advances atomically with the delta

- **WHEN** sync applies a batch of changes derived from an event delta
- **THEN** the system SHALL commit those cache writes and the advanced
  `sync_state` cursor in the same transaction; a partial commit SHALL
  NOT be observable

#### Scenario: Interrupted run resumes from the cursor

- **WHEN** a sync run is interrupted (reboot, kill, network loss) before
  completing
- **THEN** the next run SHALL resume from the last committed cursor and
  SHALL NOT re-process already-committed events

#### Scenario: Partial application never corrupts the cache

- **WHEN** a crash occurs mid-batch
- **THEN** the cache SHALL reflect only fully-committed units of work
  (per-message / per-conversation atomic writes); no half-written
  message SHALL remain

### Requirement: Rate-Limit Respect

Fetching MUST be bounded and backoff-aware, and sync MUST NOT perform a
full re-fetch on every run.

#### Scenario: Incremental by default

- **WHEN** `reduit sync` runs without `--full`
- **THEN** the system SHALL fetch only events newer than the persisted
  cursor; it SHALL NOT re-fetch the whole mailbox

#### Scenario: Backoff on transient failure

- **WHEN** Proton returns a transient error (network failure, 5xx, or
  HTTP 429 rate limit)
- **THEN** the system SHALL back off before retrying, honoring any
  `Retry-After` Proton supplies (handled in go-proton-api's transport),
  and SHALL NOT bypass it

#### Scenario: Bounded concurrency

- **WHEN** several mailboxes sync in one invocation
- **THEN** the system SHALL bound the number of concurrent in-flight
  Proton requests so as not to surge Proton's API

### Requirement: Triggered Execution

Sync MUST be invokable as the CLI verb `reduit sync [--mailbox …]
[--full]`, suitable for cron / timer / launchd, and MAY run as an
optional foreground watch loop. There MUST NOT be an always-on network
daemon.

#### Scenario: One-shot CLI run

- **WHEN** `reduit sync` is invoked
- **THEN** the system SHALL sync the selected mailboxes, persist their
  cursors and run summaries, and exit

#### Scenario: Mailbox selection

- **WHEN** `reduit sync --mailbox <id|address>` is invoked
- **THEN** the system SHALL sync only the named mailbox and leave other
  mailboxes' `sync_state` untouched

#### Scenario: Optional foreground watch loop

- **WHEN** the operator starts the optional watch loop
- **THEN** the system SHALL re-run sync on an interval in the foreground
  and SHALL stop on signal; it SHALL NOT open any network listener or
  run as a background service

### Requirement: Bookkeeping And Observability

Per-mailbox sync state and per-run summaries MUST be persisted.

#### Scenario: Cursor and last-run persisted

- **WHEN** a sync run completes for a mailbox
- **THEN** the system SHALL persist that mailbox's event cursor and
  last-run timestamp in `sync_state`

#### Scenario: Per-run summary counts

- **WHEN** a sync run completes
- **THEN** the system SHALL persist a summary of that run — messages
  added / updated / deleted, attachments processed, and any error
  count — for observability

### Requirement: Offline Behavior

With no network available, browse, keyword search, and
previously-computed semantic search MUST continue to work against the
cache.

#### Scenario: Reads work offline

- **WHEN** the network is unavailable
- **THEN** browsing cached messages, FTS keyword search, and semantic
  search over already-computed embeddings SHALL all succeed against the
  local cache

#### Scenario: Sync degrades gracefully offline

- **WHEN** `reduit sync` is invoked with no network
- **THEN** the system SHALL fail the network-dependent fetch cleanly,
  leave the cache and cursors unchanged, and report the failure — it
  SHALL NOT corrupt or truncate the cache

### Requirement: FTS Upkeep

The `messages_fts` index MUST stay in sync with `messages` as rows land,
maintained by database triggers.

#### Scenario: New message becomes searchable

- **WHEN** sync inserts a message row
- **THEN** the FTS5 external-content index SHALL be updated by trigger
  so the message is immediately keyword-searchable

#### Scenario: Updated and deleted messages reindex

- **WHEN** sync updates or deletes a message row
- **THEN** the corresponding `messages_fts` entry SHALL be updated or
  removed by trigger, with no orphaned or stale FTS rows

## Out of Scope

- Real-time push to mail clients / IMAP IDLE. There is no relay
  (ADR-0012); sync materializes a local cache, not live client sessions.
- Sending mail. Outbound is SPEC-0010 (ADR-0020); sync never writes to
  Proton.
- Embedding computation. Sync only populates the cache that the
  embedding pass (SPEC-0008, ADR-0015) reads from; it does not compute
  vectors.
- Fact extraction. Contact facts (SPEC, ADR-0019) are a downstream pass
  over the cache, not part of sync.
