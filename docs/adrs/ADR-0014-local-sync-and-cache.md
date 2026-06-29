# ADR-0014: Local sync-and-cache from the Proton event stream

- **Status:** accepted
- **Date:** 2026-06-29
- **Deciders:** Joe Stump

## Context and Problem Statement

Reduit's reason to exist (ADR-0012) is local semantic search, RAG, and agent
access over Proton mail. All three need mail to be **present locally**: the
Proton API is rate-limited and network-bound, so embedding, FTS, hybrid search,
and fact extraction cannot run against it live on every query. We need a local
cache of decrypted mail in SQLite (ADR-0006), kept current against Proton.

Unlike the sibling `msgbrowse`, whose source is a static, already-decrypted
on-disk export, Reduit's source is the **live, encrypted, rate-limited** Proton
API. The original SPEC-0002 already worked out the hard part — consuming Proton's
event stream with a persisted cursor — for the (now removed) IMAP backend. That
logic is the most valuable thing to carry forward; only its *sink* changes, from
"materialize IMAP UID state" to "materialize a RAG cache."

## Decision Drivers

- **Rate limits are real.** A full re-fetch on every run is hostile to Proton and
  slow. Sync must be incremental and resumable.
- **Idempotent and crash-safe.** Re-running sync must converge, never duplicate,
  and survive interruption (reboot, network loss) without corrupting the cache.
- **Decrypt once, locally.** Bodies must be decrypted (mailbox passphrase from the
  keychain, ADR-0013) before they can be embedded/searched; the decrypted form
  lands in the local cache (accepted at-rest, ADR-0012).
- **Multi-mailbox.** N mailboxes sync independently, each with its own Proton
  event cursor; one mailbox's failure must not stall the others.
- **Offline-friendly.** Browsing, keyword search, and previously-computed semantic
  search must work with no network at all.

## Considered Options

1. **Full re-fetch each run.** Simple, but rate-limit-hostile and slow; rejected.
2. **Event-stream incremental sync with a persisted cursor.** Bootstrap a mailbox
   with a bounded backfill, then advance a stored Proton event ID, applying
   creates/updates/deletes idempotently. (Carried over from SPEC-0002.)
3. **On-demand fetch, no cache.** Query Proton live per request. Defeats the whole
   point (rate limits, offline, embeddings); rejected.

## Decision Outcome

**Chosen: option 2 — incremental event-stream sync into a local cache.**

- **Per-mailbox worker.** One sync routine per active mailbox, isolated so a crash
  or auth failure in one does not affect the others (the isolation principle from
  the original SPEC-0002 survives).
- **Bootstrap then tail.** First sync performs a bounded historical backfill
  (configurable window, or the full mailbox, as the operator chooses); subsequent syncs advance the
  persisted Proton event cursor and apply the delta.
- **Idempotent keying.** Messages are keyed by a stable content identity (Proton
  message ID + a content hash), so re-import and overlapping windows converge
  without duplicates. This is also the key embeddings and facts hang off
  (ADR-0015, ADR-0019), so re-sync never orphans derived data.
- **Decrypt in the pipeline.** Bodies and attachment metadata are decrypted via
  `go-proton-api` (ADR-0001) using the keychain passphrase, then written to the
  cache. Attachment payloads are handled per ADR-0016.
- **Triggered, not daemonized by default.** Sync runs as a CLI verb
  (`reduit sync`) suitable for cron / launchd / systemd-timer, and may also run as
  a foreground watch loop. There is no always-on network service (ADR-0012); the
  cadence is the operator's, bounded to respect Proton's limits.
- **Bookkeeping.** Per-mailbox sync state (cursor, last-run, counts) and per-run
  summaries are persisted (ADR-0006) for observability and incrementality.

### Consequences

**Positive**

- Search/RAG/facts all run locally and offline against fresh-enough mail without
  hammering Proton.
- Re-running sync is always safe; interrupted runs resume from the cursor.
- Reuses the genuinely hard, already-designed event-stream logic from SPEC-0002.

**Negative**

- The cache can lag Proton between runs; "live" is really "as of last sync." The
  operator chooses the cadence.
- Decryption requires the passphrase to be retrievable at sync time (keychain
  unlocked, ADR-0013).
- Backfill of a large mailbox is bounded by Proton's rate limits and can be slow
  on first run.

**Operational**

- `reduit sync [--mailbox …] [--full]` — incremental by default; `--full` forces a
  rescan. Schedule it via cron/timer.
- Sync writes only to the cache DB; it never writes to Proton (that is ADR-0020).
