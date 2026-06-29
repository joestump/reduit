# Design: Outbound Send (SPEC-0010)

## Architecture

Send is a single internal routine — call it `send.Submit(ctx, req)` —
that both surfaces invoke. The CLI verb `reduit send` parses flags into
a `SendRequest`; the MCP `send` tool's typed handler (ADR-0017) builds
the same `SendRequest` from its validated JSON arguments. Neither
surface composes or encrypts mail itself; both hand the request to the
one routine, which is where the Proton client, the keychain, and the
cache are touched. This is the structural guarantee behind "behavior
cannot diverge": there is exactly one code path that writes mail.

The routine resolves the named from-mailbox to a `mailboxes` row
(SPEC-0001), rejecting an absent, unknown, or non-`active` mailbox
before any Proton call — there is no default-mailbox fallback. It reads
that mailbox's passphrase from the OS keychain
(`mailbox/<id>/mailbox_passphrase`, ADR-0013) to unlock the OpenPGP
signing/encryption keys, then uses the existing `go-proton-api` client
(ADR-0001) — the same instance used for auth/sync/decrypt — to compose,
encrypt, and submit. Per-recipient encryption mode (Proton-internal E2E
vs external) is decided by the client's recipient-key handling; the
routine surfaces which path applied. On success it reflects the message
into the local cache; on any failure it returns an error to the caller.
There is no spool and no retry loop — this is one submission, not an
MTA.

```mermaid
sequenceDiagram
    participant CLI as reduit send
    participant MCP as MCP send tool
    participant R as send.Submit (one routine)
    participant KC as OS Keychain
    participant GP as go-proton-api
    participant P as Proton
    participant DB as SQLite cache

    alt CLI surface
        CLI->>R: SendRequest{from, to, subj, body, attach}
    else MCP surface (sole mutating tool)
        MCP->>MCP: validate required fields (reject if ambiguous)
        MCP->>R: SendRequest{from, to, subj, body, attach}
    end
    R->>R: resolve from-mailbox row (no default fallback)
    R->>KC: read mailbox/<id>/mailbox_passphrase
    KC-->>R: passphrase (unlock keys)
    R->>GP: compose + encrypt (per-recipient mode) + attachments
    GP->>P: submit message
    alt submission ok
        P-->>GP: sent (Sent folder)
        GP-->>R: ok + per-recipient encryption path
        R->>DB: immediate local insert (stable-hash key)
        R-->>CLI: ok (path summary)
        R-->>MCP: ok (path summary)
        Note over DB: next sync sees Sent item;<br/>same hash → reconciled, no dup
    else submission fails
        P-->>GP: error
        GP-->>R: error
        R-->>CLI: error (no spool, no retry)
        R-->>MCP: tool error
    end
```

## One routine, two surfaces

`SendRequest` is the single shared input shape; `send.Submit` is the
single shared implementation. The CLI is a thin flag parser
(`--from`, `--to` (repeatable), `--cc`, `--bcc`, `--subject`, `--body`
/`--body-file`, `--attach` (repeatable)); the MCP tool is a thin typed
handler whose JSON Schema is inferred by the official Go SDK (ADR-0017).
Everything load-bearing — mailbox resolution, keychain read, Proton
compose/submit, encryption-mode selection, local reflection, error
mapping — lives in `send.Submit`. A surface-local send path does not
exist, so the "behavior cannot diverge" requirement is enforced by
construction rather than by parallel tests alone.

## Agent safety (MCP send)

`send` is the **only** mutating tool in an otherwise read-only MCP
surface (ADR-0017). Its guard lives in the tool handler, before the
shared routine:

- **All required fields present.** `from`, `to`, `subject`, `body` are
  required by the tool's input schema; the SDK rejects a call missing
  any of them before the handler runs, and the handler additionally
  rejects empty/whitespace values.
- **No ambiguity.** An unresolvable recipient or an unnamed/unknown
  from-mailbox is rejected with a clear tool error; the handler never
  infers or auto-fills a missing value.
- **No silent side effect.** No read-only tool, and no internal flow,
  calls `send.Submit`. Sending happens only on an explicit `send`
  invocation. Read tools have no write path to mail.

The exact human-confirmation UX (e.g. an out-of-band confirm) is an
implementation detail per ADR-0020; the invariant fixed here is
"explicit, unambiguous invocation only — never autonomous."

## Encryption modes

Encryption is inherited from `go-proton-api`, not reimplemented
(ADR-0001/ADR-0020). The client resolves each recipient's keys and
selects the path:

- **Proton-internal (E2E).** Recipient is a Proton address with a
  published public key; the message and attachments are encrypted
  end-to-end to that key.
- **External.** Recipient has no Proton public key; the send uses the
  external path the client supports for that recipient.

The routine returns a per-recipient summary of which path applied so
the caller (and, via the MCP result, the agent and the human) is not
misled about confidentiality. Attachments follow the body's
encryption mode per recipient — there is no separate cleartext
attachment path.

## Local reflection and reconciliation

A sent message must show up locally like received mail. Two mechanisms
exist and must not double-count:

- **Immediate local insert.** On success the routine inserts the sent
  message into the cache keyed by its stable hash (ADR-0014), so it is
  searchable at once without waiting for a sync.
- **Next sync.** The Sent folder is synced like any other; the Sent
  item arrives with the **same** stable hash.

Because both paths key on the same content hash, the later sync is an
idempotent upsert onto the existing row — one message, one row, no
duplicate in the cache or in search results. If the immediate insert is
skipped (e.g. send succeeded but the local write failed), the next sync
still reflects the message; the insert is an acceleration, not the
source of truth (Proton remains authoritative, ADR-0014).

## Failure model (no MTA semantics)

Send submits exactly once and surfaces the outcome:

- **Submission error** (network, Proton API error, revoked/invalid
  token): returned to the caller as a CLI error / non-zero exit or an
  MCP tool error. A `needs_reauth`-class token failure also drives the
  mailbox state transition per SPEC-0001; the send itself still fails
  loudly.
- **Recipient-key / encryption error**: returned to the caller; no
  partial or downgraded send is performed silently.
- **Attachment read/encrypt error**: the whole send is rejected; the
  message is not sent without the attachment.

There is no spool table, no server-side retry, and no onward relay. Re-
trying is the caller's decision (re-run `reduit send` / re-invoke the
tool), not a background queue.

## Edge cases

- **Non-active from-mailbox.** A `pending_auth` or `needs_reauth`
  mailbox is rejected up front with a re-auth hint; send never silently
  picks another mailbox to satisfy the request.
- **Mixed-mode recipient set.** Some recipients Proton-internal, some
  external: each is handled on its own path and the per-recipient
  summary makes the mixed confidentiality explicit rather than implying
  uniform E2E.
- **Send succeeds, local insert fails.** The message is already in
  Proton's Sent folder; the next sync reflects it. The routine reports
  the send as successful (Proton is the source of truth) and the local
  cache converges on the next sync.
- **Crash between submit and local insert.** Same convergence: the next
  sync picks up the Sent item by stable hash. No duplicate, no lost
  record.
- **Keychain locked.** If the passphrase cannot be read, the send fails
  before any Proton call with a clear keychain/unlock error — it never
  proceeds with unlocked-but-wrong or stale keys.

## References

- ADR-0020 (outbound send via go-proton-api) — direct send, two
  surfaces one path, agent-safe, local record, no queue/relay.
- ADR-0001 (go-proton-api as Proton client) — the client that composes,
  encrypts, and submits; encryption inherited not reimplemented.
- ADR-0013 (secrets in OS keychain) — `mailbox/<id>/mailbox_passphrase`
  unlocks signing/encryption keys at send time.
- ADR-0017 (stdio MCP) — `send` is the sole mutating tool; typed
  handler, explicit invocation, read tools have no write path.
- ADR-0014 (sync-and-cache) — stable-hash keying reconciles immediate
  insert with the later Sent-folder sync.
- SPEC-0001 (mailbox model) — from-mailbox resolves to a `mailboxes`
  row; sendable requires `state = active`.
- SPEC-0005 (compose affordance) — MAY call this routine; draft storage
  remains out of scope here.
