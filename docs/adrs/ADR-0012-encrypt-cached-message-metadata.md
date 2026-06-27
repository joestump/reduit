# ADR-0012: Encrypt cached message metadata at rest

- **Status:** proposed (2026-06-27)
- **Date:** 2026-06-27
- **Deciders:** Joe Stump

## Context and Problem Statement

The `messages` table (introduced in
`20260502000002_mailbox_uids.sql`) is a metadata-only cache. It exists
so the IMAP server can answer LIST/FETCH/SEARCH without a Proton
round-trip for every listing. By design it never stores message bodies
or full headers — those are fetched on demand via the Proton client and
remain OpenPGP end-to-end-encrypted the entire time. The row is "soft
metadata only," as the migration comment puts it.

But two of those metadata columns are sensitive:

```sql
CREATE TABLE messages (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id         TEXT    NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    proton_message_id  TEXT    NOT NULL,
    subject            TEXT    NOT NULL DEFAULT '',   -- plaintext PII
    sender             TEXT    NOT NULL DEFAULT '',   -- plaintext PII
    rfc822_size        INTEGER NOT NULL DEFAULT 0,
    flags              TEXT    NOT NULL DEFAULT '',
    internal_date      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

`subject` and `sender` are stored as plaintext `TEXT`. For a
privacy-first Proton relay, subject lines and correspondents *are* the
sensitive content: who someone talks to and what about is exactly the
metadata Proton's E2E model is meant to protect. Here it sits
unencrypted in a SQLite file that ADR-0003 explicitly treats as
untrusted at rest — the file "may be backed up, snapshotted, or mounted
by a host with broader access." ADR-0003 encrypted every account
*secret* under that threat model but said nothing about cached message
metadata, because the `messages` table did not exist yet.

So this is an undocumented gap, not a reversal: no prior ADR ever
weighed the trade-off of caching subject/sender in plaintext. The
security audit (issue #51) surfaced it. This ADR records the decision;
implementation (sealing helpers, the re-encryption migration, the spec
update) is tracked separately on #51.

## Decision Drivers

- **PII-at-rest exposure.** Subject lines and correspondent addresses
  are high-sensitivity personal data, and they currently sit in
  plaintext in a file the threat model treats as untrusted.
- **Consistency with ADR-0003.** Reduit already has a per-account
  envelope-encryption scheme with column-name AAD. A new bespoke
  mechanism would be a second thing to audit; reusing the existing one
  is strictly less surface.
- **IMAP SEARCH / SORT functionality.** `SEARCH SUBJECT` and
  server-side `SORT` currently can (in principle) push down to SQL.
  Encrypting the column changes that.
- **Per-account cryptographic isolation.** Whatever protects this data
  should preserve ADR-0003's property that compromising one account's
  data key does not expose another account's.
- **Performance at family scale.** Reduit is family-grade software, not
  a high-throughput mail provider. A small per-row decrypt cost on a
  listing of hundreds-to-thousands of messages is acceptable; a
  per-listing network round-trip to Proton is not.

## Considered Options

1. **Accept the risk and document it (status quo).** Leave `subject`
   and `sender` as plaintext `TEXT`. Record in the spec and operator
   docs that the SQLite cache contains subject/sender in the clear, and
   lean on filesystem permissions + disk encryption.
2. **Encrypt `subject` and `sender` under the per-account data key.**
   Seal each value with XChaCha20-Poly1305 under the account's data
   key, using the same envelope and column-name-AAD pattern ADR-0003
   established for `accounts` secret columns (see `internal/account/
   secrets.go`). Store ciphertext; decrypt in memory at FETCH/LIST
   time.
3. **Drop the columns; derive metadata on demand from Proton.** Remove
   `subject`/`sender` from the cache entirely and fetch them from
   Proton every time an IMAP listing needs them.

## Decision Outcome

**Chosen: option 2 — encrypt `subject` and `sender` under the
per-account data key.** Status: **proposed** — this ADR needs
ratification before the #51 implementation lands.

Rationale:

- **Consistent with ADR-0003.** It reuses the exact envelope scheme and
  the column-name-AAD discipline already implemented in
  `internal/account/secrets.go`: each value is `cryptenv.Seal`-ed under
  the account's data key with the canonical column name as additional
  authenticated data, so a ciphertext cannot be substituted from one
  column (or one row's column) into another sealed under the same key.
  Per-account data-key isolation from ADR-0003 carries straight over —
  compromising one account's data key exposes only that account's
  cached subjects/senders.
- **Keeps offline IMAP listing working.** Bodies were already remote;
  these columns exist precisely so listing does not hit Proton. We keep
  that property by decrypting in memory at FETCH/LIST time rather than
  removing the cache. This is why option 3 is rejected: dropping the
  columns reintroduces a per-listing Proton round-trip (latency,
  rate-limit pressure, and a hard dependency on Proton being reachable
  to render a folder), trading a real availability/performance
  regression for no privacy benefit over option 2.
- **Strictly better privacy than option 1, for low cost.** Option 1
  leaves the single most sensitive cached data in the clear under a
  threat model that ADR-0003 already declared insufficient for
  secrets. The marginal cost of option 2 is a per-row in-memory
  decrypt and the loss of SQL-level search push-down (see
  Consequences) — cheap at family-mailbox scale.

### Consequences

**Positive**

- Subject lines and correspondents are no longer readable from a
  backup, snapshot, or broader-access mount of the SQLite file without
  the service master key — closing the audit gap and bringing the
  `messages` cache up to ADR-0003's at-rest posture.
- One encryption scheme to audit, not two. The same `cryptenv` envelope
  and column-name-AAD invariant govern both account secrets and cached
  message metadata.

**Negative / trade-offs (honest)**

- **SQL-level search/sort push-down is lost.** `SEARCH SUBJECT` and
  server-side `SORT` on subject can no longer be expressed as a `WHERE
  subject LIKE ?` / `ORDER BY subject` against ciphertext. They must
  decrypt the candidate rows in memory and match/sort there. This is
  acceptable at family-mailbox scale (a folder is hundreds to low
  thousands of rows). A keyed **blind index** (e.g. an HMAC of a
  normalized subject for equality search) could restore push-down for
  exact-match queries later; it is **out of scope here** and noted as a
  follow-up on #51, not a commitment.
- **A migration must re-encrypt existing rows.** Any already-cached
  `subject`/`sender` values must be read, sealed under each account's
  data key, and written back as ciphertext, per account. This is part
  of the #51 implementation. (The project is pre-alpha with no
  production data, so this is a clean forward ratchet rather than a
  delicate backfill — but the migration must still be written.)
- **Small per-row CPU cost on read.** Each FETCH/LIST that surfaces
  subject/sender pays an AEAD open per row. Negligible at target scale.

**Neutral**

- **`rfc822_size`, `flags`, and `internal_date` stay plaintext.** IMAP
  needs them to build a listing *without* decryption (size and date
  drive FETCH responses and `SORT`/SEARCH on date/size; flags drive
  `\Seen` etc.), and they are low-sensitivity operational metadata, not
  PII in the sense subject/sender are. Encrypting them would forfeit
  cheap SQL-level listing for little privacy gain. They remain in the
  clear deliberately.
- `proton_message_id` and the UID join structures are unchanged; this
  decision is scoped to the two PII-bearing TEXT columns.

## Pros and Cons of the Options

### Encrypt under the per-account data key (chosen)

- **Good:** Reuses ADR-0003's envelope + column-name-AAD; one scheme to
  audit; per-account isolation preserved.
- **Good:** Offline listing keeps working — decrypt in memory, no
  Proton round-trip.
- **Good:** Closes the at-rest PII gap for the highest-sensitivity
  cached fields at low cost.
- **Bad:** Loses SQL push-down for `SEARCH SUBJECT` / `SORT` on
  subject; needs in-memory matching (or a future blind index).
- **Bad:** Requires a re-encryption migration.

### Accept the risk and document it (rejected)

- **Good:** Zero implementation cost; SQL search/sort stay trivial.
- **Bad:** Leaves the single most sensitive cached data — who you
  correspond with and about what — in plaintext under a threat model
  ADR-0003 already declared insufficient for secrets. Inconsistent with
  the project's privacy-first framing.

### Drop the columns; derive on demand (rejected)

- **Good:** Nothing sensitive cached at all; nothing to encrypt or
  migrate.
- **Bad:** Reintroduces a per-listing Proton round-trip — latency,
  rate-limit pressure, and a hard dependency on Proton being reachable
  just to render a folder. Defeats the reason the cache exists.

## References

- ADR-0003 (service-master-key envelope encryption for at-rest
  secrets) — establishes the per-account data-key envelope, the
  XChaCha20-Poly1305 column sealing, the column-name-AAD discipline,
  and the "SQLite file is untrusted at rest" threat model this ADR
  extends to cached message metadata.
- SPEC-0001 (Account Model), REQ "Account-Scoped Data" — the
  `messages` cache is per-account state filtered by `account_id`; the
  per-account data key that seals subject/sender is the same key that
  scopes the account. The spec update enumerating `subject`/`sender` as
  encrypted columns is tracked on #51.
- `internal/account/secrets.go` — the reference implementation of the
  Seal/Open + column-name-AAD pattern this decision applies to
  `messages.subject` and `messages.sender`.
- `internal/store/migrations/20260502000002_mailbox_uids.sql` — defines
  the `messages` table whose `subject`/`sender` columns this ADR
  governs.
- Issue #51 — audit-coverage gap and the home for the implementation
  (sealing, migration, spec update, follow-up blind-index note).
