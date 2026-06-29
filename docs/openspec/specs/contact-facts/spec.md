# SPEC-0011: Sender / Contact Facts

## Overview

A mail archive is most useful as knowledge about *people*: who you
correspond with and what is durably true about your dealings with them
— addresses, order numbers, account identifiers, recurring topics,
commitments. Reduit distills this into short, **cited** facts per
correspondent, gathered by an LLM pass over a contact's messages and
surfaced wherever the system answers "who is this person?" Each fact is
an atomic statement carrying a `category`, a `fact_hash` for dedupe, a
`source_message_hash` pointing at the message it was drawn from, and the
model that produced it. This mirrors the decision `msgbrowse` made for
chat contacts (its ADR-0011 / `contact-facts` spec), keyed here on email
correspondents.

Facts attach to a **contact** — a correspondent identity in the store
(ADR-0006), not a raw email address. The `contacts` and
`contact_identifiers` rows are **materialized during sync** (SPEC-0002
owns their population); this spec does not create them, it consumes
them. The `contact_identifiers` table maps several addresses to one
contact, so a person who writes from work and personal addresses
accrues one fact set rather than fragmenting across mailboxes. Where an
identity is ambiguous, this spec owns the manual merge surface: `reduit
contacts merge` reconciles the ambiguous identities. `reduit facts
[--mailbox …] [--contact …]` runs the
extraction incrementally: a per-contact `fact_state` cursor records the
last processed message hash and the model used, so each run touches only
newer messages, is safe to re-run, and re-opens the whole contact when
the model changes without wiping prior facts. Provenance is by stable
content hash with **no FK to `messages`**, so idempotent re-sync
(ADR-0014) never orphans a citation. Extraction is an LLM feature: it
routes through the single egress (ADR-0018), obeys the
per-conversation/sender denylist, and runs locally by default; with no
endpoint it fails cleanly and the rest of Reduit is unaffected. Facts
are read back through one store method, consumed identically by the MCP
tool surface (SPEC-0006) and the loopback UI contact view (SPEC-0005).

Governing: ADR-0019 (sender/contact facts extraction), ADR-0018 (LLM
single-egress posture + denylist), ADR-0006 (SQLite store; contacts,
contact_identifiers, contact_facts, fact_state), ADR-0014 (sync-and-
cache; stable-hash provenance), SPEC-0002 (sync materializes
`contacts` / `contact_identifiers`), SPEC-0005 (loopback UI), SPEC-0006
(MCP tool surface).

## Requirements

### Requirement: Facts Attach to a Contact, Not an Address

Every fact SHALL be keyed to a `contact_id` — a correspondent identity —
and never to a raw email address. The `contacts` and
`contact_identifiers` rows SHALL be materialized during sync (SPEC-0002
owns their population); this spec consumes them and SHALL NOT create or
populate them. The `contact_identifiers` table SHALL map one or more
addresses to a single contact so that a person who writes from several
addresses accrues exactly one fact set. Where a new address cannot be
unambiguously attributed to an existing contact, reconciliation SHALL be
a manual operation via `reduit contacts merge` (see the Manual Identity
Reconciliation requirement); the system SHALL NOT silently merge or
split contacts during extraction.

#### Scenario: Multiple addresses resolve to one contact

- **WHEN** a contact has two `contact_identifiers` rows (e.g. a work and
  a personal address) and messages arrive from both
- **THEN** extraction SHALL accrue facts under the single owning
  `contact_id`, producing one combined fact set rather than two

#### Scenario: Facts are never keyed to a raw address

- **WHEN** the extractor stores a fact
- **THEN** the row SHALL carry a `contact_id`, and no fact SHALL be
  keyed by an email address string

#### Scenario: Ambiguous identity is not auto-reconciled

- **WHEN** a message arrives from an address not yet mapped to any
  contact and the correct contact is ambiguous
- **THEN** the system SHALL NOT automatically merge it into an existing
  contact; reconciliation SHALL be a manual operation and facts for the
  unmapped address SHALL NOT silently join another contact's set

### Requirement: Manual Identity Reconciliation via `reduit contacts merge`

While `contacts` and `contact_identifiers` rows are materialized during
sync (SPEC-0002), ambiguous identities — where two contacts are the same
person, or an address should move to a different contact — SHALL be
reconciled manually, and this surface is **owned by this spec**. `reduit
contacts merge` SHALL fold one contact's identifiers and facts into
another so that the surviving `contact_id` accrues a single combined
fact set. The merge SHALL be operator-driven and SHALL NOT run
automatically during sync or extraction. Merged facts SHALL be subject
to the `UNIQUE(contact_id, fact_hash)` constraint so that reconciliation
never produces duplicates.

#### Scenario: Operator merges two contacts into one

- **WHEN** the operator runs `reduit contacts merge` to fold one contact
  into another
- **THEN** the losing contact's `contact_identifiers` and `contact_facts`
  SHALL be re-keyed to the surviving `contact_id`, the
  `UNIQUE(contact_id, fact_hash)` constraint SHALL collapse any
  duplicate facts, and the result SHALL be one combined fact set under
  the surviving contact

#### Scenario: Merge is never automatic

- **WHEN** sync or `reduit facts` encounters an address that could
  plausibly belong to an existing contact
- **THEN** it SHALL NOT merge contacts on its own; merging SHALL occur
  only when the operator runs `reduit contacts merge`

### Requirement: Incremental, Cited Fact Extraction

`reduit facts [--mailbox …] [--contact …]` SHALL run an LLM pass using
the text/embedding model role (ADR-0018) over a contact's messages and
emit facts. Each emitted fact SHALL carry `fact` (the statement),
`category` (a constrained label), `fact_hash` (a content hash of the
normalized fact), `source_message_hash` (the message it was drawn from),
and the `model` used. Extraction SHALL be incremental and safe to
re-run.

#### Scenario: Facts command emits cited, categorized facts

- **WHEN** the operator runs `reduit facts --contact <id>` with a
  reachable text model
- **THEN** the system SHALL read the contact's eligible messages and
  persist zero or more `contact_facts` rows, each with `fact`,
  `category`, `fact_hash`, `source_message_hash`, and the producing
  `model`

#### Scenario: Category is constrained

- **WHEN** the model returns a fact whose category is outside the
  allowed set
- **THEN** the system SHALL coerce it to a default category (`other`)
  rather than rejecting the fact or storing an arbitrary label

#### Scenario: Scope can be narrowed by mailbox or contact

- **WHEN** `--mailbox` and/or `--contact` is supplied
- **THEN** extraction SHALL process only the contacts (and their
  messages) matching the given scope, and MAY process all contacts when
  no scope flag is given

### Requirement: Citation by Stable Message Hash

Every fact SHALL carry a `source_message_hash` identifying the message
it was drawn from. This provenance SHALL be a **stable content hash**
with **no foreign key to `messages`**, so that idempotent re-sync
(ADR-0014) — which may delete and re-insert message rows — never wipes
or orphans a fact. A consumer SHALL be able to resolve the hash back to
the source message to verify the fact when that message is present.

#### Scenario: Every fact records its source message hash

- **WHEN** a fact is persisted
- **THEN** the row SHALL contain a non-empty `source_message_hash`
  referencing the message that supports it

#### Scenario: No FK cascade from messages to facts

- **WHEN** the schema for `contact_facts` is created
- **THEN** `source_message_hash` SHALL NOT be a foreign key to
  `messages`, so re-sync of the message row does not cascade-delete the
  fact

#### Scenario: Consumers can verify a fact against its source

- **WHEN** a fact is surfaced
- **THEN** the fact SHALL always carry its `source_message_hash` as its
  citation; when the source message is currently cached, the consumer
  SHALL also receive resolvable coordinates (mailbox, message_id,
  timestamp) and SHALL be able to open that message to verify the fact;
  when the source is not cached, the fact SHALL still be returned,
  marked source-not-cached (NOT omitted). This differs from SPEC-0006's
  "fully cited or omitted" omit-rule, which is scoped to message/search
  retrieval results, not contact facts

### Requirement: Per-Contact Deduplication

Restated facts SHALL collapse to a single row. `contact_facts` SHALL
enforce `UNIQUE(contact_id, fact_hash)` where `fact_hash` is a content
hash of the normalized fact text. Inserting a fact that already exists
for a contact SHALL be a no-op, so re-running extraction — or extracting
the same fact from two addresses merged onto one contact — never
duplicates it.

#### Scenario: Restated fact does not duplicate

- **WHEN** the model emits a fact whose `fact_hash` already exists for
  that `contact_id`
- **THEN** the insert SHALL be a no-op (e.g. `ON CONFLICT DO NOTHING`)
  and no duplicate row SHALL be created

#### Scenario: Same fact from two merged addresses collapses

- **WHEN** the same fact is drawn from messages on two different
  addresses that map to one contact
- **THEN** the `UNIQUE(contact_id, fact_hash)` constraint SHALL keep a
  single row for that contact

### Requirement: Incremental Cursor in fact_state

A per-contact `fact_state` row SHALL record the last processed message
hash and the model that produced its facts. `reduit facts` SHALL process
only messages newer than the recorded cursor and SHALL persist the
cursor as it advances, so a run is resumable and re-running with no new
messages is a no-op. When the stored model differs from the configured
model, extraction SHALL re-open the contact from the start and SHALL NOT
wipe prior facts (dedupe keeps the set clean).

#### Scenario: Only newer messages are processed

- **WHEN** `reduit facts` runs for a contact whose `fact_state` cursor
  points at a prior message
- **THEN** the system SHALL process only messages newer than the cursor
  position and SHALL advance the cursor as it proceeds

#### Scenario: Re-run with no new messages is a no-op

- **WHEN** `reduit facts` runs for a contact whose cursor is already at
  the newest message and the model is unchanged
- **THEN** the system SHALL make no LLM call for that contact and SHALL
  leave its facts unchanged

#### Scenario: Changing the model re-opens extraction without wiping

- **WHEN** the configured text model differs from the model stored in a
  contact's `fact_state`
- **THEN** the system SHALL re-process the contact from the start and
  SHALL NOT delete existing facts; new facts merge in and the
  `UNIQUE(contact_id, fact_hash)` constraint prevents duplicates

### Requirement: Privacy — Single Egress and Denylist

Extraction SHALL obey the single-egress boundary (ADR-0018): the only
outbound model call SHALL go through `internal/llm`. It SHALL honor the
per-conversation/sender denylist, and denylisted threads SHALL NEVER
contribute content to any fact. Filtering SHALL happen before content is
read, so denylisted message bodies never reach the extractor or the
model. Under the local-default posture, no message content SHALL leave
the device.

#### Scenario: Denylisted thread never contributes a fact

- **WHEN** a contact has messages in a denylisted conversation or from a
  denylisted sender
- **THEN** those messages SHALL be excluded before any content is read,
  SHALL never be sent to a model, and SHALL produce no `contact_facts`
  rows

#### Scenario: Extraction routes only through the single egress

- **WHEN** the extractor needs the model
- **THEN** the only outbound network call SHALL be via `internal/llm`
  (text/embedding role); the extractor SHALL NOT open any other egress

#### Scenario: Local default sends nothing off-device

- **WHEN** the text model role is configured to the local default
- **THEN** no message content SHALL leave the device during extraction

### Requirement: Surfacing via MCP and the UI Contact View

Stored facts SHALL be retrievable through an MCP tool (SPEC-0006), each
fact carrying its citation, and SHALL be shown in the loopback UI
contact view (SPEC-0005). Both surfaces SHALL read facts through the
**same store method**, so the two views cannot drift.

#### Scenario: MCP tool returns facts with citations

- **WHEN** an MCP client requests a contact's facts
- **THEN** the tool SHALL return the facts each with its
  `source_message_hash` (and resolvable source reference) so the caller
  can cite where a fact came from

#### Scenario: UI contact view shows the same facts

- **WHEN** the operator opens a contact in the loopback UI
- **THEN** the contact view SHALL display that contact's facts with
  links to their source messages

#### Scenario: One store method, no drift

- **WHEN** facts are read for either the MCP tool or the UI
- **THEN** both SHALL call the same store read method, so the MCP and UI
  surfaces always present the same fact set for a contact

### Requirement: Graceful Absence of an LLM Endpoint

With no reachable LLM endpoint, `reduit facts` SHALL fail cleanly with a
clear message and SHALL NOT corrupt or delete existing facts. Already
extracted facts SHALL remain readable via the MCP tool and the UI, and
the rest of Reduit (browsing, keyword search) SHALL be unaffected.

#### Scenario: Facts command fails cleanly with no endpoint

- **WHEN** `reduit facts` runs and no LLM endpoint is reachable
- **THEN** the command SHALL exit with a clear error, SHALL make no
  partial or corrupting writes, and SHALL leave `fact_state` and
  `contact_facts` intact

#### Scenario: Existing facts stay readable without an endpoint

- **WHEN** no endpoint is configured or reachable but prior facts exist
- **THEN** those facts SHALL remain retrievable via the MCP tool and the
  UI contact view, and browsing and keyword search SHALL keep working

## Out of Scope

- **Automatic cross-mailbox identity resolution / entity-linking.**
  `contacts` and `contact_identifiers` rows are populated during sync
  (SPEC-0002); recognizing that one person spans several addresses is
  supported via `contact_identifiers`. Where the identity is ambiguous,
  reconciliation is **manual** and owned by this spec via `reduit
  contacts merge` (see the Manual Identity Reconciliation requirement).
  No automatic merge/split heuristic is in scope.
- **CRM features.** Reminders, pipelines, follow-up tracking, and other
  relationship-management workflows are not in scope; facts are durable
  knowledge, not a CRM.
- **Hand-editing facts.** Manual creation, correction, or curation of
  facts is deferred; facts are LLM-derived and corrected by re-running
  (the schema stores facts as rows, leaving room to add editing later).
- **Fact extraction from attachments.** Extraction reads text message
  bodies first; attachment-derived facts (over extracted attachment
  text, ADR-0016) can come later.
