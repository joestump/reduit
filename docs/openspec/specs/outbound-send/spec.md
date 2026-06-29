# SPEC-0010: Outbound Send

## Overview

Reduit is otherwise a read-and-search tool; **send** is the one place it
writes to Proton (ADR-0020). There is no SMTP submission server and no
relay (ADR-0012): outbound mail is an internal capability, not a
protocol endpoint. Reduit builds the message and submits it through the
existing `go-proton-api` client (ADR-0001) — the same client used for
auth, sync, and decrypt — reusing that client's OpenPGP composition and
recipient-key handling. The source mailbox's passphrase, read from the
OS keychain (ADR-0013) by `mailbox/<id>/mailbox_passphrase`, unlocks the
signing and encryption keys for that send.

Send is exposed on two surfaces that share **one** internal routine: a
CLI verb (`reduit send --from <mailbox> --to … --subject … [body /
attachments]`) and an MCP `send` tool (ADR-0017). The MCP `send` tool is
the **only** mutating tool in the otherwise read-only MCP surface, so it
is guarded: it requires explicit, unambiguous invocation with all
required fields and MUST NOT fire as a silent side effect. Because both
surfaces funnel through the same routine, behavior — encryption,
from-mailbox resolution, error surfacing, local reflection — cannot
diverge between them.

This is submission of a user-composed message, not an MTA: there is no
spooling, no server-side retry, and no onward relay. A failed send
surfaces an error to the caller. A successful send is reflected in the
local cache — by the next sync picking up the Sent folder and/or an
immediate local insert — and reconciled by the idempotent stable-hash
keying (ADR-0014) so the Sent item is never duplicated when sync later
observes it.

Governing: ADR-0020 (outbound send via go-proton-api), ADR-0001
(go-proton-api as Proton client), ADR-0013 (secrets in OS keychain),
ADR-0017 (stdio MCP, the send tool as sole mutator), ADR-0014
(sync-and-cache, stable-hash keying), SPEC-0001 (mailbox model).

## Requirements

### Requirement: Compose, Encrypt, and Submit via go-proton-api

Reduit SHALL build the outbound message and submit it through the
existing `go-proton-api` client, reusing that client's OpenPGP
composition and recipient-key handling rather than reimplementing
encryption. The system SHALL unlock the source mailbox's signing and
encryption keys using the mailbox passphrase read from the OS keychain
(ADR-0013) at send time, and SHALL NOT read the passphrase from any
database column. Send SHALL NOT introduce any SMTP submission server,
listener, or relay.

#### Scenario: Message composed and submitted through the Proton client

- **WHEN** a send is invoked with a valid from-mailbox, recipients,
  subject, and body
- **THEN** the system SHALL compose and encrypt the message using the
  existing `go-proton-api` client's OpenPGP/recipient-key handling and
  SHALL submit it through that client, with no SMTP path involved

#### Scenario: Passphrase unlocks keys from the keychain at send time

- **WHEN** a send needs the source mailbox's signing/encryption keys
- **THEN** the system SHALL read the mailbox passphrase from the OS
  keychain key `mailbox/<id>/mailbox_passphrase` to unlock those keys,
  and SHALL NOT read it from any database column

#### Scenario: No SMTP or relay surface is created

- **WHEN** the send capability is built and exercised
- **THEN** the system SHALL NOT open an SMTP listener, bind a
  submission port, or relay onward; send SHALL remain an internal call
  into `go-proton-api`

### Requirement: Explicit From-Mailbox

Every send SHALL name its source mailbox explicitly. The system SHALL
NOT apply an implicit or fallback default mailbox that could send from
the wrong account. A send whose from-mailbox is absent, unknown, or not
in a sendable state SHALL be rejected with a clear error rather than
silently resolved.

#### Scenario: From-mailbox is required

- **WHEN** a send is invoked without a from-mailbox
- **THEN** the system SHALL reject the send with a clear error and
  SHALL NOT select a default mailbox on the caller's behalf

#### Scenario: Unknown from-mailbox is rejected

- **WHEN** a send names a from-mailbox that does not resolve to an
  existing `mailboxes` row
- **THEN** the system SHALL reject the send with an error identifying
  the unknown mailbox and SHALL NOT fall back to another mailbox

#### Scenario: From-mailbox must be in a sendable state

- **WHEN** a send names a mailbox whose `state` is not `active` (e.g.
  `pending_auth`, `needs_reauth`)
- **THEN** the system SHALL reject the send with an error directing the
  operator to authenticate that mailbox, and SHALL NOT send from a
  different mailbox

### Requirement: One Routine, Two Surfaces

The CLI verb `reduit send` and the MCP `send` tool SHALL both call the
same internal send routine. Encryption, from-mailbox resolution,
recipient handling, error surfacing, and local reflection SHALL be
implemented once in that routine so the two surfaces cannot diverge.
Neither surface SHALL contain its own parallel send implementation.

#### Scenario: CLI and MCP share the send routine

- **WHEN** a send is initiated from either `reduit send` or the MCP
  `send` tool with equivalent inputs
- **THEN** both SHALL invoke the same internal send routine and SHALL
  produce equivalent composition, encryption, and local-reflection
  behavior

#### Scenario: Behavior cannot diverge between surfaces

- **WHEN** a change is made to send behavior (e.g. encryption-mode
  selection or local reflection)
- **THEN** it SHALL be made in the shared routine and apply to both
  surfaces; a surface-local override of send behavior SHALL NOT exist

### Requirement: Agent-Safe MCP Send

The MCP `send` tool SHALL be the only mutating MCP tool and SHALL
require explicit, unambiguous invocation carrying all required fields:
from-mailbox, recipients, subject, and body. It SHALL NOT fire as a
silent or automatic side effect of any other tool or flow. An
invocation that is ambiguous or missing a required field SHALL be
rejected with a clear, actionable error rather than guessed or
partially executed.

#### Scenario: Send requires all required fields

- **WHEN** the MCP `send` tool is called missing any of from-mailbox,
  recipients, subject, or body
- **THEN** the tool SHALL reject the call with an error naming the
  missing field(s) and SHALL NOT send a partial message

#### Scenario: Ambiguous invocation is rejected

- **WHEN** the MCP `send` tool is called with ambiguous or
  underspecified arguments (e.g. an unresolvable recipient or an
  unnamed from-mailbox)
- **THEN** the tool SHALL reject the call with a clear error and SHALL
  NOT infer or auto-fill the ambiguous value

#### Scenario: Send never fires as a silent side effect

- **WHEN** any read-only tool or agent flow runs
- **THEN** it SHALL NOT cause mail to be sent; sending SHALL occur only
  on an explicit `send` invocation, the sole mutating tool

### Requirement: Local Reflection of Sent Mail

A successful send SHALL become visible and searchable in the local
cache, either by the next sync picking up the Sent folder, by an
immediate local insert, or both. When both occur, the idempotent
stable-hash keying (ADR-0014) SHALL reconcile them so a single sent
message appears exactly once; sync observing the Sent item later SHALL
NOT create a duplicate.

#### Scenario: Sent message becomes locally searchable

- **WHEN** a send completes successfully
- **THEN** the message SHALL be reflected in the local cache (via next
  sync of the Sent folder and/or an immediate local insert) and SHALL
  be returned by local search like received mail

#### Scenario: No duplicate when sync later sees the Sent item

- **WHEN** an immediate local insert recorded a sent message and a
  later sync observes the same message in the Sent folder
- **THEN** the stable-hash keying SHALL reconcile them to one row, and
  the message SHALL NOT appear twice in the cache or in search results

### Requirement: No MTA Semantics

Send SHALL be treated as submission of a single user-composed message,
not as a mail transfer agent. The system SHALL NOT spool the message,
SHALL NOT perform server-side retry of its own, and SHALL NOT relay the
message onward. A failed send SHALL surface an error directly to the
caller (CLI exit/error or MCP tool error).

#### Scenario: Failed send surfaces an error, not a queue

- **WHEN** a send fails (e.g. Proton submission error, invalid
  recipient key, revoked token)
- **THEN** the system SHALL surface the error to the caller and SHALL
  NOT spool the message or schedule its own retry

#### Scenario: No onward relay or spooling

- **WHEN** a send is invoked
- **THEN** the system SHALL submit exactly once through `go-proton-api`
  and SHALL NOT hold the message in a server-side queue or relay it to
  another host

### Requirement: Attachments

Send SHALL support attaching files to the outbound message.
Attachments SHALL be encrypted per Proton through the existing
`go-proton-api` client's attachment handling, consistent with the
message body's encryption mode for each recipient.

#### Scenario: Send with attachments

- **WHEN** a send is invoked with one or more attachments
- **THEN** the system SHALL include them in the submitted message,
  encrypted per Proton via the existing client, with no separate
  unencrypted attachment path

#### Scenario: Attachment failure surfaces an error

- **WHEN** an attachment cannot be read or encrypted
- **THEN** the system SHALL reject the send with a clear error
  identifying the attachment and SHALL NOT send the message without it

### Requirement: Recipient Encryption Modes

The system SHALL handle Proton-internal (end-to-end encrypted)
recipients and external recipients per `go-proton-api`'s capabilities,
selecting the appropriate path per recipient. The system SHALL surface
clearly which encryption path applies so the caller is not misled about
the confidentiality of a given send.

#### Scenario: Proton-internal recipient uses E2E

- **WHEN** a recipient resolves to a Proton address with a published
  public key
- **THEN** the system SHALL encrypt to that recipient end-to-end via
  the client's recipient-key handling and SHALL reflect that this path
  was used

#### Scenario: External recipient path is surfaced

- **WHEN** a recipient is external and lacks a Proton public key
- **THEN** the system SHALL use the appropriate external path supported
  by `go-proton-api` and SHALL surface to the caller that the send to
  that recipient is not Proton-internal E2E

## Out of Scope

- Re-adding an SMTP submission server or relay — removed by ADR-0012;
  send is an internal `go-proton-api` call, not a protocol endpoint.
- Scheduled or delayed send — send submits immediately; there is no
  timer, spool, or send-later queue.
- Mailing-list or bulk-send semantics — this is single-message
  submission, not list expansion or batch delivery.
- Draft management and draft storage — a compose affordance in
  SPEC-0005 MAY call this send routine, but persisting, editing, or
  syncing drafts is not handled here.
- Server-side retry or MTA queueing — a failed send returns an error to
  the caller (see No MTA Semantics).
