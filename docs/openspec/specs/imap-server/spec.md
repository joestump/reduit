# SPEC-0003: IMAP Server

## Overview

The Reduit **IMAP server** serves IMAPS (port 993) to email clients.
It implements `emersion/go-imap` v2's `Backend` and `Session`
interfaces, routes authentication to the per-account state from
SPEC-0001, and exposes Proton mailboxes as IMAP folders. UIDs are
assigned and persisted locally per ADR-0010 (deferred); label/folder
mapping is governed by ADR-0011 (deferred). This spec covers the
server-level behavior all clients depend on.

Governing: ADR-0007 (emersion libraries), ADR-0009 (TLS via disk),
SPEC-0001 (Account Model), SPEC-0002 (Sync Worker).

## Requirements

### Requirement: TLS Required, IMAPS Only

The server MUST listen on a single IMAPS port (default 993). Plaintext
IMAP, STARTTLS-from-cleartext, and unencrypted authentication MUST
NOT be supported.

#### Scenario: Cleartext connections are refused

- **WHEN** a client connects without negotiating TLS
- **THEN** the server SHALL close the connection without responding
  to any IMAP command

#### Scenario: TLS config is sourced from the hot-reloading loader

- **WHEN** the IMAP server starts or restarts
- **THEN** its `tls.Config.GetCertificate` SHALL be wired to the
  shared cert loader from ADR-0009. Cert rotation MUST NOT require
  an IMAP server restart

### Requirement: SASL PLAIN Authentication With user@host Identity

The server MUST advertise `AUTH=PLAIN` (and only `PLAIN`) and accept
authentication from clients sending the username in `user@host`
form.

#### Scenario: PLAIN is the only advertised SASL mechanism

- **WHEN** a client requests `CAPABILITY`
- **THEN** the response SHALL include `AUTH=PLAIN` and SHALL NOT
  include `AUTH=LOGIN`, `AUTH=CRAM-MD5`, `AUTH=DIGEST-MD5`,
  `AUTH=ANONYMOUS`, or any GSSAPI mechanism

#### Scenario: user@host identifies the local user

- **WHEN** a SASL PLAIN response presents an identity of the form
  `local@host`
- **THEN** the server SHALL look up the account whose primary email
  alias is `local@host` and validate the password against
  `accounts.imap_password_hash`

#### Scenario: Authentication failure returns NO with no detail

- **WHEN** authentication fails for any reason (bad password, account
  suspended, account does not exist)
- **THEN** the server SHALL respond with `NO [AUTHENTICATIONFAILED]`
  and SHALL NOT distinguish between failure modes in the response.
  The reason SHALL be logged at INFO level with structured fields

#### Scenario: Suspended account is rejected even with correct password

- **WHEN** the account exists, the password is correct, but the
  account is in state `suspended` or `soft_deleted`
- **THEN** authentication SHALL fail. The server MAY include
  `[AUTHENTICATIONFAILED] Account suspended` for diagnostics

### Requirement: UID Stability

Each (account, mailbox) pair MUST have a `UIDVALIDITY` value assigned
at creation. UIDs within a mailbox MUST be monotonically increasing
and locally assigned by Reduit; they MUST NOT change for the lifetime
of the account+mailbox.

#### Scenario: UIDVALIDITY assigned at first sync

- **WHEN** a new mailbox is created for an account (either Proton
  system folder or a user label discovered during sync)
- **THEN** the system SHALL assign a `UIDVALIDITY` (Unix timestamp at
  microsecond precision is sufficient) and persist it. UIDVALIDITY
  MUST NOT change unless the local mailbox state is rebuilt from
  scratch (e.g., a `reduit reset-mailbox` operation, deferred)

#### Scenario: UID assignment is monotonic

- **WHEN** a new message arrives in a mailbox
- **THEN** the system SHALL assign it a UID greater than every UID
  previously assigned in that mailbox, regardless of message arrival
  order in Proton's event stream

#### Scenario: Reused message ID does not get a reused UID

- **WHEN** a Proton message ID that was previously expunged from a
  mailbox is re-added to the same mailbox (label removal then
  re-addition)
- **THEN** the system SHALL assign a fresh UID greater than the
  current `UIDNEXT`, never reuse the prior UID

### Requirement: Folder Hierarchy and Mapping

Proton system folders MUST map to standard IMAP folder names. Proton
user labels MUST appear under a `Labels/` namespace.

#### Scenario: System folders map to standard names

- **WHEN** a client lists folders
- **THEN** the response SHALL include: `INBOX`, `Sent`, `Drafts`,
  `Trash`, `Spam`, `Archive`, `All Mail`. Each maps to the
  corresponding Proton system folder (`Inbox`, `Sent`, `Drafts`,
  `Trash`, `Spam`, `Archive`, `All Mail` respectively)

#### Scenario: User labels appear under Labels/

- **WHEN** the user has Proton labels named `Receipts`, `Family/Tax`,
  and `Family/Trips`
- **THEN** the folder list SHALL include `Labels/Receipts`,
  `Labels/Family/Tax`, `Labels/Family/Trips`. The `/` separator is
  preserved from Proton's nested label semantics

#### Scenario: Moving between system folders changes Proton system flag

- **WHEN** a client moves a message from `INBOX` to `Archive`
- **THEN** the system SHALL apply the corresponding Proton operation
  (remove `Inbox` label, add `Archive` label) and the change SHALL
  be visible to other clients within 1 second via IDLE

#### Scenario: Moving between Labels/ folders adjusts labels additively

- **WHEN** a client moves a message from `Labels/Foo` to `Labels/Bar`
- **THEN** the system SHALL remove the `Foo` label and add the `Bar`
  label on Proton

### Requirement: IDLE Support With Live Updates

The server MUST support `IDLE`. While in IDLE, the server MUST emit
`EXISTS`, `EXPUNGE`, and `FETCH` untagged responses from
SPEC-0002's pubsub notifications within 1 second of the corresponding
Proton event.

#### Scenario: IDLE emits EXISTS within 1s of new message

- **WHEN** a client is in IDLE on a mailbox and a new message arrives
  via the sync worker
- **THEN** the server SHALL emit `* {N} EXISTS` within 1 second

#### Scenario: IDLE timeout matches RFC

- **WHEN** a client has been in IDLE for 29 minutes without server-
  initiated activity
- **THEN** the server SHALL emit `* BYE Idle timeout` and close the
  connection per RFC 2177 recommendations

### Requirement: Concurrent Sessions Per Account

Multiple email clients for the same account MUST be able to connect
concurrently without state corruption.

#### Scenario: Multiple devices co-IDLE on same mailbox

- **WHEN** the user has Apple Mail on an iPhone and Thunderbird on a
  laptop, both connected to the same account, both IDLE on INBOX
- **THEN** both clients SHALL receive the same `EXISTS` /
  `EXPUNGE` / `FETCH` updates. Neither client's session SHALL block
  the other

#### Scenario: Per-session state is isolated

- **WHEN** session A selects INBOX and session B selects Sent
- **THEN** the server's per-session state (selected mailbox, fetch
  cursor, deleted flags pending expunge) SHALL be isolated. Commands
  in one session MUST NOT affect the other's state

### Requirement: Account Isolation in IMAP Operations

An authenticated session MUST only access state belonging to its
authenticated account.

#### Scenario: LIST shows only own folders

- **WHEN** session A (account X) issues `LIST`
- **THEN** the response SHALL contain only mailboxes belonging to
  account X. Mailboxes for any other account MUST NOT appear

#### Scenario: SELECT of a non-owned mailbox fails as not-found

- **WHEN** a malicious or buggy client constructs a mailbox name
  guess for another account
- **THEN** the server SHALL return `NO Mailbox does not exist`,
  identical to a genuine not-found case. No information leakage

### Requirement: Per-Session Authentication Lifetime

A session's authentication MUST be revoked immediately if the account
is suspended or deleted. Existing IMAP commands MUST NOT continue
operating after revocation.

#### Scenario: Suspension drops live sessions

- **WHEN** an admin suspends an account that currently has live IMAP
  sessions
- **THEN** the server SHALL emit `* BYE Account suspended` on each
  live session and close them within 1 second

## Out of Scope

- IMAP CONDSTORE / QRESYNC extensions (deferred; clients fall back to
  full RESYNC).
- Server-side search beyond what `go-imap` provides natively (Proton's
  full-text search wired in v0.2+).
- IMAP quota extension (deferred).
- Multi-IMAPS-port support per account (single shared port for all
  accounts).
