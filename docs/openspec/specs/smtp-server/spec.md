# SPEC-0004: SMTP Submission Server

## Overview

The Reduit **SMTP submission server** serves SMTPS (port 465) to
email clients for outgoing mail. It implements `emersion/go-smtp`'s
`Backend` interface, routes authentication to per-account state, and
hands accepted messages to a per-account outbox worker that handles
Proton-side encryption and submission via `go-proton-api`.

Governing: ADR-0001 (go-proton-api), ADR-0007 (emersion libraries),
ADR-0009 (TLS via disk), SPEC-0001 (Account Model), SPEC-0003 (IMAP
Server) for parallel auth model.

## Requirements

### Requirement: TLS Required, SMTPS Only

The server MUST listen on a single SMTPS port (default 465).
Plaintext SMTP submission and STARTTLS-from-cleartext MUST NOT be
supported.

#### Scenario: Cleartext connections are refused

- **WHEN** a client connects without negotiating TLS
- **THEN** the server SHALL close the connection without responding

#### Scenario: TLS config is sourced from the hot-reloading loader

- **WHEN** the SMTP server starts
- **THEN** its `tls.Config.GetCertificate` SHALL be wired to the
  shared cert loader from ADR-0009

### Requirement: SASL PLAIN Authentication Matching IMAP

The server MUST advertise `AUTH PLAIN` and accept the same `user@host`
identity form as the IMAP server (SPEC-0003), validated against the
same `accounts.imap_password_hash` column.

#### Scenario: Single password for IMAP and SMTP

- **WHEN** a user has a per-user relay password
- **THEN** the same password SHALL authenticate both IMAP and SMTP
  for that user. Separate passwords per protocol are NOT supported

#### Scenario: AUTH announced only after TLS

- **WHEN** a client requests `EHLO` over a TLS-negotiated connection
- **THEN** the response SHALL include `AUTH PLAIN`. Without TLS, the
  connection SHALL not have reached this state per the previous
  requirement

### Requirement: Submission Authorization

After successful authentication, an outgoing message MUST be authorized
against the authenticated account's identities. The `MAIL FROM`
address MUST match one of the account's known Proton aliases.

#### Scenario: MAIL FROM matches a known alias

- **WHEN** an authenticated session issues `MAIL FROM:<joe@stump.rocks>`
  and `joe@stump.rocks` is one of the account's Proton-configured
  email aliases
- **THEN** the server SHALL accept the command with `250 OK`

#### Scenario: MAIL FROM does not match any alias

- **WHEN** an authenticated session issues `MAIL FROM:<not-mine@example.com>`
  with an address not bound to the authenticated account
- **THEN** the server SHALL respond with
  `553 5.7.1 Sender address rejected: not authorized for this account`

### Requirement: Recipient and Message Size Limits

The server MUST enforce reasonable limits on recipient count and
message size. Limits MUST be configurable.

#### Scenario: Recipient limit

- **WHEN** the configured `MAX_RECIPIENTS` is 100 and a session
  issues a 101st `RCPT TO`
- **THEN** the server SHALL respond with `452 4.5.3 Too many recipients`

#### Scenario: Message size limit

- **WHEN** the configured `MAX_MESSAGE_BYTES` is 25 MiB and a
  message exceeds that size
- **THEN** the server SHALL respond with
  `552 5.3.4 Message too large`. The size limit SHALL be advertised
  via `EHLO` `SIZE` extension

### Requirement: Outbox Handoff and Synchronous Confirmation

After `DATA` completes, the server MUST hand the message to a
per-account outbox worker that performs encryption and Proton
submission. The SMTP response (250 OK or 5xx) MUST reflect the
outcome of submission, not just acceptance into the queue.

#### Scenario: Synchronous send is the primary path

- **WHEN** a message is submitted, the user is authenticated, and the
  envelope is valid
- **THEN** the server SHALL block on the outbox worker's submission
  result. On success the server SHALL respond `250 OK`. On Proton
  failure the server SHALL map the failure to an SMTP error code and
  respond accordingly

#### Scenario: Submission timeout

- **WHEN** the outbox worker has not returned within the configured
  `SMTP_SUBMIT_TIMEOUT` (default 60s)
- **THEN** the server SHALL respond with
  `451 4.4.7 Submission timed out, message will be retried`. The
  outbox worker SHALL continue retrying in the background and
  surface eventual outcomes via IMAP Drafts (deferred / per
  SPEC-0005)

### Requirement: Encryption Pipeline

For each recipient, the system MUST select the appropriate Proton
encryption mode: end-to-end PGP for Proton recipients, plain SMTP
relay for external recipients with no published key, optional
end-to-end PGP for external recipients with a published key.

#### Scenario: Proton recipient gets E2E

- **WHEN** an outgoing recipient is `someone@proton.me` (or any
  Proton-hosted address) and Proton's address-key lookup returns a
  key
- **THEN** the system SHALL encrypt the message body to that
  recipient's public key, signed by the sender's primary key, before
  handing it to Proton for submission

#### Scenario: External recipient with no published key gets plain

- **WHEN** an outgoing recipient is `someone@external.tld` and
  Proton's key lookup returns no key
- **THEN** the system SHALL submit the message in cleartext (relayed
  via Proton's outbound MTA). The signing key SHALL still be applied
  if the user has signing enabled in Proton

#### Scenario: External recipient with WKD/public-key gets optional E2E

- **WHEN** an outgoing recipient is `someone@external.tld`, Proton's
  key lookup returns a key, and the user's account configuration
  enables E2E to external recipients
- **THEN** the system SHALL encrypt the message body to that key.
  v0.1 MAY default this to the same behavior as the Proton web client
  (controlled by the account's "encrypt to outside" preferences in
  Proton)

### Requirement: Sent Folder Materialization

A successful send MUST result in a copy of the sent message appearing
in the user's IMAP `Sent` folder within 5 seconds.

#### Scenario: Sent message visible via IDLE

- **WHEN** a send completes successfully and an IMAP IDLE session is
  selected on `Sent`
- **THEN** the IDLE session SHALL receive an `EXISTS` notification
  for the new message within 5 seconds. This happens via Proton's
  event stream (the sync worker materializes the new message)

### Requirement: Per-Account Outbox Concurrency Limit

The outbox MAY process multiple sends concurrently per account, but
MUST cap concurrency to prevent a single account from exhausting
Proton API quotas or system resources.

#### Scenario: Per-account concurrency cap

- **WHEN** the configured per-account outbox concurrency cap is `N`
  and `N` sends are in flight for the account
- **THEN** additional submissions SHALL queue. Default cap: 4

### Requirement: Account Isolation in SMTP

An authenticated SMTP session MUST only submit on behalf of its
authenticated account. Cross-account submission MUST be impossible.

#### Scenario: MAIL FROM is bound to authenticated account only

- **WHEN** an authenticated session as account A attempts to set
  `MAIL FROM` to an alias of account B
- **THEN** the server SHALL reject per the alias-mismatch rule above.
  No special-case for admins; admins still send only as themselves

### Requirement: Per-Session Authentication Lifetime

A session's authentication MUST be revoked immediately if the account
is suspended or deleted; in-flight `DATA` commands SHALL fail.

#### Scenario: Suspension drops live SMTP sessions

- **WHEN** an admin suspends an account with a live SMTP session that
  is in `DATA` mode
- **THEN** the server SHALL respond `451 4.7.1 Account suspended`
  and close the connection within 1 second

## Out of Scope

- Outbound TLS verification of relayed mail (Proton handles outbound
  delivery; Reduit doesn't relay externally).
- DSN generation by Reduit (Proton produces DSNs; they arrive via
  the sync worker as new messages in the Inbox).
- DKIM / SPF signing (Proton signs outbound mail with its own keys).
- ARC / DMARC awareness.
- Multi-recipient batching beyond what go-smtp provides natively.
