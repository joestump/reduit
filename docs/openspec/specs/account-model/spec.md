# SPEC-0001: Account Model

## Overview

Reduit distinguishes two concepts:

- A **user** is an OIDC-authenticated human, identified by the OIDC
  `sub` claim. A user is not a row in any table; the OIDC subject is
  the user identity, surfaced in-process as `Principal.Subject`.
- An **account** is the unit of multi-tenancy: one Proton mailbox
  configuration (refresh token, mailbox passphrase, key envelope) plus
  the per-account relay credentials (IMAP/SMTP password) used by
  email clients. Every account row is owned by exactly one user
  (`owner_oidc_sub`); a user MAY own zero or more accounts.

All account state is persisted in SQLite per ADR-0006; sensitive
fields are envelope-encrypted per ADR-0003.

Governing: ADR-0002 (multi-tenant), ADR-0003 (encryption), ADR-0004
(OIDC), ADR-0006 (SQLite), ADR-0010 (multi-Proton-account per user).

## Requirements

### Requirement: Account Identity

Every account MUST have a stable internal identifier. Account records
MUST also store the Proton user ID once Proton login completes; that
identifier disambiguates which Proton mailbox the account row
represents.

#### Scenario: Account creation generates a stable ID

- **WHEN** a new account is created
- **THEN** the system SHALL assign a UUIDv7 (or similar
  monotonically-sortable ID) and persist it as the primary key

#### Scenario: Proton user ID recorded on first successful login

- **WHEN** an account completes the Proton login flow for the first
  time
- **THEN** the system SHALL persist the Proton user ID (`proton_user_id`)
  on the account row. Subsequent logins for the same account MUST
  observe the same Proton user ID; a mismatch SHALL be treated as an
  error and SHALL NOT silently overwrite the stored value

### Requirement: Account Ownership by OIDC Subject

Every account row MUST carry an `owner_oidc_sub` column recording the
OIDC subject of the user who created the account. Ownership MUST be
immutable for the lifetime of the account row; reassignment is out of
scope.

#### Scenario: Account creation records the creator's OIDC subject

- **WHEN** an authenticated user (OIDC `sub` = S) creates a new
  account
- **THEN** the system SHALL persist `owner_oidc_sub = S` on the new
  row. The column MUST be `NOT NULL`

#### Scenario: A user MAY own multiple accounts

- **WHEN** an authenticated user with one or more existing accounts
  initiates the add-account flow
- **THEN** the system SHALL permit creation of an additional account
  row owned by the same OIDC subject. The system MUST NOT reject the
  creation on the grounds that the user already owns an account

#### Scenario: A user MUST NOT add the same Proton account twice

- **WHEN** an authenticated user attempts to create a second account
  whose `proton_user_id` matches an account they already own
- **THEN** the database SHALL reject the insert with a uniqueness
  constraint violation on `(owner_oidc_sub, proton_user_id)`. The
  application layer SHALL surface this as a friendly "you already
  added that Proton account" error, not a 500

#### Scenario: Two distinct users MAY in principle reference the same Proton mailbox

- **WHEN** two distinct OIDC subjects each create an account for the
  same `proton_user_id`
- **THEN** the database SHALL accept both rows. Access control at the
  relay (IMAP/SMTP credentials, MCP tokens) is per-account and
  remains the only authority on who can act on a given mailbox

#### Scenario: Ownership is immutable

- **WHEN** any code path attempts to update `owner_oidc_sub` on an
  existing account row
- **THEN** the storage layer SHOULD reject the update (e.g., via a
  trigger or by virtue of no migration touching the column). At
  minimum, no application code path SHALL issue such an update

### Requirement: User Identity Exists Without an Account

Successful OIDC login MUST establish the user identity for the
session regardless of whether the user owns any accounts. Account
creation MUST be a separate, deliberate action.

#### Scenario: First-time login does not create an account

- **WHEN** a user logs in via OIDC for the first time and the
  configured policy permits the login (allowlist or
  `OIDC_AUTO_CREATE`-equivalent gate)
- **THEN** the system SHALL establish a session bound to the OIDC
  `sub` claim. The system MUST NOT create an `accounts` row as a
  side effect of login

#### Scenario: Authenticated user with zero accounts is allowed

- **WHEN** an authenticated request arrives from a user who owns
  zero accounts
- **THEN** the system SHALL accept the session as valid. Routes
  that require an account in scope SHALL either redirect the user
  to the add-account wizard or surface an explicit "no accounts
  yet" state per SPEC-0005

### Requirement: Per-Account Data Key

Every account MUST own a unique 256-bit data key, generated at account
creation. The data key MUST be envelope-encrypted under the service
master key (per ADR-0003) and stored in the account row.

#### Scenario: Data key minted at account creation

- **WHEN** a new account is created
- **THEN** the system SHALL generate 32 bytes of cryptographically
  secure random data, seal it under the service master key using
  XChaCha20-Poly1305, and persist the ciphertext + nonce in the
  `key_envelope` column

#### Scenario: Data key never persists in plaintext

- **WHEN** the data key is in use during a request
- **THEN** the plaintext key MAY exist in process memory for the
  duration of the request, but MUST NOT be written to disk, logs, or
  any other sink

### Requirement: Encrypted Secret Storage

The following account fields MUST be encrypted at rest under the
account's data key before insert: Proton refresh token, Proton mailbox
passphrase, per-user IMAP/SMTP password.

#### Scenario: Refresh token sealed before insert

- **WHEN** a Proton refresh token is set on an account
- **THEN** the system SHALL seal it under the account's data key
  (XChaCha20-Poly1305 with a fresh nonce) and persist
  `nonce || ciphertext` in the `refresh_token_ciphertext` column

#### Scenario: Mailbox passphrase sealed before insert

- **WHEN** a Proton mailbox passphrase is set on an account
- **THEN** the system SHALL seal it under the account's data key with
  a fresh nonce and persist the result in
  `mailbox_passphrase_ciphertext`

#### Scenario: Per-user IMAP/SMTP password sealed before insert

- **WHEN** a per-user relay password is generated or rotated
- **THEN** the system SHALL seal it under the account's data key with
  a fresh nonce and persist the result in
  `imap_password_ciphertext`. A bcrypt or Argon2id hash of the same
  password SHALL also be stored in `imap_password_hash` for SASL
  authentication lookups; the encrypted form is for display in the
  admin UI on rotation only

### Requirement: Account Lifecycle States

Every account MUST have a `state` field whose value is one of:
`pending_proton_setup`, `active`, `suspended`, `soft_deleted`.

#### Scenario: New account starts in pending_proton_setup

- **WHEN** an account is created via OIDC login but Proton has not
  yet been configured
- **THEN** the account state SHALL be `pending_proton_setup`

#### Scenario: Successful Proton login transitions to active

- **WHEN** the Proton login flow completes (auth + 2FA + mailbox
  passphrase unlock all succeed) and a refresh token is persisted
- **THEN** the account state SHALL transition to `active` and the sync
  worker SHALL start

#### Scenario: Suspension halts sync but preserves state

- **WHEN** an admin suspends an account
- **THEN** the account state SHALL transition to `suspended`, the
  sync worker SHALL stop, and IMAP/SMTP authentication for that
  account SHALL fail with `[AUTHENTICATIONFAILED] Account suspended`

#### Scenario: Soft delete preserves audit data for retention period

- **WHEN** an account is deleted
- **THEN** the system SHALL transition state to `soft_deleted`, set
  `deleted_at` to the current time, stop the sync worker, and reject
  authentication. The row and ciphertexts MUST NOT be hard-deleted
  for the configured retention period (default 30 days)

### Requirement: Admin Status

Admin status is a property of the **user** (OIDC subject), not of
any one account row. Admin users MAY manage all accounts (create,
suspend, delete) regardless of ownership and access system diagnostic
routes.

#### Scenario: Admin status is sourced from the OIDC subjects allowlist

- **WHEN** an authenticated request is dispatched
- **THEN** the system SHALL treat the user as an admin if and only
  if the request's OIDC subject (`Principal.Subject`) appears in
  the configured admin-subjects allowlist (env: `OIDC_ADMIN_SUBS`,
  comma-separated). The check is performed against the user
  identity, not against any per-account row

#### Scenario: Non-admin cannot perform admin actions

- **WHEN** a non-admin user attempts to suspend, delete, or list
  an account they do not own
- **THEN** the system SHALL respond with HTTP 403 Forbidden and SHALL
  NOT mutate state

#### Scenario: User MAY act on accounts they own without being admin

- **WHEN** an authenticated, non-admin user initiates a management
  action (rotate credentials, configure MCP token, view dashboard)
  scoped to an account where `owner_oidc_sub` equals their OIDC
  subject
- **THEN** the system SHALL permit the action subject to the
  per-action scenarios defined elsewhere in this spec and in
  SPEC-0005

### Requirement: Account-Scoped Data

Every table that stores per-account state (mailbox UID maps, message
metadata cache, sync cursors, sessions, MCP tokens) MUST carry an
`account_id` column with a foreign-key constraint and an index. All
queries against these tables MUST filter by `account_id`.

#### Scenario: account_id foreign key on every per-account table

- **WHEN** a per-account table is created
- **THEN** its schema MUST include `account_id` with a foreign key
  reference to `accounts(id)` and `ON DELETE CASCADE` (cascade fires
  only when the account is hard-deleted after the retention period)

#### Scenario: Application code never queries without account scope

- **WHEN** application code reads or writes a per-account table
- **THEN** the query MUST include `WHERE account_id = ?`. This is
  enforced by linting / code review; a static-check rule is
  RECOMMENDED

### Requirement: Account Hard Delete After Retention

Soft-deleted accounts whose `deleted_at` is older than the configured
retention period MUST be hard-deleted by a periodic sweep job.

#### Scenario: Retention sweep removes expired soft-deleted accounts

- **WHEN** the retention sweep job runs and finds soft-deleted
  accounts with `deleted_at < now() - retention_period`
- **THEN** the system SHALL delete those rows, which SHALL cascade to
  all per-account tables, and SHALL log the deletion at INFO level
  with the account ID and OIDC subject (no other PII)

## Out of Scope

- OIDC group/role-based access control beyond the simple admin
  allowlist (deferred).
- Multi-instance / clustered deployment (single-host only for v1).
- Account export / migration to another Reduit instance (deferred).
