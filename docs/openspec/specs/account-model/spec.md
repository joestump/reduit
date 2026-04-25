# SPEC-0001: Account Model

## Overview

An **Account** is the unit of multi-tenancy in Reduit. Each account
binds an OIDC identity (the human, authenticated via Pocket ID or
similar) to a Proton Mail account configuration (refresh token,
mailbox passphrase, key envelope) and the per-user relay credentials
(IMAP/SMTP password) used by their email clients. All account state is
persisted in SQLite per ADR-0006; sensitive fields are envelope-
encrypted per ADR-0003.

Governing: ADR-0002 (multi-tenant), ADR-0003 (encryption), ADR-0004
(OIDC), ADR-0006 (SQLite).

## Requirements

### Requirement: Account Identity

Every account MUST have a stable internal identifier and a unique
binding to one OIDC subject. Account records MAY also store the Proton
user ID for diagnostic and admin purposes once Proton login completes,
but the OIDC subject is the primary identity key.

#### Scenario: Account creation generates a stable ID

- **WHEN** a new account is created
- **THEN** the system SHALL assign a UUIDv7 (or similar
  monotonically-sortable ID) and persist it as the primary key

#### Scenario: One OIDC subject maps to one account

- **WHEN** a user's OIDC `sub` claim is presented to the system and an
  account already exists for that subject
- **THEN** the system MUST return the existing account; it MUST NOT
  create a duplicate

#### Scenario: OIDC subject uniqueness is enforced at the storage layer

- **WHEN** an attempt is made to insert a second account row with the
  same OIDC subject
- **THEN** the database SHALL reject the insert with a uniqueness
  constraint violation

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

### Requirement: Admin Flag

Every account MUST have an `is_admin` boolean. Admin accounts MAY
manage other accounts (create, suspend, delete) and access system
diagnostic routes.

#### Scenario: Admin status is configurable via OIDC subjects allowlist

- **WHEN** an account is created or refreshed
- **THEN** the system SHALL set `is_admin = true` if and only if the
  account's OIDC subject appears in the configured admin-subjects
  allowlist (env: `OIDC_ADMIN_SUBS`, comma-separated)

#### Scenario: Non-admin cannot perform admin actions

- **WHEN** a non-admin account attempts to suspend, delete, or list
  another account
- **THEN** the system SHALL respond with HTTP 403 Forbidden and SHALL
  NOT mutate state

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
