# SPEC-0001: Account Model

## Overview

Reduit distinguishes two persisted entities and one derived attribute:

- A **user** is a row in the `users` table sourced from OIDC. The
  `oidc_subject` column on `users` is `UNIQUE NOT NULL` and carries
  the OIDC `sub` claim of the authenticated human. Optional attributes
  (`email`, `display_name`) MAY be carried from the ID token's claims.
  A user MAY own zero or more accounts.
- An **account** is the unit of multi-tenancy: one Proton mailbox
  configuration (refresh token, mailbox passphrase, key envelope) plus
  the per-account relay credentials (IMAP/SMTP password) used by
  email clients. Every account row is owned by exactly one user via a
  `user_id` foreign key.
- **Admin status** is a derived, computed attribute, not a column on
  either table. At session-bind time (and only at session-bind time)
  the system checks whether the authenticated `Principal.Subject`
  appears in the configured `OIDC_ADMIN_SUBS` allowlist and tags the
  session accordingly. The tag is not recomputed per-request.

All persisted state is in SQLite per ADR-0006; sensitive account
fields are envelope-encrypted per ADR-0003.

Governing: ADR-0002 (multi-tenant; "tenant" now means user),
ADR-0003 (encryption), ADR-0004 (OIDC), ADR-0006 (SQLite),
ADR-0010 (multi-Proton-account per user).

## Requirements

### Requirement: User Identity

Every authenticated human MUST be represented by exactly one row in
the `users` table. The row is keyed by an internal UUIDv7 `id` and
carries a `UNIQUE NOT NULL` `oidc_subject` column matching the OIDC
`sub` claim. The user row is the canonical home for "who is the
human"; `Principal.Subject` from the request context resolves to
exactly one user row via this column.

#### Scenario: User row created on first successful OIDC login

- **WHEN** an OIDC login succeeds and no `users` row exists for the
  authenticating `Principal.Subject`
- **THEN** the system SHALL insert a new `users` row with a fresh
  UUIDv7 `id`, `oidc_subject = Principal.Subject`, `created_at = now()`,
  `last_login_at = now()`, and any optional ID-token claims
  (`email`, `display_name`) the system chooses to mirror

#### Scenario: Subsequent logins update last_login_at

- **WHEN** an OIDC login succeeds and a `users` row already exists for
  `Principal.Subject`
- **THEN** the system SHALL update `last_login_at = now()` on the
  existing row and bind the session to the existing `user_id`. No new
  row SHALL be created

#### Scenario: oidc_subject is unique

- **WHEN** any code path attempts to insert a `users` row whose
  `oidc_subject` matches an existing row
- **THEN** the database SHALL reject the insert via the `UNIQUE`
  constraint on `users(oidc_subject)`. The application SHALL never
  rely on a second row to carry the same OIDC subject

#### Scenario: User row exists with zero accounts

- **WHEN** a user has authenticated but has not yet completed the
  add-Proton-account wizard
- **THEN** the `users` row SHALL exist with no corresponding rows in
  `accounts`. This is a first-class, supported state. Any read query
  that joins `users` to `accounts` SHALL use a LEFT JOIN where it
  matters

### Requirement: Account Identity

Every account MUST have a stable internal identifier and MUST be
owned by exactly one user. Account records MUST also store the Proton
user ID once Proton login completes; that identifier disambiguates
which Proton mailbox the account row represents.

#### Scenario: Account creation generates a stable ID

- **WHEN** a new account is created
- **THEN** the system SHALL assign a UUIDv7 (or similar
  monotonically-sortable ID) and persist it as the primary key

#### Scenario: Account row carries a user_id foreign key

- **WHEN** an account row is created
- **THEN** the row MUST carry a `user_id` column referencing
  `users(id)` with `ON DELETE CASCADE`. The column MUST be `NOT NULL`.
  No code path SHALL create an `accounts` row without a resolved
  `user_id`

#### Scenario: Proton user ID recorded on first successful login

- **WHEN** an account completes the Proton login flow for the first
  time
- **THEN** the system SHALL persist the Proton user ID
  (`proton_user_id`) on the account row. Subsequent logins for the
  same account MUST observe the same Proton user ID; a mismatch SHALL
  be treated as an error and SHALL NOT silently overwrite the stored
  value

#### Scenario: A user MAY own multiple accounts

- **WHEN** an authenticated user with one or more existing accounts
  initiates the add-account flow
- **THEN** the system SHALL permit creation of an additional account
  row owned by the same `user_id`. The system MUST NOT reject the
  creation on the grounds that the user already owns an account

#### Scenario: A user MUST NOT add the same Proton account twice

- **WHEN** an authenticated user attempts to create a second account
  whose `proton_user_id` matches an account they already own
- **THEN** the database SHALL reject the insert with a uniqueness
  constraint violation on `(user_id, proton_user_id)`. The application
  layer SHALL surface this as a friendly "you already added that
  Proton account" error, not a 500

#### Scenario: Two distinct users MAY in principle reference the same Proton mailbox

- **WHEN** two distinct users each create an account for the same
  `proton_user_id`
- **THEN** the database SHALL accept both rows. Access control at the
  relay (IMAP/SMTP credentials, MCP tokens) is per-account and
  remains the only authority on who can act on a given mailbox

#### Scenario: Ownership is immutable

- **WHEN** any code path attempts to update `user_id` on an existing
  account row
- **THEN** the storage layer SHOULD reject the update (e.g., via a
  trigger or by virtue of no migration touching the column). At
  minimum, no application code path SHALL issue such an update.
  Reassignment of an account from one user to another is out of scope

### Requirement: Admin Status

Admin status is a property of the **user**, computed exactly once
per session at session-bind time from the OIDC subjects allowlist
(`OIDC_ADMIN_SUBS`). It MUST NOT be persisted as a column on
`users` or `accounts`, and it MUST NOT be recomputed per-request.
The allowlist is the single source of truth.

#### Scenario: Admin status is sourced from the OIDC subjects allowlist at session-bind time

- **WHEN** an authenticated session is bound (immediately after a
  successful OIDC `/auth/callback` exchange creates the session
  record)
- **THEN** the system SHALL set the session's admin tag to `true` if
  and only if the authenticated `Principal.Subject` appears in the
  configured `OIDC_ADMIN_SUBS` allowlist (env var, comma-separated).
  The check is performed against the user identity, never against any
  per-account row. The result SHALL be stored on the session payload
  (or kept in the in-process session struct — implementation detail)
  and SHALL NOT be recomputed on subsequent requests within the same
  session

#### Scenario: Per-request handlers read the cached admin tag, never the allowlist

- **WHEN** a request handler authorizes an admin-only operation
- **THEN** it SHALL read the admin tag from the bound session and
  SHALL NOT re-consult `OIDC_ADMIN_SUBS`. The tag computed at
  session-bind time is authoritative for the lifetime of that
  session

#### Scenario: Allowlist changes take effect on the next session bind

- **WHEN** the operator updates `OIDC_ADMIN_SUBS` and restarts the
  process (the v0.1 supported reconfiguration path; hot-reload is
  deferred), and an existing user re-authenticates so a fresh
  session is bound
- **THEN** the new session SHALL be tagged according to the updated
  allowlist. Sessions bound prior to the restart SHALL be
  invalidated by the restart itself in the v0.1 in-memory session
  store; if the SCS sqlite store ever outlives the process restart,
  the operator-facing reconfiguration procedure SHALL include an
  explicit session-invalidation step (truncate the sessions table,
  or call a `RevokeAllSessions` admin tool) so no stale admin tag
  survives a tightening of the allowlist

#### Scenario: No admin column exists on either users or accounts

- **WHEN** any code path persists a user row or an account row
- **THEN** the row SHALL NOT carry an `is_admin` column. Any code
  attempting to read `is_admin` from either table SHALL fail at
  compile / lint time

#### Scenario: Non-admin cannot perform admin actions

- **WHEN** a non-admin user attempts to suspend, delete, or list an
  account they do not own
- **THEN** the system SHALL respond with HTTP 403 Forbidden and SHALL
  NOT mutate state

#### Scenario: User MAY act on accounts they own without being admin

- **WHEN** an authenticated, non-admin user initiates a management
  action (rotate credentials, configure MCP token, view dashboard)
  scoped to an account whose `user_id` equals their session's
  `user_id`
- **THEN** the system SHALL permit the action subject to the
  per-action scenarios defined elsewhere in this spec and in
  SPEC-0005

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

- **WHEN** an account is created via the add-account wizard but Proton
  has not yet been configured
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

### Requirement: User Lifecycle

User rows have their own lifecycle, distinct from account lifecycle.
A user row MAY be removed; removal SHALL cascade to that user's
accounts via the `user_id` FK `ON DELETE CASCADE`.

#### Scenario: User removal cascades to accounts

- **WHEN** a `users` row is deleted (operator action; no UI surface
  in v0.1)
- **THEN** all `accounts` rows whose `user_id` matches SHALL be
  deleted by the FK cascade. Per-account state in dependent tables
  SHALL further cascade per the `account_id` FK on those tables

#### Scenario: User row persists across logout

- **WHEN** a user logs out (session destroyed)
- **THEN** the `users` row SHALL persist. Logout invalidates the
  session, not the user identity. Re-authentication binds a new
  session to the same `user_id`

### Requirement: Account-Scoped Data

Every table that stores per-account state (mailbox UID maps, message
metadata cache, sync cursors, sessions, MCP tokens) MUST carry an
`account_id` column with a foreign-key constraint and an index. All
queries against these tables MUST filter by `account_id`.

#### Scenario: account_id foreign key on every per-account table

- **WHEN** a per-account table is created
- **THEN** its schema MUST include `account_id` with a foreign key
  reference to `accounts(id)` and `ON DELETE CASCADE` (cascade fires
  when the account is hard-deleted after the retention period, or
  when its owning user is deleted)

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
  with the account ID and the owning user's `oidc_subject` (no other
  PII)

## Out of Scope

- OIDC group/role-based access control beyond the simple admin
  allowlist (deferred).
- Multi-OIDC-subject linking (one user attaching multiple OIDC
  identities) — orthogonal; the `users` table is a precondition,
  but the linking semantics are not specified here.
- Multi-instance / clustered deployment (single-host only for v1).
- Account export / migration to another Reduit instance (deferred).
- A user-management admin UI surface beyond the implicit "user is
  created on first login" path — admin-driven user removal is an
  operator-tool action in v0.1.
