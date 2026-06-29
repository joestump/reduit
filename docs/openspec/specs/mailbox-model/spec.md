# SPEC-0001: Mailbox Model

## Overview

Reduit is a single-user, local-first tool: the OS user running the
binary *is* the identity. There is no login, no OIDC, no session store,
and no admin allowlist. What was once a two-entity "users + accounts"
model collapses to a single persisted entity — the **mailbox** — plus
the OS keychain that holds its secrets. A `mailboxes` row is a local
configuration record for one configured Proton mailbox, keyed by an
internal UUIDv7 `id`, carrying the `proton_user_id` recorded on first
successful auth, the mailbox `address`, and a lifecycle `state`. It
holds no secret: the Proton refresh token and the mailbox passphrase
live in the OS keychain (ADR-0013), referenced by `mailbox_id`.

One install MAY serve several Proton mailboxes for the one local user
(the operator's personal and family accounts, for example). Multi-
mailbox is a first-class v1 capability, not multi-tenancy: every
mailbox belongs to the same OS user, and "tenant" is not a concept.
The same Proton account MUST NOT be configured twice; distinct Proton
accounts MUST be addable side by side without a "you already have one"
rejection.

All derived state — cached messages, attachments, links, contacts,
embeddings, contact facts, sync cursors, FTS5 — lives in one SQLite
file in `data_dir` (ADR-0006) and is scoped per mailbox by a
`mailbox_id` column. The cache is derived and disposable; Proton is the
source of truth. No column is encrypted at the app layer; cache
confidentiality rests on OS full-disk encryption.

Governing: ADR-0012 (single-user local-first), ADR-0013 (secrets in OS
keychain), ADR-0006 (SQLite store), ADR-0014 (sync-and-cache),
SPEC-0011 (contact-level identity reconciliation).

## Requirements

### Requirement: Mailbox Identity

Every configured Proton mailbox MUST be represented by exactly one row
in the `mailboxes` table, keyed by an internal UUIDv7 `id`. The row
SHALL record the `proton_user_id` on first successful auth and treat it
as immutable thereafter; a later auth presenting a different
`proton_user_id` for the same row SHALL be an error and SHALL NOT
silently overwrite the stored value. The mailbox `address` SHALL be
stored on the row.

#### Scenario: Mailbox row created with a UUIDv7 id

- **WHEN** the operator adds a mailbox via `reduit auth`
- **THEN** the system SHALL insert a new `mailboxes` row with a fresh
  UUIDv7 `id`, the supplied `address`, `state = pending_auth`, and no
  `proton_user_id` yet

#### Scenario: proton_user_id recorded on first successful auth

- **WHEN** a mailbox completes the Proton auth flow for the first time
  and `proton_user_id` is currently unset on its row
- **THEN** the system SHALL persist the returned `proton_user_id` on
  the row and transition the mailbox to `active`

#### Scenario: proton_user_id is immutable after it is set

- **WHEN** a subsequent auth for an existing mailbox returns a
  `proton_user_id` different from the one stored on its row
- **THEN** the system SHALL treat this as an error and SHALL NOT
  overwrite the stored `proton_user_id`. The mailbox SHALL remain in
  its current state and the discrepancy SHALL be surfaced to the
  operator

### Requirement: Multi-Mailbox

One install MAY hold N `mailboxes` rows for the one local user. The
same Proton account MUST NOT be added twice: `proton_user_id` SHALL be
`UNIQUE` across the `mailboxes` table. Adding a distinct Proton account
MUST NOT be rejected on the grounds that a mailbox already exists.

#### Scenario: A second distinct mailbox is added

- **WHEN** the operator runs `reduit auth` for a Proton account whose
  `proton_user_id` does not match any existing row
- **THEN** the system SHALL create an additional `mailboxes` row for
  the same local user and MUST NOT reject the request because a mailbox
  already exists

#### Scenario: The same Proton account cannot be added twice

- **WHEN** an auth flow resolves a `proton_user_id` that already exists
  on another `mailboxes` row
- **THEN** the database SHALL reject the insert via the `UNIQUE`
  constraint on `mailboxes(proton_user_id)`, and the system SHALL
  surface a clear "that Proton account is already configured" message
  rather than creating a duplicate

#### Scenario: Mailboxes are independently namespaced

- **WHEN** two mailboxes are configured in one install
- **THEN** each SHALL have its own UUIDv7 `id`, its own keychain
  secret entries, and its own `mailbox_id`-scoped cache rows; no shared
  key or row SHALL span the two mailboxes

### Requirement: No Identity or Auth Layer

The schema SHALL NOT contain a `users` table, an `oidc_subject` column,
or an `is_admin` column on any table. The OS user is the identity;
there is no session store, no OIDC, and no admin role. Any code path
that reads such a column SHALL fail at compile or lint time.

#### Scenario: No users table exists

- **WHEN** the migrations are applied to a fresh database
- **THEN** the resulting schema SHALL contain no `users` table and no
  table whose primary purpose is to represent an authenticating human

#### Scenario: No identity or admin columns exist

- **WHEN** any code path persists a `mailboxes` row
- **THEN** the row SHALL NOT carry an `oidc_subject` or `is_admin`
  column. Any code attempting to read `oidc_subject` or `is_admin` from
  any table SHALL fail at compile or lint time

#### Scenario: The OS user is the identity

- **WHEN** the binary is invoked
- **THEN** the system SHALL act as the invoking OS user with no login,
  session bind, or authorization check, and SHALL NOT consult any
  external identity provider

### Requirement: Secret References, Not Secrets

A `mailboxes` row SHALL reference, never store, its secrets. Per-mailbox
secrets live in the OS keychain under service `reduit` and key
`mailbox/<id>/<kind>` where `<kind>` ∈ {`refresh_token`,
`mailbox_passphrase`}. The database SHALL NOT contain any secret,
ciphertext, key-envelope, or passphrase column.

#### Scenario: Secrets written to the keychain on first auth

- **WHEN** `reduit auth` completes for a mailbox
- **THEN** the system SHALL write the Proton refresh token to keychain
  key `mailbox/<id>/refresh_token` and the mailbox passphrase to
  `mailbox/<id>/mailbox_passphrase` under service `reduit`, and SHALL
  store only the `mailbox_id` reference in the database

#### Scenario: No secret columns in the schema

- **WHEN** the migrations are applied to a fresh database
- **THEN** no table SHALL contain a column holding a secret value
  (refresh token, mailbox passphrase, key envelope, or any
  ciphertext). Secrets are retrieved from the keychain by `mailbox_id`
  at use time

#### Scenario: Secret retrieval is keyed by mailbox id

- **WHEN** a sync or send operation needs a mailbox's refresh token or
  passphrase
- **THEN** the system SHALL read it from the OS keychain using the
  `mailbox/<id>/<kind>` key derived from the row's `id`, and SHALL NOT
  read it from any database column

### Requirement: Per-Mailbox Cache Scoping

Every cache table that stores per-mailbox state SHALL carry a
`mailbox_id` column. Per-mailbox reads SHALL filter on `mailbox_id`;
global or cross-mailbox reads MAY omit it. Deleting a mailbox SHALL
cascade its `mailbox_id`-scoped cache rows and SHALL delete its
keychain entries.

#### Scenario: Per-mailbox table carries mailbox_id

- **WHEN** a per-mailbox cache table (e.g. `messages`, `sync_state`) is
  created
- **THEN** its schema SHALL include a `mailbox_id` column referencing
  the owning mailbox, indexed for the per-mailbox read path

#### Scenario: Per-mailbox read filters on mailbox_id

- **WHEN** application code reads cached state scoped to a single
  mailbox
- **THEN** the query SHALL include `WHERE mailbox_id = ?` so results do
  not bleed across mailboxes

#### Scenario: Cross-mailbox read may omit mailbox_id

- **WHEN** a global search or cross-mailbox aggregation runs over the
  cache
- **THEN** the query MAY omit the `mailbox_id` filter and operate over
  all mailboxes; derived hash-keyed tables (`embeddings`,
  `contact_facts`) MAY be shared across mailboxes

#### Scenario: Deleting a mailbox cascades cache and deletes secrets

- **WHEN** a mailbox is removed
- **THEN** the system SHALL delete its `mailbox_id`-scoped cache rows
  (via FK cascade) and SHALL delete its keychain entries
  `mailbox/<id>/refresh_token` and `mailbox/<id>/mailbox_passphrase`

### Requirement: Mailbox Lifecycle and State

Every `mailboxes` row SHALL carry a `state` field whose value is one of
`pending_auth`, `active`, `needs_reauth`, `removed`. The system SHALL
drive transitions only along the defined lifecycle and SHALL NOT place
a mailbox in an undefined state.

#### Scenario: New mailbox starts in pending_auth

- **WHEN** a mailbox row is created via `reduit auth` but auth has not
  yet completed
- **THEN** its `state` SHALL be `pending_auth`

#### Scenario: Successful auth transitions to active

- **WHEN** the Proton auth flow completes and the refresh token and
  passphrase are written to the keychain
- **THEN** the mailbox `state` SHALL transition to `active` and sync
  MAY begin

#### Scenario: Invalid refresh token transitions to needs_reauth

- **WHEN** a sync or send operation observes that the stored Proton
  refresh token is invalid or revoked
- **THEN** the mailbox `state` SHALL transition to `needs_reauth`,
  sync SHALL stop for that mailbox, and the operator SHALL be directed
  to re-run `reduit auth` to supply fresh credentials

#### Scenario: Removal cascades cache and deletes keychain entries

- **WHEN** the operator removes a mailbox
- **THEN** the system SHALL transition it to `removed` (or delete the
  row), cascade-delete its `mailbox_id`-scoped cache rows, and delete
  its keychain entries; no orphaned secret SHALL remain in the keychain

## Out of Scope

- Multi-user / OIDC / admin RBAC — there is no `users` table, no
  identity provider, and no role model (ADR-0012).
- Account export or migration to another Reduit install.
- Identity reconciliation across mailboxes — recognizing that one
  person spans several addresses is a contact-level concern handled in
  SPEC-0011, not the mailbox model.
- Network-served relay surfaces (IMAP/SMTP listeners, TLS) — removed by
  ADR-0012; run Proton Bridge for those.
