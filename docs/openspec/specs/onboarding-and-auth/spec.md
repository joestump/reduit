# SPEC-0007: Onboarding & Proton Auth

## Overview

Reduit has no login screen, no OIDC, and no network listener; the only
way a Proton mailbox enters the system is the local, interactive
`reduit auth` command run by the OS user at a terminal. This spec
defines that flow: it walks the operator from an email address through
SRP password authentication, optional TOTP 2FA, and mailbox-passphrase
unlock, creating exactly one `mailboxes` row (SPEC-0001) that starts in
`pending_auth` and transitions to `active` on success, with the
`proton_user_id` recorded on first auth and treated as immutable.

All Proton-protocol work — SRP, 2FA challenges, human-verification /
CAPTCHA, mailbox-passphrase OpenPGP key unlock, refresh-token rotation —
is delegated to `go-proton-api` (ADR-0001); Reduit owns the CLI prompts,
the state transitions, and where the secrets land. The two live secrets
produced by a successful auth — the Proton refresh token and the mailbox
passphrase — are written to the OS keychain (ADR-0013) under service
`reduit` at keys `mailbox/<id>/refresh_token` and
`mailbox/<id>/mailbox_passphrase`. They MUST NOT be written to disk,
logs, the SQLite store, error messages, or shell history. The same flow
re-authenticates a mailbox in `needs_reauth` and supports adding a second
or Nth distinct Proton account without any "you already have one"
rejection, while forbidding adding the same Proton account twice.

Because secrets are read non-interactively from the keychain at sync and
send time, a usable OS keyring / Secret Service session is a hard
prerequisite. On an interactive desktop this is the login keychain; on a
headless host the operator unlocks a Secret Service collection out of
band before sync workers run (ADR-0013). This spec documents that
requirement; it does not reintroduce an on-disk key file.

Governing: ADR-0012 (single-user local-first), ADR-0001
(go-proton-api as Proton client), ADR-0013 (secrets in OS keychain),
SPEC-0001 (mailbox model).

## Requirements

### Requirement: Add-Mailbox Flow

The `reduit auth` command SHALL interactively add and authenticate one
Proton mailbox. It SHALL prompt for the email address, perform SRP
password authentication, satisfy any 2FA challenge, capture and apply
the mailbox passphrase, and on success record `proton_user_id` and
transition the mailbox to `active`. The `mailboxes` row SHALL be created
in `pending_auth` before network auth begins and SHALL only advance to
`active` after both the refresh token and the passphrase are persisted
to the keychain.

#### Scenario: Operator runs reduit auth for a new mailbox

- **WHEN** the operator runs `reduit auth` and supplies an email address
  not matching any existing mailbox
- **THEN** the system SHALL create a `mailboxes` row with a fresh UUIDv7
  `id`, the supplied `address`, and `state = pending_auth`, then begin
  SRP authentication via go-proton-api

#### Scenario: Successful auth activates the mailbox

- **WHEN** SRP, any required 2FA, and mailbox-passphrase unlock all
  complete for a `pending_auth` mailbox
- **THEN** the system SHALL persist the returned `proton_user_id` on the
  row, write the refresh token and passphrase to the keychain, and
  transition the mailbox `state` to `active`

#### Scenario: Aborted auth leaves no active mailbox

- **WHEN** the operator cancels, or auth fails, before the secrets are
  written to the keychain
- **THEN** the mailbox SHALL NOT transition to `active`; it SHALL remain
  `pending_auth` (or be removed), and no partial secret SHALL be left in
  the keychain

### Requirement: SRP and 2FA Handling

Password authentication SHALL use go-proton-api's SRP exchange; Reduit
SHALL NOT implement its own SRP. When the account requires TOTP 2FA, the
flow SHALL prompt for the one-time code and submit it.

When Proton returns a human-verification challenge (API code 9001 —
expected on effectively every fresh login from a third-party client),
the flow SHALL resolve it the way Proton Bridge does (ADR-0021): open
`https://verify.proton.me/?methods=<offered>&token=<token>` in the
operator's browser (and print the URL for copy/paste), wait for the
operator to complete the challenge on Proton's own page — which verifies
the token **server-side** — then retry the login presenting the **same**
token via go-proton-api's HV-token login. The flow SHALL pass through
all offered methods (captcha, email, sms) and SHALL NOT attempt to
render, embed, or capture the challenge itself: the challenge's
`frame-ancestors` CSP is first-party-only, and no client-side token
capture exists in this flow (see ADR-0021 for the falsified
alternatives).

#### Scenario: TOTP 2FA is required

- **WHEN** go-proton-api reports that the account requires 2FA after a
  successful password step
- **THEN** the system SHALL prompt the operator for the TOTP code and
  submit it to complete authentication

#### Scenario: Human verification / CAPTCHA is requested

- **WHEN** Proton responds to the auth attempt with a human-verification
  challenge (code 9001) carrying offered methods and a verification
  token
- **THEN** the system SHALL print and open
  `https://verify.proton.me/?methods=<offered>&token=<token>`, wait for
  the operator to confirm completion, and retry the login with the same
  token; on success the flow SHALL continue to 2FA/passphrase as normal,
  and it SHALL NOT crash, loop, or print the raw challenge payload

#### Scenario: Verification not completed before retry

- **WHEN** the operator confirms before the challenge is actually
  completed and the retry returns another human-verification challenge
- **THEN** the system SHALL allow at least one further solve-and-retry
  attempt before aborting with a clear, actionable error

#### Scenario: Wrong password or 2FA code

- **WHEN** the supplied password or TOTP code is rejected by Proton
- **THEN** the system SHALL report a concise authentication-failed
  message without echoing the entered secret, and SHALL leave the
  mailbox in `pending_auth` (or `needs_reauth` for a re-auth)

### Requirement: Mailbox Passphrase Capture and Key Unlock

The mailbox passphrase SHALL be read interactively from the terminal
with echo disabled. It SHALL be used to unlock the mailbox's OpenPGP
private keys via go-proton-api. On success the passphrase SHALL be
written to keychain key `mailbox/<id>/mailbox_passphrase`. The
passphrase MUST NOT be written to disk, to logs, to the SQLite store, or
to any error message.

#### Scenario: Passphrase is read without echo

- **WHEN** the flow prompts for the mailbox passphrase
- **THEN** the system SHALL read it with terminal echo disabled so the
  passphrase is not displayed on screen

#### Scenario: Passphrase unlocks OpenPGP keys

- **WHEN** the operator supplies the mailbox passphrase
- **THEN** the system SHALL attempt to unlock the mailbox's OpenPGP
  private keys via go-proton-api; on failure it SHALL re-prompt or abort
  with a clear error and SHALL NOT proceed to `active`

#### Scenario: Passphrase is persisted only to the keychain

- **WHEN** the passphrase has unlocked the OpenPGP keys
- **THEN** the system SHALL store it only at keychain key
  `mailbox/<id>/mailbox_passphrase` under service `reduit`, and SHALL NOT
  write it to disk, logs, the database, or any other location

### Requirement: Secret Write, Read, and Delete

Per-mailbox secrets SHALL be created in the OS keychain at auth time,
read non-interactively at sync and send time, and deleted when the
mailbox is removed. The keys SHALL be `mailbox/<id>/refresh_token` and
`mailbox/<id>/mailbox_passphrase` under service `reduit`; the database
SHALL hold only the `mailbox_id` reference.

#### Scenario: Secrets created on successful auth

- **WHEN** `reduit auth` completes for a mailbox
- **THEN** the system SHALL write the Proton refresh token to
  `mailbox/<id>/refresh_token` and the mailbox passphrase to
  `mailbox/<id>/mailbox_passphrase`

#### Scenario: Secrets read non-interactively at use time

- **WHEN** a sync or send operation needs the refresh token or passphrase
  for an `active` mailbox
- **THEN** the system SHALL read it from the keychain by the
  `mailbox/<id>/<kind>` key without prompting the operator, subject only
  to the OS keyring being unlocked

#### Scenario: Secrets deleted on mailbox removal

- **WHEN** a mailbox is removed
- **THEN** the system SHALL delete both `mailbox/<id>/refresh_token` and
  `mailbox/<id>/mailbox_passphrase`; no orphaned secret SHALL remain in
  the keychain

### Requirement: Re-Auth Flow

A mailbox in `needs_reauth` SHALL be re-authenticated by re-running
`reduit auth` for that mailbox. Re-auth SHALL reuse the existing
`mailboxes` row and its `proton_user_id`, overwrite the keychain
secrets, and preserve the existing `mailbox_id`-scoped cache. A re-auth
that resolves a different `proton_user_id` than the row already holds
SHALL be an error and SHALL NOT overwrite the stored value.

#### Scenario: Re-auth restores an invalidated mailbox

- **WHEN** the operator runs `reduit auth` for a mailbox whose `state`
  is `needs_reauth`
- **THEN** the system SHALL re-run the auth flow against the same row,
  rewrite the refresh token and passphrase in the keychain, and
  transition the mailbox back to `active`

#### Scenario: Re-auth preserves the existing cache

- **WHEN** a `needs_reauth` mailbox is successfully re-authenticated
- **THEN** the system SHALL preserve its existing `mailbox_id`-scoped
  cache rows and sync cursors; re-auth SHALL refresh credentials, not
  reset derived state

#### Scenario: Re-auth resolving a different Proton account is rejected

- **WHEN** a re-auth for an existing mailbox resolves a `proton_user_id`
  that differs from the value stored on the row
- **THEN** the system SHALL treat this as an error, SHALL NOT overwrite
  the stored `proton_user_id`, and SHALL surface the discrepancy to the
  operator

### Requirement: Multi-Mailbox Add

Adding a mailbox SHALL NOT be blocked on the grounds that a mailbox
already exists. The same Proton account MUST NOT be added twice: an auth
that resolves an existing `proton_user_id` SHALL be rejected with a
clear message rather than creating a duplicate row.

#### Scenario: A second distinct mailbox is added

- **WHEN** the operator runs `reduit auth` for a Proton account whose
  `proton_user_id` matches no existing row
- **THEN** the system SHALL add an additional `mailboxes` row for the
  same local OS user and MUST NOT reject the request because a mailbox
  already exists

#### Scenario: The same Proton account cannot be added twice

- **WHEN** an auth flow resolves a `proton_user_id` already present on
  another `mailboxes` row
- **THEN** the system SHALL refuse to create a duplicate (the
  `UNIQUE(proton_user_id)` constraint backstops this) and SHALL surface
  a clear "that Proton account is already configured" message; if the
  existing mailbox is in `needs_reauth`, the message SHALL direct the
  operator to re-auth it instead

### Requirement: No Secret Leakage

Passphrases and refresh tokens MUST NOT appear in process output, in
`slog` records, in error messages, or in shell history. Secret values
SHALL be passed only through no-echo prompts and the keychain API, never
through command-line flags or environment that a process listing or
history file would capture.

#### Scenario: Secrets are absent from logs

- **WHEN** the auth flow runs at any log level, including debug
- **THEN** no `slog` record SHALL contain the password, TOTP code,
  mailbox passphrase, or refresh token value; secrets SHALL be redacted
  or omitted from all structured fields and messages

#### Scenario: Secrets are not passed as flags

- **WHEN** the operator authenticates a mailbox
- **THEN** the passphrase and password SHALL be read via interactive
  no-echo prompts, not via CLI flags or environment variables, so they
  do not land in shell history or a process listing

#### Scenario: Errors do not echo secrets

- **WHEN** an auth step fails
- **THEN** the surfaced error SHALL describe the failure without
  including the entered password, TOTP code, passphrase, or token

### Requirement: Keyring Availability

A usable OS keyring / Secret Service session SHALL be a precondition for
auth and for non-interactive secret retrieval. When the keyring is
unavailable or locked, the system SHALL fail with a clear, actionable
message rather than silently falling back to an on-disk secret store.

#### Scenario: Auth fails clearly when the keyring is unavailable

- **WHEN** `reduit auth` reaches the secret-write step but no usable
  keyring / Secret Service session is available
- **THEN** the system SHALL abort with a clear message instructing the
  operator to provision or unlock the keyring, and SHALL NOT persist the
  secret anywhere else

#### Scenario: Headless host requires out-of-band unlock

- **WHEN** Reduit runs on a headless host with no interactive desktop
  session
- **THEN** the operator SHALL unlock a Secret Service collection out of
  band before sync workers run, and the documentation SHALL describe
  this setup; Reduit SHALL NOT introduce its own key file as a fallback

## Out of Scope

- Web / OIDC login, session stores, and any network-facing auth surface —
  deleted by ADR-0012.
- Generating IMAP/SMTP relay credentials — there is no relay (ADR-0012);
  run Proton Bridge for protocol clients.
- A graphical onboarding UI or wizard; `reduit auth` is a terminal flow.
- Credential rotation policy beyond re-running `reduit auth` for a
  `needs_reauth` mailbox.
- FIDO2 / hardware-key second factors beyond TOTP — handled upstream by
  go-proton-api if needed; not specified here.
