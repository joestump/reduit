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

All Proton-protocol work — SRP, 2FA challenges, mailbox-passphrase
OpenPGP key unlock, refresh-token rotation — is delegated to
`go-proton-api` (ADR-0001); Reduit owns the CLI prompts, the state
transitions, and where the secrets land. Human verification is *avoided*
rather than solved: reduit identifies as a Proton Bridge client
(app-version), which Proton waves through with no CAPTCHA, so there is no
in-app challenge solver (ADR-0021). The live secrets
produced by a successful auth — the Proton refresh token, the Proton
access token, the mailbox passphrase, and the derived salted key
passphrase — are written to the OS keychain
(ADR-0013) under service `reduit` at keys `mailbox/<id>/refresh_token`,
`mailbox/<id>/access_token`, `mailbox/<id>/mailbox_passphrase`, and
`mailbox/<id>/salted_key_pass`. The
access token is persisted so a cross-process resume can reuse the cached
session and preserve the 2FA-elevated scope; the salted key passphrase is
persisted so a scope-DOWNGRADED resume can still unlock the OpenPGP keys
without the (scope-elevated) salts endpoint (see "Cross-Process Session
Resume"). They MUST NOT be written to disk,
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
ADR-0021 (avoid human verification via the Bridge app-version),
SPEC-0001 (mailbox model).

## Requirements

### Requirement: Add-Mailbox Flow

The `reduit auth` command SHALL interactively add and authenticate one
Proton mailbox. It SHALL prompt for the email address, perform SRP
password authentication, satisfy any 2FA challenge, capture and apply
the mailbox passphrase, and on success record `proton_user_id` and
transition the mailbox to `active`. The `mailboxes` row SHALL be created
in `pending_auth` before network auth begins and SHALL only advance to
`active` after the refresh token, access token, and passphrase are
persisted to the keychain.

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
  row, write the refresh token, access token, and passphrase to the
  keychain, and transition the mailbox `state` to `active`

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

The flow SHALL avoid Proton's human-verification wall by presenting a
Proton **Bridge** app-version by default (`proton.DefaultAppVersion`,
e.g. `macos-bridge@3.21.2`): Proton challenges the web client family with
a 9001 CAPTCHA on every fresh login but waves the Bridge family through
with none (ADR-0021). Under the default the normal login therefore never
sees a challenge and continues straight to TOTP/passphrase. If Proton
still returns a 9001 — which means a **non-Bridge** app-version was
configured (`proton.app_version` / `REDUIT_PROTON_APP_VERSION`, or the
`auto` web-client detection) — the flow SHALL return a clear, actionable
error directing the operator to unset or override the app-version, and
SHALL NOT attempt to render, embed, or capture the challenge and SHALL
NOT implement an in-app CAPTCHA solver (every solve mechanism was
falsified live or proved unnecessary; see ADR-0021).

#### Scenario: TOTP 2FA is required

- **WHEN** go-proton-api reports that the account requires 2FA after a
  successful password step
- **THEN** the system SHALL prompt the operator for the TOTP code and
  submit it to complete authentication

#### Scenario: Default Bridge app-version avoids human verification

- **WHEN** the operator authenticates under the default configuration
  (no `proton.app_version` set), so reduit presents the Bridge
  app-version `proton.DefaultAppVersion`
- **THEN** Proton SHALL NOT raise a 9001 human-verification challenge and
  the flow SHALL continue to TOTP/passphrase as a normal login

#### Scenario: Human verification / CAPTCHA is requested

- **WHEN** Proton responds to the auth attempt with a human-verification
  challenge (code 9001) — indicating a non-Bridge app-version was
  configured — carrying offered methods and a verification token
- **THEN** the system SHALL return a clear, actionable error instructing
  the operator to unset or override `proton.app_version` /
  `REDUIT_PROTON_APP_VERSION` (or set a Bridge value), and it SHALL NOT
  crash, loop, print the raw challenge token, render/embed/capture the
  challenge, or launch a browser

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

Unlocking derives a *salted key passphrase* from the passphrase and the
primary key's salt (fetched from the salts endpoint, which requires the
2FA-elevated scope). This derived value SHALL be retained and persisted to
keychain key `mailbox/<id>/salted_key_pass` so a later resume can unlock the
OpenPGP keys directly from it WITHOUT calling the salts endpoint — the
mechanism that lets a scope-downgraded refreshed session still sync (see
"Cross-Process Session Resume"). It is a secret (it grants mailbox key
access) and MUST NOT be written to disk, to logs, to the SQLite store, or to
any error message.

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
mailbox is removed. The keys SHALL be `mailbox/<id>/refresh_token`,
`mailbox/<id>/access_token`, `mailbox/<id>/mailbox_passphrase`, and
`mailbox/<id>/salted_key_pass` under
service `reduit`; the database SHALL hold only the `mailbox_id` reference.
The salted key passphrase is raw key bytes, so it SHALL be stored
base64-encoded (the keychain API is string-typed).

#### Scenario: Secrets created on successful auth

- **WHEN** `reduit auth` completes for a mailbox
- **THEN** the system SHALL write the Proton refresh token to
  `mailbox/<id>/refresh_token`, the Proton access token to
  `mailbox/<id>/access_token`, the mailbox passphrase to
  `mailbox/<id>/mailbox_passphrase`, and the derived salted key passphrase
  (base64-encoded) to `mailbox/<id>/salted_key_pass`

#### Scenario: Secrets read non-interactively at use time

- **WHEN** a sync or send operation needs the refresh token, access token,
  passphrase, or salted key passphrase for an `active` mailbox
- **THEN** the system SHALL read it from the keychain by the
  `mailbox/<id>/<kind>` key without prompting the operator, subject only
  to the OS keyring being unlocked

#### Scenario: Secrets deleted on mailbox removal

- **WHEN** a mailbox is removed
- **THEN** the system SHALL delete `mailbox/<id>/refresh_token`,
  `mailbox/<id>/access_token`, `mailbox/<id>/mailbox_passphrase`, and
  `mailbox/<id>/salted_key_pass`; no
  orphaned secret SHALL remain in the keychain

### Requirement: Re-Auth Flow

A mailbox in `needs_reauth` SHALL be re-authenticated by re-running
`reduit auth` for that mailbox. Re-auth SHALL reuse the existing
`mailboxes` row and its `proton_user_id`, overwrite the keychain
secrets, and preserve the existing `mailbox_id`-scoped cache. A re-auth
that resolves a different `proton_user_id` than the row already holds
SHALL be an error and SHALL NOT overwrite the stored value.

`reduit auth refresh` SHALL be the reliable one-command fix. Its cheap
path (resume the stored session and rotate tokens) SHALL NOT declare
success on a Labels probe alone: a lazily-refreshed session can label mail
yet be scope-downgraded so it cannot unlock (403 code 9101 on the salts
endpoint). The cheap path SHALL therefore VERIFY the resumed session can
actually unlock the OpenPGP keys (via the persisted salted key passphrase,
or the passphrase fallback); when unlock is impossible on the resumed
session, it SHALL fall through to the FULL interactive re-login (password +
TOTP), which re-elevates scope and re-persists every secret.

#### Scenario: Re-auth restores an invalidated mailbox

- **WHEN** the operator runs `reduit auth` for a mailbox whose `state`
  is `needs_reauth`
- **THEN** the system SHALL re-run the auth flow against the same row,
  rewrite the refresh token, access token, passphrase, and salted key
  passphrase in the keychain, and transition the mailbox back to `active`

#### Scenario: auth refresh escalates when the resumed session cannot unlock

- **WHEN** `auth refresh`'s cheap resume succeeds and even passes a Labels
  probe, but the resumed session is scope-downgraded so it cannot unlock the
  OpenPGP keys (the salts endpoint would 9101)
- **THEN** the system SHALL NOT report the mailbox "Refreshed"; it SHALL
  escalate to the full interactive re-login, which re-elevates the session
  scope and re-persists the refresh token, access token, passphrase, salted
  key passphrase, and session UID, returning the mailbox to `active`

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

### Requirement: Cross-Process Session Resume

A session minted by `reduit auth` SHALL be resumable from a separate
process (a sync or send run) without re-prompting. Four pieces of persisted
state make this correct, and all SHALL be honored (ADR-0001, ADR-0013,
ADR-0021):

- **Access token (session reuse, not eager refresh).** Resume SHALL rebuild
  the session by REUSING the cached tokens via go-proton-api's session-reuse
  constructor (`Manager.NewClient`), which makes no network call and
  preserves the access token's scope. Resume SHALL NOT use an eager refresh
  (`Manager.NewClientWithRefresh`): an eager `/auth/v4/refresh` of a
  freshly-2FA'd session returns a REDUCED scope, which later fails key/salt
  access (`GetSalts` during `Unlock`) with **403 code 9101** ("Access token
  does not have sufficient scope") — so a low-scope call like `labels`
  succeeds on resume while `sync` 9101s. The access token SHALL therefore be
  persisted per mailbox as a session secret (in the keychain, alongside the
  refresh token), presented on every resume, and — because a lazy refresh
  (triggered when the cached access token expires) may rotate the access
  token, refresh token, and UID — re-read and re-persisted after operations
  whenever it changed. An auth handler registered on the resumed client SHALL
  capture the rotated tokens from that lazy refresh.
- **Session UID.** The go-proton-api session UID (`auth.UID`, distinct
  from the account's `proton_user_id`) SHALL be persisted per mailbox as
  non-secret session state and presented on every resume. Proton's
  `/auth/v4/refresh` identifies the session by this UID; a lazy refresh
  without it yields code **10013** ("invalid refresh token"). Because a
  resume may rotate the UID, the caller SHALL re-read and re-persist it
  after each resume, alongside the rotated access and refresh tokens.
- **App-version binding.** Proton binds a session to the app-version that
  minted it, so the app-version presented at resume SHALL match the one
  presented at mint; a mismatch also yields 10013. The default Bridge
  app-version (`proton.DefaultAppVersion`) satisfies this for the normal
  path; an operator who overrides `proton.app_version` SHALL do so
  consistently across `auth`, `labels`, and `sync`.
- **Salted key passphrase (unlock without the salts endpoint).** The salted
  key passphrase is derived ONCE at login — while the session still holds the
  full 2FA-elevated scope the salts endpoint (`GetSalts`) requires — and
  persisted per mailbox (keychain). A resume SHALL unlock the OpenPGP keys
  from this persisted value and SHALL NOT call the salts endpoint, so a
  scope-DOWNGRADED refreshed session can still unlock and sync. This closes
  the live failure mode where, after the original access token's TTL expires,
  go-proton-api's lazy `/auth/v4/refresh` returns a scope-downgraded token:
  low-scope calls (`labels`) still succeed, but a resume-time `GetSalts`
  returns **403 code 9101** ("Access token does not have sufficient scope"),
  permanently breaking `sync` until a full re-login. Retrying or refreshing
  again can never re-elevate scope; only a full re-login can, and the
  persisted salted key passphrase avoids needing the elevated-scope call on
  resume at all (Proton Bridge's pattern). A mailbox that has no persisted
  salted key passphrase (a pre-fix row) SHALL fall back to a passphrase
  unlock and, on success, persist the freshly-derived value so the next
  resume skips the salts endpoint (self-heal); note the self-heal's passphrase
  unlock itself calls `GetSalts`, so a pre-fix row on an already-downgraded
  session CANNOT self-heal without one full re-login. A persisted salted key
  passphrase that no longer decrypts (e.g. after a password change) SHALL fall
  back to a passphrase unlock once (a still-full-scope session may salvage it
  and re-persist a fresh value); if that also fails, the mailbox SHALL go to
  `needs_reauth` with an actionable "re-authenticate" message.

#### Scenario: Resume unlocks from the persisted salted key passphrase without the salts endpoint

- **WHEN** a sync or send process resumes an `active` mailbox that has a
  persisted salted key passphrase
- **THEN** the system SHALL unlock the OpenPGP keys from the persisted salted
  key passphrase WITHOUT calling the salts endpoint, so a scope-downgraded
  refreshed session unlocks successfully and syncs

#### Scenario: Pre-fix mailbox self-heals the salted key passphrase

- **WHEN** a resume finds no persisted salted key passphrase (a pre-fix row)
  and the resumed session still has full scope
- **THEN** the system SHALL unlock via the stored passphrase (which calls the
  salts endpoint) and SHALL persist the freshly-derived salted key passphrase,
  so the next resume unlocks without the salts endpoint

#### Scenario: Stale salted key passphrase falls back then re-persists

- **WHEN** a resume's persisted salted key passphrase no longer decrypts the
  keys (e.g. after a password change)
- **THEN** the system SHALL fall back to a passphrase unlock once; on success
  it SHALL re-persist the freshly-derived salted key passphrase, and on
  failure of both it SHALL transition the mailbox to `needs_reauth` with an
  actionable re-authenticate message

#### Scenario: Resume reuses the cached access token to preserve scope

- **WHEN** a sync or send process resumes an `active` mailbox from its
  stored session
- **THEN** the system SHALL reconstruct the client by reusing the stored
  access token (session reuse, no eager refresh), so the 2FA-elevated scope
  is preserved and key/salt access during `Unlock` does not fail with 403
  code 9101; and after a lazy refresh that rotates the access token, refresh
  token, or UID SHALL persist the rotated values so the next resume matches

#### Scenario: Missing access token forces re-auth rather than a scope-reduced resume

- **WHEN** a mailbox row has a refresh token and session UID but no persisted
  access token (e.g. a pre-fix row)
- **THEN** the system SHALL NOT resume via an eager refresh that would reduce
  the session scope and later 9101; `labels` and `sync` SHALL surface an
  actionable "re-authenticate" message, and `auth refresh` SHALL fall back to
  the interactive re-login, which stores a fresh full-scope access token and
  self-heals the row

#### Scenario: Missing session UID forces re-auth rather than a broken resume

- **WHEN** a mailbox row has a refresh token but no persisted session UID
  (e.g. a pre-migration row)
- **THEN** the system SHALL NOT attempt a resume that would fail with
  10013; it SHALL fall back to the interactive re-login, which re-persists
  the refresh token, access token, and session UID, self-healing the row

#### Scenario: Resume app-version matches the minting app-version

- **WHEN** a mailbox is resumed for `labels` or `sync`
- **THEN** the system SHALL present the same app-version used at `auth`
  time (the default Bridge value unless the operator overrode it
  consistently), so Proton does not reject the resume with 10013

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

Reduit's structured logging backend SHALL be `github.com/charmbracelet/log`
used *as an `slog.Handler`* (ADR-0022): the `slog` API surface and the
redaction discipline of this requirement are properties of the `slog`
records themselves (`LogValue()` on secret-bearing types, structure-only
auth logging) and SHALL be unchanged by the backend. Logs SHALL go to
stderr. Any log-level assertion in this requirement holds regardless of
`logger.format` (`text` or `json`).

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
