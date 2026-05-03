# SPEC-0005: Admin UI Flows

## Overview

The Reduit **admin UI** is the HTTP control plane: OIDC-gated web
surface for first-time setup, Proton-account configuration, ongoing
management, sync-status visibility, and per-account IMAP/SMTP
credential rotation. It is server-rendered HTML using HTMX for
interactions and SSE for live updates per ADR-0005. A user (one OIDC
identity, one row in `users`) MAY own zero or more accounts (Proton
mailboxes) per ADR-0010 / SPEC-0001. Admin status is computed once
per session at session-bind time from `OIDC_ADMIN_SUBS`, never
stored on `users` or `accounts`, and never recomputed per-request.

Governing: ADR-0004 (OIDC), ADR-0005 (frontend stack), ADR-0010
(multi-Proton-account per user), SPEC-0001 (Account Model).

## Requirements

### Requirement: Authentication Gating

All routes except a small allowlist MUST require an authenticated
OIDC session. Unauthenticated requests to protected routes MUST
redirect to the OIDC login flow.

#### Scenario: Unauthenticated request redirects to login

- **WHEN** an unauthenticated browser issues `GET /accounts`
- **THEN** the server SHALL respond `302 Found` with `Location:
  /auth/login` and SHALL include a `?return_to=/accounts` query
  parameter for post-login redirect

#### Scenario: Authenticated request proceeds

- **WHEN** the request carries a valid `reduit_session` cookie that
  resolves to an active session bound to a user row (`user_id`,
  `Principal.Subject`)
- **THEN** the request SHALL proceed to the route handler with the
  user identity in context. Routes that require an account in scope
  SHALL resolve the account from the request path and SHALL verify
  `account.user_id == session.user_id` (or the session is admin) per
  SPEC-0001

#### Scenario: Allowlist bypasses auth

- **WHEN** an unauthenticated request hits `/healthz`, `/readyz`,
  `/metrics`, `/auth/login`, `/auth/callback`, or `/static/*`
- **THEN** the server SHALL serve the response without requiring
  authentication. Metrics MAY be IP-restricted via configuration

### Requirement: OIDC Login Flow

The login flow MUST follow OIDC authorization-code with PKCE.

#### Scenario: Login initiates auth-code-with-PKCE

- **WHEN** a user visits `/auth/login`
- **THEN** the server SHALL generate a state value, a nonce, and a
  PKCE code verifier; SHALL persist them in a short-lived
  pre-session record; and SHALL redirect the browser to the IdP's
  authorization endpoint with the standard query parameters

#### Scenario: Callback validates state, nonce, and code

- **WHEN** the IdP redirects to `/auth/callback` with
  `state` and `code`
- **THEN** the server SHALL validate the state matches a pending
  pre-session, exchange the code for an ID token, validate the ID
  token's signature, issuer, audience, and nonce, upsert the
  `users` row keyed by `oidc_subject`, and create a Reduit session
  bound to the resolved `user_id` and `Principal.Subject`

#### Scenario: Session admin tag is computed at bind time

- **WHEN** a session is bound (immediately after `/auth/callback`
  validation creates the session record)
- **THEN** the server SHALL set the session's admin tag to `true`
  if and only if `Principal.Subject` appears in `OIDC_ADMIN_SUBS`,
  and SHALL NOT consult any `is_admin` column (none exists) on
  `users` or `accounts`. The result is computed exactly once per
  session and cached on the session payload (or in the in-process
  session struct — implementation detail) per SPEC-0001 "Admin
  Status". Per-request handlers SHALL read the cached tag and
  SHALL NOT re-consult the allowlist on each request

#### Scenario: First-time login establishes user identity only

- **WHEN** the OIDC `sub` claim has not been seen before AND the
  configured login policy permits the user (admin allowlist or an
  equivalent gate; `OIDC_AUTO_CREATE` semantics apply to user
  admittance, not account creation)
- **THEN** the server SHALL upsert a `users` row keyed by the OIDC
  `sub`, create a session bound to that `user_id`, and SHALL NOT
  create an `accounts` row. Account creation is a separate,
  deliberate action via the add-account wizard. The session's admin
  tag is computed from `OIDC_ADMIN_SUBS` per the bind-time scenario
  above; first-time logins are NOT auto-promoted to admin. If the
  login policy denies the user, the server SHALL respond
  `403 Forbidden — contact your administrator`

#### Scenario: Post-login routing depends on account ownership

- **WHEN** OIDC login succeeds
- **THEN** the server SHALL redirect to `?return_to` if present and
  authorized; otherwise to `/accounts`. If the authenticated user
  owns zero accounts, `/accounts` SHALL render the empty-state
  variant defined under "Account Dashboard"

#### Scenario: Logout clears local session

- **WHEN** a user issues `POST /auth/logout`
- **THEN** the server SHALL delete the session record, clear the
  cookie, and redirect to `/`. If the IdP advertises
  `end_session_endpoint`, the server SHOULD redirect to it for
  RP-Initiated Logout

### Requirement: Add-Proton-Account Wizard

A multi-step HTMX wizard MUST guide a user through adding a Proton
account: email, password, optional 2FA, mailbox passphrase. Each step
renders as a partial swapped into the wizard container. The wizard
MUST be repeatable: a user MAY run it any number of times to add
additional Proton accounts they own (per SPEC-0001 ownership rules).
The wizard prose MUST be neutral about ownership ("Add a Proton
account", not "Add your Proton account") so that the second-and-later
runs read naturally.

#### Scenario: Wizard creates the account on entry, owned by the authenticated user

- **WHEN** an authenticated user begins the wizard at
  `/accounts/setup`
- **THEN** the server SHALL create a new account row in state
  `pending_proton_setup` with `user_id` set to the authenticated
  session's `user_id`. The wizard SHALL operate on that row for the
  remainder of the flow

#### Scenario: Wizard is repeatable

- **WHEN** an authenticated user who already owns one or more
  accounts initiates the wizard again
- **THEN** the server SHALL accept the request and SHALL NOT block
  on grounds that the user already owns an account. The server
  SHALL reject only the specific case where the resulting Proton
  account would duplicate one the user already owns (per SPEC-0001
  uniqueness on `(user_id, proton_user_id)`); that rejection SHALL
  render an inline "you already added that Proton account" error

#### Scenario: Step 1 — Proton email and password

- **WHEN** a user starts the wizard at `/accounts/setup` and submits
  step 1 with `email` and `password`
- **THEN** the server SHALL call `go-proton-api`'s authentication
  flow (`AuthInfo` + `Auth`). On success, render step 2 (or step 3
  if no 2FA configured). On failure, render step 1 with the error
  message

#### Scenario: Step 2 — TOTP if account has TOTP enabled

- **WHEN** step 1 succeeds and the account requires TOTP
- **THEN** the server SHALL render step 2 with a 6-digit input
  field. Submission calls `AuthTOTP` and proceeds to step 3 on
  success, or re-renders step 2 with an error on failure. Three
  consecutive failures SHALL abort the wizard and require restart

#### Scenario: Step 2 — FIDO2 if account has FIDO2 enabled

- **WHEN** step 1 succeeds and the account requires FIDO2
- **THEN** the server SHALL render step 2 with the FIDO2 challenge
  via WebAuthn JS API. Submission calls Proton's FIDO2 endpoint
  via `go-proton-api` and proceeds on success

#### Scenario: Step 3 — Mailbox passphrase

- **WHEN** auth + 2FA complete
- **THEN** the server SHALL render step 3 prompting for the mailbox
  passphrase. Submission attempts to unlock the user's primary key
  via `go-proton-api`. On success the account transitions to
  `active`, the sync worker starts, and the wizard redirects to
  `/accounts`. On failure the server SHALL render step 3 with an
  error and allow retry up to three times before aborting

#### Scenario: Wizard state is per-session and ephemeral

- **WHEN** a user partially completes the wizard and navigates away
- **THEN** the server SHALL discard wizard state on session
  invalidation or after 30 minutes of inactivity. Partial
  credentials SHALL NOT persist beyond memory

### Requirement: Account Dashboard

An authenticated user MUST see a dashboard at `/accounts` that lists
the accounts they own and their current state. A user MAY own zero,
one, or many accounts.

#### Scenario: User sees only the accounts they own

- **WHEN** a non-admin user visits `/accounts`
- **THEN** the page SHALL render one card per account where
  `account.user_id` equals the session's `user_id`, each showing
  state, last sync time, and per-account IMAP/SMTP host
  configuration. The page SHALL also include an "Add another Proton
  account" call-to-action that links to the wizard

#### Scenario: User with zero accounts lands on the wizard or empty state

- **WHEN** an authenticated user who owns zero accounts visits
  `/accounts`
- **THEN** the server SHALL render an explicit empty state with a
  primary "Add a Proton account" call-to-action linking to
  `/accounts/setup`. The server MAY redirect directly to
  `/accounts/setup` instead, at the implementation's discretion.
  This state is first-class regardless of admin status — a brand-new
  admin who has authenticated but not yet added a Proton account
  sees the same empty state

#### Scenario: Admin sees all accounts grouped by user

- **WHEN** an admin user visits `/accounts` (or the admin
  all-accounts view at `/admin/accounts`)
- **THEN** the page SHALL render all account cards, grouped by
  the owning user (display order: by `users.email` or
  `users.display_name` if available, falling back to
  `users.oidc_subject`). Admin actions (suspend, delete) SHALL be
  visible only on the admin view. The admin's own accounts SHALL be
  presented in their own group like any other user's

### Requirement: Sync Status via SSE

The account dashboard MUST push live sync status updates via SSE.

#### Scenario: SSE endpoint per account

- **WHEN** the dashboard subscribes to `GET /sse/accounts/{id}/status`
  with `Accept: text/event-stream`
- **THEN** the server SHALL emit events for state changes (sync
  cursor advanced, error encountered, message-fetch in progress).
  The connection SHALL remain open until client disconnect

#### Scenario: SSE access control

- **WHEN** a user subscribes to an account's SSE stream that they
  don't own and aren't admin for
- **THEN** the server SHALL respond `403 Forbidden`

#### Scenario: SSE is proxy-buffer-tolerant

- **WHEN** the SSE response is generated
- **THEN** the server SHALL set `X-Accel-Buffering: no`,
  `Cache-Control: no-cache`, and SHALL emit comment-only heartbeats
  every 15 seconds to keep idle proxies from closing the connection

### Requirement: Per-Account IMAP/SMTP Credentials

A user MUST be able to view the relay IMAP/SMTP host, port, username,
and rotate the password for any account they own from the admin UI.
Relay credentials are per-account; a user with multiple accounts has
distinct credentials for each. The plaintext password MUST be
displayed exactly once at rotation.

#### Scenario: Credentials view shows host and username for an owned account

- **WHEN** a user visits the credentials view for an account they
  own (e.g., `/accounts/{id}/credentials`)
- **THEN** the page SHALL display IMAP host, IMAP port (993),
  SMTP host, SMTP port (465), and the per-account username
  (`user@host`). The password SHALL NOT be shown — only the
  rotation button. The ownership check is `account.user_id ==
  session.user_id || session.is_admin`; if the check fails the
  server SHALL respond `403 Forbidden`

#### Scenario: Rotation generates new password and shows once

- **WHEN** a user clicks the rotation button on an owned account
- **THEN** the server SHALL generate a new random password (32+
  bytes of entropy, encoded as a 24-char base32 string for
  email-client friendliness), update both the encrypted ciphertext
  and the bcrypt/Argon2id hash for that account, and render the
  new password in a one-time-display modal with a copy-to-clipboard
  button. After modal close the password MUST NOT be retrievable

#### Scenario: Rotation invalidates existing IMAP/SMTP sessions

- **WHEN** a password is rotated for an account
- **THEN** all existing IMAP/SMTP sessions for that account SHALL be
  closed within 1 second per SPEC-0003 / SPEC-0004 session-lifetime
  rules (the new password hash invalidates SASL on next reconnect).
  Sessions for the user's other accounts SHALL be unaffected

### Requirement: Admin Account Management

Admins MUST be able to suspend, unsuspend, and soft-delete other
accounts.

#### Scenario: Admin suspends an account

- **WHEN** an admin issues `POST /admin/accounts/{id}/suspend`
- **THEN** the server SHALL transition the account state to
  `suspended`, stop the sync worker, drop live IMAP/SMTP sessions,
  and log the action with admin's OIDC sub

#### Scenario: Admin soft-deletes an account

- **WHEN** an admin issues `POST /admin/accounts/{id}/delete`
- **THEN** the server SHALL transition state to `soft_deleted`, set
  `deleted_at`, stop the sync worker, drop sessions, and log the
  action

#### Scenario: Admin un-suspends an account

- **WHEN** an admin issues `POST /admin/accounts/{id}/unsuspend` for
  an account in state `suspended`
- **THEN** the server SHALL transition state back to `active` and
  start the sync worker

### Requirement: First-Run Bootstrap

The very first OIDC login on a fresh deployment MUST establish a
regular user. There is NO auto-promotion of the first authenticator
to admin. Admin status is computed at session-bind time from
`OIDC_ADMIN_SUBS` and there only. When the deployment is in a state
where no admin can ever authenticate (allowlist empty, no admin yet)
the system SHALL surface an explicit operator-configuration warning
in the UI; it SHALL NOT promote anyone to compensate.

#### Scenario: First OIDC login creates a regular user

- **WHEN** no `users` row has yet been written and the first OIDC
  login arrives
- **THEN** the system SHALL accept the login (subject to the login
  policy), upsert a `users` row keyed by the OIDC `sub`, and create
  a session. The session's admin tag SHALL be `true` only if the
  `Principal.Subject` matches an entry in `OIDC_ADMIN_SUBS`. The
  system MUST NOT add the subject to any in-memory admin set as a
  side effect of being the first authenticator. The system MUST NOT
  create an `accounts` row as a side effect of bootstrap; the user
  is routed to the add-account wizard per the dashboard empty-state
  rule

#### Scenario: Empty allowlist surfaces a configuration warning

- **WHEN** the dashboard or a related management page renders a
  request, AND no session in the system has ever been admin-tagged,
  AND `OIDC_ADMIN_SUBS` is empty
- **THEN** the page SHALL render an operator-configuration warning
  banner at the top: "No administrator is configured. Set
  `OIDC_ADMIN_SUBS` (comma-separated OIDC subjects) and
  re-authenticate to gain admin access." The banner MUST NOT
  attempt to promote any user; it is informational only

#### Scenario: Allowlist match grants admin on next bind

- **WHEN** the operator updates `OIDC_ADMIN_SUBS` and restarts the
  process (v0.1 — hot-reload deferred) so that an existing user's
  `oidc_subject` is now in the allowlist, and that user
  re-authenticates so a fresh session is bound
- **THEN** the new session's admin tag SHALL be `true`. No data
  migration SHALL be required; admin is purely a session-bind-time
  attribute. Sessions bound prior to the restart SHALL be
  invalidated by the restart itself (in-memory session store) or
  via the operator-facing session-revocation step required by
  SPEC-0001 "Admin Status" if the SCS sqlite store outlives the
  restart, so no stale admin tag survives a tightening of the
  allowlist

## Out of Scope

- Bulk account import / export.
- Custom branding (logos, themes) beyond DaisyUI's built-in theme
  system.
- Audit log UI beyond simple action logging in stderr (deferred to
  v0.5).
- Mobile-app-specific UI beyond responsive Tailwind design.

## Mockups

High-fidelity reference renders generated via the `gemini-mockup`
skill against the project's visual identity (see Reduit's
`CLAUDE.md` § Visual Identity). These are reference targets, not
pixel-perfect specifications — implementation may diverge so long as
the spec requirements above are met.

| File | Screen |
|---|---|
| [`mockups/01-login.png`](mockups/01-login.png) | OIDC login page |
| [`mockups/02-account-dashboard.png`](mockups/02-account-dashboard.png) | Single-user dashboard with live sync card |
| [`mockups/03-wizard-step-1-credentials.png`](mockups/03-wizard-step-1-credentials.png) | Add-Proton-account wizard — step 1 (email + password) |
| [`mockups/04-wizard-step-2-totp.png`](mockups/04-wizard-step-2-totp.png) | Wizard — step 2 (TOTP) |
| [`mockups/05-wizard-step-3-passphrase.png`](mockups/05-wizard-step-3-passphrase.png) | Wizard — step 3 (mailbox passphrase) |
| [`mockups/06-credentials-rotation-modal.png`](mockups/06-credentials-rotation-modal.png) | IMAP/SMTP credentials view + rotation modal |
| [`mockups/07-mcp-tokens.png`](mockups/07-mcp-tokens.png) | MCP token issuance and revocation |
| [`mockups/08-admin-all-accounts.png`](mockups/08-admin-all-accounts.png) | Admin all-accounts table with summary stats |

Regenerate any of these by invoking the `gemini-mockup` skill with
the same filename (it overwrites cleanly). Run a scan-in-arrears
when the visual identity changes — see the skill's SKILL.md for the
workflow.
