# SPEC-0005: Admin UI Flows

## Overview

The Reduit **admin UI** is the HTTP control plane: OIDC-gated web
surface for first-time setup, Proton-account configuration, ongoing
management, sync-status visibility, and per-user IMAP/SMTP credential
rotation. It is server-rendered HTML using HTMX for interactions and
SSE for live updates per ADR-0005.

Governing: ADR-0004 (OIDC), ADR-0005 (frontend stack), SPEC-0001
(Account Model).

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
  resolves to an active session for an account
- **THEN** the request SHALL proceed to the route handler with the
  account in context

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
  token's signature, issuer, audience, and nonce, and create a
  Reduit session bound to the OIDC `sub` claim

#### Scenario: First-time login auto-creates account

- **WHEN** the OIDC `sub` claim has no existing account record AND
  `OIDC_AUTO_CREATE` is true
- **THEN** the server SHALL create a new account record in state
  `pending_proton_setup` and bind the session to it. If
  `OIDC_AUTO_CREATE` is false, the server SHALL respond `403
  Forbidden — contact your administrator`

#### Scenario: Logout clears local session

- **WHEN** a user issues `POST /auth/logout`
- **THEN** the server SHALL delete the session record, clear the
  cookie, and redirect to `/`. If the IdP advertises
  `end_session_endpoint`, the server SHOULD redirect to it for
  RP-Initiated Logout

### Requirement: Add-Proton-Account Wizard

A multi-step HTMX wizard MUST guide a user through Proton account
configuration: email, password, optional 2FA, mailbox passphrase.
Each step renders as a partial swapped into the wizard container.

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
their account(s) and current state.

#### Scenario: User sees only their own account

- **WHEN** a non-admin user visits `/accounts`
- **THEN** the page SHALL render exactly one account card (theirs)
  showing state, last sync time, and per-user IMAP/SMTP host
  configuration

#### Scenario: Admin sees all accounts

- **WHEN** an admin user visits `/accounts`
- **THEN** the page SHALL render all account cards. Admin actions
  (suspend, delete) SHALL be visible only on this view, not on the
  non-admin view

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

### Requirement: Per-User IMAP/SMTP Credentials

A user MUST be able to view their relay IMAP/SMTP host, port,
username, and rotate their password from the admin UI. The plaintext
password MUST be displayed exactly once at rotation.

#### Scenario: Credentials view shows host and username

- **WHEN** a user visits `/accounts/me/credentials`
- **THEN** the page SHALL display IMAP host, IMAP port (993),
  SMTP host, SMTP port (465), and username (`user@host`). The
  password SHALL NOT be shown — only the rotation button

#### Scenario: Rotation generates new password and shows once

- **WHEN** a user clicks the rotation button
- **THEN** the server SHALL generate a new random password (32+
  bytes of entropy, encoded as a 24-char base32 string for
  email-client friendliness), update both the encrypted ciphertext
  and the bcrypt/Argon2id hash, and render the new password in a
  one-time-display modal with a copy-to-clipboard button. After
  modal close the password MUST NOT be retrievable

#### Scenario: Rotation invalidates existing IMAP/SMTP sessions

- **WHEN** a password is rotated
- **THEN** all existing IMAP/SMTP sessions for that account SHALL be
  closed within 1 second per SPEC-0003 / SPEC-0004 session-lifetime
  rules (the new password hash invalidates SASL on next reconnect)

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

The very first OIDC login on a fresh deployment MUST become the
initial admin, regardless of `OIDC_ADMIN_SUBS` configuration.

#### Scenario: Empty database creates first admin

- **WHEN** the accounts table is empty and the first OIDC login
  arrives
- **THEN** the system SHALL auto-create an account with `is_admin =
  true` and persist the OIDC `sub` to the in-memory admin allowlist.
  Subsequent admins MUST be configured via env

## Out of Scope

- Bulk account import / export.
- Custom branding (logos, themes) beyond DaisyUI's built-in theme
  system.
- Audit log UI beyond simple action logging in stderr (deferred to
  v0.5).
- Mobile-app-specific UI beyond responsive Tailwind design.
