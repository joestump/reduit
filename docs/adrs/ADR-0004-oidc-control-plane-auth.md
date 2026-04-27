# ADR-0004: OIDC for control-plane authentication

- **Status:** accepted
- **Date:** 2026-04-25
- **Deciders:** Joe Stump

## Context and Problem Statement

Users authenticate to Reduit's admin / setup HTTP endpoints to:

- Configure their Proton account (first-time SRP login, 2FA enrollment,
  mailbox passphrase entry).
- Manage their per-user IMAP/SMTP credentials.
- View sync status and logs.
- (Optionally) drive the MCP server with their identity.

The IMAPS and SMTPS protocol endpoints have their own authentication
(SASL PLAIN with the per-user IMAP/SMTP password). This ADR is
about the **control plane** only.

## Decision Drivers

- Multi-user (per ADR-0002). Identity must scope every admin action to
  a specific user.
- Self-hosters typically already run an OIDC IdP (Pocket ID, Authelia,
  Keycloak). Reduit should leverage what they have, not add another
  identity store.
- No password store inside Reduit. We do not want to be in the
  business of password resets, brute-force lockouts, MFA enrollment,
  WebAuthn re-registration. Outsource identity entirely.
- Joe's stumpcloud already runs Pocket ID. OIDC clients are
  provisioned via the `joestump.pocket_id` Ansible collection per
  established conventions.

## Considered Options

1. **OIDC (any compliant IdP, default-configured for Pocket ID).**
2. **Local username/password store** with optional OIDC. Lots of UX
   surface (signup, password reset, 2FA enrollment).
3. **HTTP basic auth + reverse proxy auth** (e.g., Caddy + basicauth or
   forward-auth via Authelia). Punts auth to the proxy entirely.

## Decision Outcome

**Chosen: option 1 — OIDC, generic spec, defaults configured for
Pocket ID.**

- Reduit acts as an OIDC Relying Party. Standard authorization-code
  flow with PKCE.
- Configured via env: `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`,
  `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URL`, `OIDC_SCOPES`.
- Sessions: secure HTTP-only cookie holding an opaque session ID;
  session state in SQLite via `alexedwards/scs`.
- Authorization model: every authenticated session maps 1:1 to a
  Reduit account record via the OIDC `sub` claim. First login auto-
  creates the account record (configurable: `OIDC_AUTO_CREATE`).
- Admin role: a configurable list of OIDC `sub` claims (or an
  `admin` group claim) gets admin-only routes (manage other users,
  view system logs).

### Consequences

**Positive**

- Zero password management code in Reduit. Self-hosters' existing IdP
  handles MFA, recovery, audit, etc.
- Family deployments using Pocket ID get plug-and-play setup via the
  `joestump.pocket_id` Ansible collection (per established convention,
  OIDC clients are NEVER provisioned through the Pocket ID UI).
- Standard protocol — works with any compliant IdP (Pocket ID,
  Authelia, Keycloak, Okta, Auth0, Google Workspace).

**Negative**

- Self-hosters who do not already run an OIDC IdP must stand one up.
  Pocket ID is a small Go binary — recommended for the family
  deployment story. We do NOT bundle an OIDC IdP.
- First-time bootstrapping requires: (a) IdP up, (b) OIDC client
  registered, (c) Reduit configured with client creds, (d) admin
  user's `sub` listed in `OIDC_ADMIN_SUBS` env. Documented setup flow.
- IdP unavailability = no admin login. IMAPS/SMTPS protocol endpoints
  remain functional (they don't use OIDC), so mail flow continues.

**Neutral**

- Logout is local (clear session cookie + scs record). True logout
  from the IdP is RP-Initiated Logout (`end_session_endpoint`), wired
  if the IdP advertises it.

## Pros and Cons of the Options

### OIDC (chosen)

- **Good:** Outsources identity completely; works with any IdP;
  matches Joe's ops conventions.
- **Good:** Per-user scoping comes naturally from `sub` claim.
- **Bad:** Requires an IdP. Soft requirement for the target users
  (self-hosters typically have one or can run Pocket ID).

### Local password store

- **Good:** Self-contained — zero external dependencies.
- **Bad:** Implements password reset, MFA, lockout, audit trail,
  WebAuthn, etc. Out of scope for a relay.

### Reverse-proxy basic auth / forward-auth

- **Good:** Maximum simplicity.
- **Bad:** No identity passed to Reduit; can't scope per-user state.
  Acceptable as a wrapper for an internal-only tool, not for the
  multi-user case.

## Architecture Diagram

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant B as Browser
    participant R as Reduit
    participant I as Pocket ID (OIDC IdP)

    U->>B: visit /accounts
    B->>R: GET /accounts (no session)
    R-->>B: 302 → /auth/login
    B->>R: GET /auth/login
    R->>R: generate state · nonce · PKCE verifier
    R->>R: persist pre-session
    R-->>B: 302 → IdP /authorize?...code_challenge=...
    B->>I: GET /authorize
    U->>I: authenticate (password / passkey / etc)
    I-->>B: 302 → /auth/callback?code=...&state=...
    B->>R: GET /auth/callback
    R->>I: POST /token (code + code_verifier)
    I-->>R: id_token + access_token
    R->>R: validate signature · iss · aud · nonce
    R->>R: find account by sub (or auto-create)
    R->>R: create session in scs store
    R-->>B: Set-Cookie reduit_session; 302 → /accounts
```

OIDC authorization-code with PKCE. Reduit never sees the user's
password. Pocket ID handles password reset, MFA, WebAuthn, and audit;
Reduit just consumes the resulting `sub` claim and binds it to a
local account row.

## References

- ADR-0002 (multi-tenant) — per-user identity required.
- SPEC-0005 (Admin UI flows) — first-time setup, account list,
  add-Proton-account flow.
- [Pocket ID](https://github.com/pocket-id/pocket-id)
- [`joestump.pocket_id`](https://github.com/joestump/joestump.pocket_id) Ansible collection.
