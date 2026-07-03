# Design: Onboarding & Proton Auth (SPEC-0007)

## Architecture

`reduit auth` is a Cobra command that orchestrates three actors: the
terminal (no-echo prompts), `go-proton-api` (all Proton-protocol work),
and two stores — the SQLite `mailboxes` row (state + `proton_user_id` +
session UID) and the OS keychain (the live secrets: refresh token, access
token, and mailbox passphrase). Reduit owns none
of the cryptography: SRP, TOTP submission, and OpenPGP key unlock are
go-proton-api calls. Reduit owns ordering, prompts, state transitions,
the rule that secrets only ever go to the keychain, and the choice of
app-version. Human verification is *avoided* by presenting a Proton
Bridge app-version (ADR-0021), not solved — there is no in-app CAPTCHA
solver.

The flow is transactional in spirit: a `mailboxes` row is created in
`pending_auth` *before* any network call, and only advances to `active`
once both keychain writes succeed. If any step fails or is cancelled,
the row stays `pending_auth` (a later run can resume or it can be
removed) and no half-written secret survives — the keychain writes are
the last thing the flow does.

```mermaid
sequenceDiagram
    actor Op as Operator
    participant CLI as reduit auth
    participant GP as go-proton-api
    participant DB as SQLite (mailboxes)
    participant KC as OS keychain

    Op->>CLI: reduit auth
    CLI->>Op: prompt email
    CLI->>DB: INSERT row (pending_auth, no proton_user_id)
    CLI->>Op: prompt password (no echo)
    CLI->>GP: SRP login(email, password)<br/>x-pm-appversion = macos-bridge@3.21.2 (default)
    Note over CLI,GP: Bridge app-version → Proton raises no 9001
    alt 9001 (only if a non-Bridge app-version was configured)
        GP-->>CLI: HV challenge {methods, token}
        CLI->>Op: clear error: unset/override proton.app_version<br/>(no solver, no browser); abort
    end
    alt 2FA required
        GP-->>CLI: 2FA required
        CLI->>Op: prompt TOTP (no echo)
        CLI->>GP: submit TOTP
    end
    GP-->>CLI: session + proton_user_id + session UID + access/refresh tokens
    CLI->>DB: check proton_user_id uniqueness
    CLI->>Op: prompt mailbox passphrase (no echo)
    CLI->>GP: unlock OpenPGP keys(passphrase)
    GP-->>CLI: keys unlocked
    CLI->>KC: write mailbox/<id>/refresh_token
    CLI->>KC: write mailbox/<id>/access_token
    CLI->>KC: write mailbox/<id>/mailbox_passphrase
    CLI->>DB: set proton_user_id, session UID, state=active
    CLI->>Op: success
```

## Flow stages

1. **Email + row creation.** Prompt for the address; insert a
   `pending_auth` row with a fresh UUIDv7 `id`. For a re-auth, resolve
   the existing row instead of inserting.
2. **SRP.** Prompt for the password with echo off; hand email+password
   to go-proton-api's SRP login. Reduit never sees a password hash it
   computes itself.
3. **Human verification is avoided (ADR-0021).** reduit presents a Proton
   **Bridge** app-version by default (`proton.DefaultAppVersion`,
   `macos-bridge@3.21.2`) in the `x-pm-appversion` header. Proton
   challenges the *web* client family with a 9001 CAPTCHA on every fresh
   login but waves the Bridge family through with none, so the normal
   login never sees a challenge. There is **no in-app CAPTCHA solver** —
   every solve mechanism (loopback iframe, native webview, chromedp
   native-app-bridge capture, verify-page press-Enter/same-token retry)
   was falsified live or proved unnecessary; see ADR-0021 rev 3. If a
   non-Bridge app-version is configured (an explicit web value, or `auto`
   web-client detection) and Proton returns a 9001, reduit classifies it
   into an `HVRequiredError` only to *detect* the case and return a clear,
   actionable error ("unset/override `proton.app_version`") — it does not
   render, embed, capture, or launch a browser.
4. **2FA.** If go-proton-api signals 2FA-required, prompt for the TOTP
   code (no echo) and submit. Wrong codes re-prompt or abort with a
   concise message.
5. **Passphrase + key unlock.** Prompt for the mailbox passphrase (no
   echo); ask go-proton-api to unlock the OpenPGP private keys. Failure
   re-prompts or aborts.
6. **Persist.** Write the refresh token, access token, and passphrase to
   the keychain, record `proton_user_id` and session UID, flip state to
   `active`. Keychain writes are last so a failure before them leaves
   nothing to clean up.

## Identity resolution and uniqueness

`proton_user_id` is unknown until go-proton-api returns the session, so
the duplicate check happens *after* SRP/2FA, before the keychain writes:

- **New add.** If the resolved `proton_user_id` matches no row, record
  it on the freshly-created row. The `UNIQUE(proton_user_id)` constraint
  (SPEC-0001) is the backstop; a race that slips past the pre-check still
  fails at insert with the same "already configured" message.
- **Re-auth.** The row already carries a `proton_user_id`; the resolved
  value MUST equal it. A mismatch (operator pointed re-auth at the wrong
  Proton account) is an error and never overwrites the stored value.

This is why `reduit auth` for an already-configured account is rejected
with guidance ("already configured" for `active`, "re-auth it" for
`needs_reauth`) rather than creating a second row.

## Secret handling

| Secret | Source | Destination | Never |
| --- | --- | --- | --- |
| Password | no-echo prompt | go-proton-api SRP only | disk, logs, DB, keychain |
| TOTP code | no-echo prompt | go-proton-api only | disk, logs, DB |
| Mailbox passphrase | no-echo prompt | go-proton-api unlock + `mailbox/<id>/mailbox_passphrase` | disk, logs, DB |
| Refresh token | go-proton-api session | `mailbox/<id>/refresh_token` | disk, logs, DB |
| Access token | go-proton-api session | `mailbox/<id>/access_token` | disk, logs, DB |

- **No flags, no env.** Password and passphrase are read only via
  no-echo terminal prompts (`golang.org/x/term`), never CLI flags or
  environment, so they cannot land in shell history or a process listing.
- **slog redaction.** Auth-path logging logs *structure* (which step,
  which mailbox id, success/failure), never secret values. Secret-bearing
  types carry a `LogValue()` that returns a redacted placeholder so an
  accidental `slog` of the struct cannot leak. The structured-logging
  backend is `github.com/charmbracelet/log` used *as an `slog.Handler`*
  (ADR-0022) — only the root handler construction changed; the `slog` API
  and this redaction discipline are backend-agnostic and unchanged. Logs
  go to stderr.
- **Keychain keys.** Service `reduit`; account keys
  `mailbox/<id>/refresh_token`, `mailbox/<id>/access_token`, and
  `mailbox/<id>/mailbox_passphrase` (ADR-0013). The DB stores only the
  `mailbox_id` reference. The access token is a session secret persisted
  alongside the refresh token so a cross-process resume can reuse the cached
  session (see "Cross-process session resume").

## Re-auth and cache preservation

A `needs_reauth` mailbox arises when sync/send observes an invalid or
revoked refresh token (SPEC-0001 lifecycle). Re-auth is the same command
on the same row: it overwrites the two keychain entries and flips the
state back to `active`. It deliberately does **not** touch the
`mailbox_id`-scoped cache (messages, attachments, sync cursors, FTS5):
the credentials were stale, the derived data was not. Preserving the
cache means re-auth is cheap and does not trigger a full re-sync.

## Cross-process session resume

A session minted by `reduit auth` in one process must resume in another
(a `labels`, `sync`, or `send` run, or the cheap path of `auth refresh`)
without re-prompting. Three pieces of session state make that work, and all
are load-bearing (ADR-0001, ADR-0013, ADR-0021):

- **Access token (session reuse, not eager refresh).** Resume rebuilds the
  session by REUSING the cached tokens via go-proton-api's session-reuse
  constructor `Manager.NewClient(uid, access, refresh)`, which makes no
  network call. It deliberately does **not** use
  `Manager.NewClientWithRefresh`, whose eager `/auth/v4/refresh` of a
  freshly-2FA'd session comes back with a REDUCED scope (the "used the wrong
  newClient function" gotcha documented by Proton-API-Bridge). That reduced
  scope later fails key/salt access — `GetSalts` during `Unlock` — with
  **403 code 9101** ("Access token does not have sufficient scope"), the
  concrete bug this fixes: a low-scope call like `labels` succeeds on resume
  while `sync`'s unlock 9101s. Reusing the cached access token preserves the
  2FA-elevated scope; go-proton-api lazily refreshes only when that token
  expires (on a 401), and a registered auth handler captures the rotated
  tokens then (mirroring Proton Bridge's session caching). Because reuse does
  no I/O, resume does not validate — the first real API call surfaces an
  invalid session. The access token is a session secret, so it lives in the
  keychain alongside the refresh token, is written at `auth` time, and is
  re-read and re-persisted (with the refresh token) after operations when a
  lazy refresh rotated it. A row with a refresh token but no access token (a
  pre-fix row) is **not** resumed via an eager refresh: `labels`/`sync`
  surface an actionable re-auth message and `auth refresh` falls through to
  interactive re-login, which stores a fresh full-scope access token and
  self-heals the row.
- **Session UID.** go-proton-api returns a session UID (`auth.UID`) that
  is distinct from the account's `proton_user_id`. Proton's
  `/auth/v4/refresh` (the lazy refresh) identifies the session by this UID;
  a refresh with an empty UID yields code **10013** ("invalid refresh
  token"). The UID is non-secret session state, so it lives on the
  `mailboxes` row (not the keychain, ADR-0013), is persisted at `auth`
  time alongside the secret writes, and is presented on every resume. A
  lazy refresh may rotate the UID, the access token, and the refresh token;
  all are re-read and re-persisted afterward. A row with a token but no UID
  (a pre-migration row) skips the resume attempt and falls through to
  interactive re-login, which re-persists everything and self-heals the row.
- **App-version binding.** Proton binds a session to the app-version that
  minted it, so the app-version presented at resume must match the one at
  mint — a mismatch is another 10013. The default Bridge app-version
  satisfies this for the normal path; an operator who overrides
  `proton.app_version` must do so consistently across `auth`, `labels`,
  and `sync`.

## Keyring availability

The keychain is a hard dependency, not a fallback. Two failure points:

- **At auth time**, the secret-write step needs a writable, unlocked
  keyring. If absent, abort with an actionable message; do not stash the
  secret elsewhere.
- **At runtime**, sync/send read the secrets non-interactively. This is
  what makes a headless host need an out-of-band unlocked Secret Service
  collection (ADR-0013) — there is no human at the terminal to prompt.

Per ADR-0013, Reduit documents the headless setup rather than
reintroducing an on-disk key file. A file-based secret store, if ever
needed, would be a new opt-in ADR, loudly caveated.

## Error surfaces

| Condition | Behavior |
| --- | --- |
| Wrong password / TOTP | concise "authentication failed"; no secret echoed; row stays `pending_auth`/`needs_reauth` |
| Human verification (9001) — only under a non-Bridge app-version | clear, actionable error: "unset/override `proton.app_version` / `REDUIT_PROTON_APP_VERSION`". No solver, no browser, no raw token dump |
| Passphrase fails to unlock keys | re-prompt or abort; never advance to `active` |
| Duplicate `proton_user_id` | "already configured" (or "re-auth it"); no second row |
| `proton_user_id` mismatch on re-auth | error; stored value untouched |
| Resume with missing/rotated session UID or mismatched app-version (10013) | missing UID → fall back to interactive re-login (self-heals the row); rotated UID/token → re-persist after resume |
| Resume of a pre-fix row with no stored access token | `labels`/`sync` → actionable "no stored access token; re-authenticate" (never an eager refresh that would 9101); `auth refresh` → interactive re-login stores a fresh access token |
| Key/salt access returns 403 code 9101 ("insufficient scope") | prevented by reusing the cached access token on resume (session reuse, not eager refresh); a pre-fix row without one is sent to re-auth instead of resuming into a reduced scope |
| Keyring unavailable/locked | abort with provisioning/unlock guidance; no fallback store |

## References

- ADR-0001 (go-proton-api as Proton client — SRP, 2FA, OpenPGP unlock,
  app-version configuration)
- ADR-0012 (single-user, local-first — no web/OIDC/relay)
- ADR-0013 (secrets in the OS keychain — keying, headless unlock; session
  UID as non-secret row state)
- ADR-0021 (avoid human verification by identifying as a Proton Bridge
  client — the Bridge app-version; no in-app CAPTCHA solver; falsified
  solve approaches; session/app-version binding)
- SPEC-0001 (mailbox model — row, state machine, `proton_user_id`
  immutability and uniqueness)
