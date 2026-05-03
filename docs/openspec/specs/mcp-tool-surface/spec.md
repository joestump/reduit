# SPEC-0006: MCP Tool Surface

## Overview

Reduit's embedded MCP server (per ADR-0008) exposes Proton-specific
operations to AI agents. The surface goes beyond standard
IMAP/SMTP — labels, system folders, encrypted send, Proton search —
because those are the operations that motivate building a Proton
relay rather than using a generic IMAP MCP.

Transport: HTTP+SSE (Streamable HTTP per the MCP spec) on the same
HTTPS listener as the admin UI, mounted at `/mcp`.

Governing: ADR-0001 (go-proton-api), ADR-0008 (embedded MCP),
ADR-0010 (multi-Proton-account per user), SPEC-0001 (Account Model),
SPEC-0003 (IMAP Server) for label/folder mapping consistency.

## Requirements

### Requirement: Bearer Authentication Required

Every MCP tool invocation MUST be authenticated. Authentication MUST
identify the calling Reduit account and scope all operations to that
account. Because a single user MAY own multiple accounts per
ADR-0010 / SPEC-0001, the bearer credential alone MUST be sufficient
to disambiguate a single account; when it is not, an out-of-band
account selector is required.

#### Scenario: Per-account MCP token authenticates as the bound account

- **WHEN** an MCP request carries `Authorization: Bearer <token>`
  where the token is a Reduit-issued per-account MCP token
- **THEN** the server SHALL look up the token by hash (SHA-256 of
  the bearer value) in `mcp_tokens`, verify it's not revoked or
  expired, and bind the request to the issuing account. Per-account
  tokens are the canonical bearer credential for MCP

#### Scenario: OIDC bearer token requires account selector

- **WHEN** an MCP request carries `Authorization: Bearer <jwt>`
  where the JWT is a valid OIDC ID token from the configured IdP
- **THEN** the server SHALL validate the JWT (signature, issuer,
  audience, expiry, nonce) and resolve `Principal.Subject` to a
  `user_id` via the `users` table. The request MUST also carry an
  account selector — either a path parameter (`/accounts/{id}/...`)
  or the `X-Reduit-Account` header containing the account's UUID —
  so the server can disambiguate which of the user's accounts to
  bind. Selector resolution MUST follow the precedence rule
  ("Selector precedence" REQ). The server SHALL verify the resolved
  account satisfies `account.user_id == users.id` for the JWT
  subject (per SPEC-0001) before binding the request. Failure
  responses MUST follow the indistinguishability rule
  ("Authorization-failure indistinguishability" REQ)

#### Scenario: Unauthenticated MCP request is rejected

- **WHEN** an MCP request arrives without a valid bearer token
- **THEN** the server SHALL respond `401 Unauthorized` with a
  generic body (e.g., `{"error":"unauthenticated"}`). The
  `WWW-Authenticate` header MAY name `Bearer` as a scheme but MUST
  NOT include a `realm` parameter that leaks deployment-internal
  identifiers

### Requirement: Selector Precedence

When both a path-parameter account selector (`/accounts/{id}/...`)
and an `X-Reduit-Account` header are present, the path parameter
MUST win. The header MUST be ignored — not parsed, not validated,
not error-reported — when a path parameter is also present. The
header is consulted only on routes that do not carry an account-id
path parameter (today: the bare `/mcp` endpoint accessed with an
OIDC bearer).

This rule eliminates a request-shape oracle (an attacker cannot
probe whether the header value matches the path value to learn
ownership of a non-owned account).

#### Scenario: Path parameter wins over header

- **WHEN** an MCP request carries both `/accounts/A/mcp` and
  `X-Reduit-Account: B`
- **THEN** the server SHALL bind the request to account `A`. The
  `X-Reduit-Account` header SHALL NOT be parsed; the value of `B`
  SHALL NOT influence routing, ownership checks, error responses,
  log lines, or response headers. No "header conflicts with path"
  warning SHALL be surfaced — the header is silently ignored

#### Scenario: Header consulted only when path has no selector

- **WHEN** an MCP request reaches a route without an account-id
  path parameter (e.g., bare `/mcp`) AND carries
  `X-Reduit-Account: A`
- **THEN** the server SHALL parse the header and treat its value
  as the account selector for ownership and binding purposes,
  subject to the indistinguishability rule on failures

#### Scenario: No selector at all

- **WHEN** an OIDC-bearer MCP request arrives at a route without
  an account-id path parameter and without an `X-Reduit-Account`
  header
- **THEN** the server SHALL respond `400 Bad Request` with body
  `{"error":"selector_required"}`. This is the ONE response code
  that distinguishes "selector missing" from "selector present but
  not owned" — and it carries no account identifiers. See the
  indistinguishability rule

### Requirement: Authorization-Failure Indistinguishability

When an OIDC-bearer MCP request supplies an account selector, the
server MUST NOT leak which-account-exists-versus-which-is-owned via
its failure response. "Selector present, account does not exist"
and "selector present, account exists but is not owned by the JWT
subject" MUST produce byte-identical responses (status, headers,
body, timing characteristics).

The threat: UUIDv7 carries a creation timestamp. Without this
discipline, any holder of a valid OIDC ID token (even a non-admin
user with zero accounts) could iterate UUIDs and learn which exist
on the deployment, plus when each was created.

This REQ is the auth-handshake-layer counterpart to the existing
"Account Scope on All Operations" REQ, which already mandates
identical-to-a-genuine-miss responses at the tool layer.

#### Scenario: Non-existent and non-owned selectors return identical responses

- **WHEN** an OIDC-bearer request carries a selector referencing
  account UUID `X` where (case A) no account row exists with
  `id=X`, OR (case B) a row exists but `account.user_id != users.id`
  for the JWT subject
- **THEN** in both cases the server SHALL respond `403 Forbidden`
  with body `{"error":"forbidden"}` — byte-identical between cases.
  Headers SHALL be byte-identical: `Content-Type: application/json`,
  no `WWW-Authenticate` realm leak, no `X-Reduit-*` diagnostic
  headers. Server-side log lines MAY differ (operators need to
  triage misconfigurations) but the wire response MUST NOT

#### Scenario: Indistinguishability test exists

- **WHEN** the test suite runs the MCP authz-failure tests
- **THEN** there SHALL be at least one test that exercises both
  cases (A: non-existent UUID; B: existing UUID owned by a
  different user) with the same OIDC bearer and asserts byte-for-
  byte equality of the HTTP response (status code, headers minus
  `Date`, body). Timing-side-channel testing is out of scope for
  v0.1 but a coarse same-order-of-magnitude check is RECOMMENDED

#### Scenario: Selector-missing distinguishable from selector-present-failures

- **WHEN** the selector is missing entirely (no path id, no
  `X-Reduit-Account` header)
- **THEN** the server SHALL respond `400 Bad Request` with body
  `{"error":"selector_required"}`, distinguishable from the 403
  used for both case A and case B above. This 400 carries no
  account identifier and so leaks nothing about which UUIDs
  exist

### Requirement: Account Scope on All Operations

Every tool's effects MUST be confined to the authenticated account.
Cross-account access MUST be impossible via the MCP surface.

#### Scenario: Message lookup filters by account_id

- **WHEN** any tool resolves a message ID, attachment ID, or
  conversation ID
- **THEN** the SQL query SHALL include `WHERE account_id = ?` for
  the authenticated account. A message ID belonging to another
  account SHALL surface as a `not_found` tool error, identical to a
  genuine miss

### Requirement: Required Tool Set

The MCP server MUST expose at minimum the following tools, each with
a defined JSON schema:

- `list_messages(folder, query?, page?, page_size?)`
- `get_message(message_id, format?)`
- `search_messages(query, page?, page_size?)`
- `send_message(to, cc?, bcc?, subject, body, body_format, attachments?)`
- `list_labels()`
- `add_label(message_id, label_id)`
- `remove_label(message_id, label_id)`
- `move_to_folder(message_id, folder)`
- `mark_read(message_ids)`
- `mark_unread(message_ids)`
- `download_attachment(message_id, attachment_id)`

#### Scenario: Tool listing reflects the required set

- **WHEN** an MCP client calls `tools/list`
- **THEN** the response SHALL include at minimum the tools enumerated
  above, each with name, description, and JSON schema for inputs

#### Scenario: Each tool has a stable name and schema

- **WHEN** a tool's name or input schema changes
- **THEN** the change SHALL be a documented breaking change, bumped
  in CHANGELOG. The MCP server's protocol version MAY be bumped to
  signal incompatibility

### Requirement: Idempotent Mutations

Label add/remove and folder move tools MUST be idempotent: calling
them when the target state already exists MUST succeed without an
error.

#### Scenario: Adding an already-applied label

- **WHEN** `add_label` is called with `(message_id, label_id)` where
  the message already carries the label
- **THEN** the tool SHALL return `{ "applied": false, "already_present":
  true }` with no error. No mutation SHALL be sent to Proton

#### Scenario: Removing a non-applied label

- **WHEN** `remove_label` is called for a label not present on the
  message
- **THEN** the tool SHALL return `{ "removed": false, "not_present":
  true }` with no error

#### Scenario: Moving to current folder

- **WHEN** `move_to_folder` targets the folder the message is
  already in
- **THEN** the tool SHALL return `{ "moved": false, "already_in_folder":
  true }` with no error

### Requirement: Send-Message Encryption

`send_message` MUST handle Proton-recipient encryption automatically
per SPEC-0004's encryption pipeline. The caller MUST NOT need to
specify encryption mode.

#### Scenario: Recipient mix is handled per-recipient

- **WHEN** `send_message` includes Proton and external recipients in
  one envelope
- **THEN** the server SHALL encrypt to each Proton recipient's key
  individually and send plain (or per the user's external-encryption
  preference) to external recipients. Each recipient's encryption
  outcome SHALL be reported in the tool response

#### Scenario: Send failure surfaces structured error

- **WHEN** Proton rejects the send (HV required, rate limit, key
  fetch failure for a recipient, etc.)
- **THEN** the tool SHALL return a structured error:
  `{ "code": "<symbolic>", "message": "<human>", "retriable":
  <bool>, "details": { ... } }`

### Requirement: Pagination on List and Search

`list_messages` and `search_messages` MUST support pagination via
`page` and `page_size` parameters, with a documented maximum
`page_size`.

#### Scenario: Default and max page_size

- **WHEN** the caller omits `page_size`
- **THEN** the server SHALL use `page_size = 50`. The maximum
  permitted `page_size` SHALL be `200`; values above SHALL be clamped
  to 200 and the response SHALL include `clamped: true` in metadata

#### Scenario: Pagination metadata included

- **WHEN** a list/search response is returned
- **THEN** it SHALL include `page`, `page_size`, `total_count` (if
  cheaply available; otherwise `total_count_known: false`), and
  `has_more`

### Requirement: Folder Names Match IMAP Mapping

Folder names accepted by `move_to_folder` and returned by
`get_message` MUST match the IMAP folder names defined in
SPEC-0003's folder mapping (system folders `INBOX`, `Sent`, etc.;
user labels under `Labels/<name>`).

#### Scenario: Symbolic folder names are accepted

- **WHEN** `move_to_folder` receives `INBOX` or `Labels/Receipts`
- **THEN** the server SHALL resolve them to the corresponding
  Proton system folder or user label, identical to the IMAP backend's
  resolution

#### Scenario: Unknown folder name yields a clear error

- **WHEN** `move_to_folder` receives a folder name that doesn't
  resolve
- **THEN** the tool SHALL return `{ "code": "unknown_folder",
  "message": "Folder X does not exist", "retriable": false }`

### Requirement: Streaming Bodies and Attachments

`get_message` and `download_attachment` MUST support streaming for
large payloads to avoid buffering whole messages in process memory.

#### Scenario: Large message body streamed

- **WHEN** `get_message` is called with `format=raw` on a 50 MiB
  message
- **THEN** the response SHALL stream as MCP-protocol-defined content
  chunks (or be returned as a content URL the client can range-fetch).
  The server's memory usage SHALL NOT exceed a documented cap (default
  16 MiB) regardless of message size

#### Scenario: Attachment streaming

- **WHEN** `download_attachment` is called for a 100 MiB attachment
- **THEN** the response SHALL stream from Proton through Reduit to
  the MCP client without full buffering. The decryption pipeline
  SHALL operate on a streaming reader

### Requirement: Per-Account Concurrency Limit

The MCP server MUST cap concurrent tool invocations per account to
avoid one user exhausting per-account Proton API quotas.

#### Scenario: Per-account concurrency cap

- **WHEN** a single account has the configured cap
  (`MCP_PER_ACCOUNT_CONCURRENCY`, default 4) of concurrent tool
  invocations in flight
- **THEN** additional invocations from the same account SHALL queue
  with a maximum queue depth of 16; queue overflow SHALL return
  `503 Service Unavailable` with a `Retry-After` header

### Requirement: Token Issuance and Revocation

Per-account MCP tokens MUST be issuable from the admin UI and
revocable. Tokens are scoped to exactly one account; a user who owns
multiple accounts issues tokens separately for each. Issuance and
revocation authority is "owner of the target account, OR an admin"
— admins MAY operate on any account; non-admins MAY operate only
on accounts where `account.user_id == session.user_id`.

#### Scenario: Owner or admin issues a new MCP token

- **WHEN** an authenticated user creates a token via the admin UI
  scoped to an account `A` (e.g., `POST /accounts/A/mcp-tokens`)
- **THEN** the server SHALL verify either `A.user_id ==
  session.user_id` OR `session.is_admin == true`. On success it
  SHALL generate a 32-byte random token, store its SHA-256 hash
  with `account_id = A`, an optional label, and optional expiry.
  The plaintext token SHALL be returned exactly once via the admin
  UI. If neither authority condition holds, the server SHALL
  respond `403 Forbidden` with the indistinguishability discipline
  applied to the case where `A` does not exist (an attacker without
  admin must not be able to learn whether a given UUID exists)

#### Scenario: Owner or admin revokes a token

- **WHEN** an authenticated user revokes a token via the admin UI
  for account `A`
- **THEN** the server SHALL apply the same authority check
  (`A.user_id == session.user_id || session.is_admin`). On success
  the token SHALL be marked revoked and subsequent MCP requests
  carrying it SHALL fail with `401 Unauthorized` within 1 second.
  Failure responses follow the indistinguishability discipline

## Out of Scope

- Folder/label CRUD (creating new labels via MCP) — deferred. Labels
  are created via the user's email client or Proton web UI.
- Calendar / Drive tool surface (deferred or out-of-project).
- Aggregate / cross-account tools for admins (admins use the admin
  UI; no special MCP access).
- Webhook-style push from server to MCP client (MCP polling /
  resources / prompts patterns are sufficient for v0.1).
