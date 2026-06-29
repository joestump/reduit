# SPEC-0005: Local Browse & Search UI

## Overview

The Reduit **local UI** is an optional, server-rendered HTMX surface
for a human to browse and search the local cache (ADR-0006) with their
own eyes: mailboxes → conversations → messages, plus keyword and
semantic search, attachments, and per-contact facts. It is
**secondary to the stdio MCP** (ADR-0017), which is the primary
agent-facing surface; the UI exists only so a person can read what the
agent reads. There is no relay, no network listener beyond an optional
loopback HTTP server, and the cache is derived state — Proton remains
the source of truth (ADR-0014).

Posture is local-first and least-privilege, mirroring the sibling
`msgbrowse` project. The UI **binds loopback by default and has no
authentication** (ADR-0012): the single OS user *is* the identity,
so there is no login, no OIDC, no session or user concept. Because
cached mail is hostile input (a crafted message can carry script or a
traversal payload), the UI is built to need nothing off-origin — a
strict CSP over self-hosted assets, `html/template` auto-escaping on
every untrusted string, and path-contained media serving. To prevent
behavioral drift, the UI calls the **same `store` methods as the MCP
tools** (ADR-0017): search, transcript/context, attachments, and
contact facts share one implementation.

Governing: ADR-0005 (frontend stack, reframed), ADR-0012 (single-user
local-first), ADR-0006 (SQLite cache), ADR-0017 (stdio MCP + shared
store, no drift).

## Requirements

### Requirement: Loopback Default With Non-Loopback Warning

The UI's listen address MUST default to a loopback address. A bind to
any non-loopback address MUST be permitted but MUST emit a prominent
startup warning, because the UI has no authentication.

#### Scenario: Default bind is loopback

- **WHEN** the UI server is started without an explicit listen address
- **THEN** the system SHALL bind `127.0.0.1` (default
  `127.0.0.1:8787`) and SHALL serve only connections that reach that
  interface

#### Scenario: Non-loopback bind logs a prominent warning

- **WHEN** the operator configures a listen address whose host is not
  a loopback address (e.g. `0.0.0.0` or a routable interface)
- **THEN** the system SHALL still bind as requested AND SHALL log a
  prominent warning at startup stating that the UI has no
  authentication and that any wider exposure is the operator's
  deliberate choice behind their own access control

### Requirement: No Authentication

The UI MUST NOT implement authentication, authorization, login,
session, or any multi-user concept. It trusts the local OS user.

#### Scenario: Every route serves without a login

- **WHEN** a request reaches any UI route
- **THEN** the system SHALL serve it without any login redirect,
  credential check, session lookup, or per-user scoping, AND SHALL NOT
  set or require any authentication cookie or bearer token

#### Scenario: No OIDC, session, or user surface exists

- **WHEN** the UI is inspected for authentication machinery
- **THEN** there SHALL be no OIDC client, no session store, no
  `users` concept, and no admin/allowlist gate; the single OS user is
  the identity per ADR-0012

### Requirement: Strict Content-Security-Policy, Self-Only Assets

The UI MUST send a strict CSP and hardening headers on every HTML
response, and MUST load every asset from its own origin with no CDN.

#### Scenario: Strict CSP and hardening headers on HTML responses

- **WHEN** the server returns an HTML response (full page or HTMX
  fragment)
- **THEN** the response SHALL carry
  `Content-Security-Policy: default-src 'none'` with `script-src
  'self'`, `style-src 'self'`, `img-src 'self' data:`, `connect-src
  'self'`, `font-src 'self'`, `base-uri 'none'`, `form-action 'self'`,
  and `frame-ancestors 'none'`, plus `X-Content-Type-Options:
  nosniff`, `Referrer-Policy: no-referrer`, and `X-Frame-Options:
  DENY`

#### Scenario: All assets are same-origin and self-hosted

- **WHEN** a page references htmx, the stylesheet, the theme script,
  or icons
- **THEN** htmx (and its SSE extension where used), the built
  Tailwind 4 + DaisyUI stylesheet, the theme-toggle script, and the
  Hero Icons SHALL all be vendored or inlined and served from the UI's
  own origin, with no CDN, external font, or off-origin script, so the
  strict CSP holds without exception

### Requirement: Untrusted Content Is Escaped

All message-derived content rendered by the UI MUST be treated as
untrusted and escaped, since the cache is populated from crafted
external mail.

#### Scenario: Bodies, subjects, and extracted text are auto-escaped

- **WHEN** the UI renders a message body, subject, sender, or
  attachment-extracted text
- **THEN** the system SHALL render it through `html/template`
  auto-escaping so no embedded markup is interpreted as HTML

#### Scenario: URLs are linkified safely

- **WHEN** the UI linkifies a URL found in escaped message text
- **THEN** the generated anchor SHALL carry `rel="noopener noreferrer
  nofollow"`, and the surrounding text SHALL remain escaped

#### Scenario: Search snippets are escaped before highlighting

- **WHEN** the UI renders a search snippet with matched-term
  highlights
- **THEN** the system SHALL escape the snippet text first and apply
  highlight markers (`<mark>`) only afterward, and SHALL strip any
  stray highlight sentinels so injected markup cannot survive

### Requirement: Browse Mailboxes, Conversations, and Messages

The UI MUST let the user navigate the cache hierarchy and MUST be
multi-mailbox aware.

#### Scenario: Drill from mailboxes to a message

- **WHEN** the user opens the browse surface
- **THEN** the UI SHALL list the configured mailboxes, allow
  selecting one to list its conversations/threads, and allow selecting
  a conversation to read its messages in order, rendering each through
  the escaping rules above

#### Scenario: Filter to one mailbox or view across all

- **WHEN** the user has more than one mailbox configured
- **THEN** the UI SHALL allow scoping the view to a single mailbox AND
  SHALL allow a combined view across all mailboxes, scoping handled by
  the `mailbox_id` filter on the shared store query (ADR-0006)

### Requirement: Keyword and Semantic Search Over the Shared Store

The UI MUST offer keyword (FTS5) and semantic search that call the
**same `store` methods as the MCP search tool** (ADR-0017), and MUST
degrade gracefully when embeddings are unavailable.

#### Scenario: Search calls the same store methods as MCP

- **WHEN** the user submits a search query
- **THEN** the UI SHALL invoke the same hybrid `store` search method
  the MCP `search_messages` tool uses (FTS5 keyword + best-effort
  vector, fused by reciprocal-rank fusion), so keyword and semantic
  behavior cannot drift between surfaces

#### Scenario: Degrades to keyword-only without embeddings

- **WHEN** the embedding endpoint or stored vectors are unavailable
- **THEN** the search SHALL degrade to keyword-only results rather
  than failing, consistent with the MCP tool's degradation (ADR-0017)

#### Scenario: Results link back to the source message

- **WHEN** search results render
- **THEN** each result SHALL carry enough provenance (mailbox,
  conversation/sender, timestamp, message identity) to open the exact
  source message in the browse surface

### Requirement: Attachment and Media Serving

The UI MUST serve attachments and media with correct headers and MUST
contain path traversal; script-capable formats MUST NOT be inlined.

#### Scenario: Correct content type and disposition

- **WHEN** the UI serves an attachment or media file
- **THEN** the response SHALL set a correct `Content-Type` and an
  appropriate `Content-Disposition` for the file

#### Scenario: Path traversal is contained

- **WHEN** a media path is resolved
- **THEN** the system SHALL clean the path, anchor it (strip leading
  separators), and verify the result stays within the per-source base
  directory; a path escaping that base SHALL be rejected and the file
  SHALL NOT be served

#### Scenario: SVG is forced to download, never inlined

- **WHEN** the requested attachment is an SVG (or another
  script-capable format)
- **THEN** the system SHALL serve it with a download disposition and
  SHALL NOT render it inline, since SVG can carry script

### Requirement: Contact View With Cited Facts

The UI MUST present a contact's identifiers and the cited facts
accrued for that contact (SPEC-0011).

#### Scenario: Contact page shows identifiers and cited facts

- **WHEN** the user opens a contact
- **THEN** the UI SHALL render the contact's identifiers (the
  addresses that resolve to that person) AND the cited
  `contact_facts` for that contact, each fact showing its citation to
  the source message so the user can open the cited message

#### Scenario: Facts come from the shared store

- **WHEN** the contact page loads facts
- **THEN** it SHALL read them via the same `store` method the MCP
  contact-facts tool uses (ADR-0017), so facts cannot drift between
  surfaces

### Requirement: Optional Live Updates via SSE

The UI MAY use SSE where a screen genuinely needs live updates, but
SSE MUST NOT be load-bearing for core browse/search.

#### Scenario: SSE only where a screen needs it

- **WHEN** a screen benefits from live updates (e.g. sync progress)
- **THEN** the UI MAY open an SSE stream for that screen only, and the
  rest of the UI SHALL remain fully functional without SSE

#### Scenario: Core browse and search work without SSE

- **WHEN** SSE is unavailable or disabled
- **THEN** browsing mailboxes, reading messages, searching, and
  viewing contacts SHALL all continue to work via ordinary requests
  and HTMX swaps

## Out of Scope

- OIDC login, account-administration wizard, and any multi-user or
  admin surface — deleted by ADR-0012; the OS user is the identity.
- Write actions beyond what the CLI and MCP already own. Sending mail
  lives in SPEC-0010 (outbound send); this UI MAY surface at most a
  compose affordance that hands off to that path — send semantics
  (drafting, confirmation, Proton submission) are specified there, not
  here.
- Exposing the UI to the network. A non-loopback bind is permitted but
  is entirely the operator's responsibility behind their own access
  control; the UI ships no authentication to make that safe.
- IMAP/SMTP relay credentials, MCP-token issuance, and per-account
  state management — all removed with the relay (ADR-0012).
