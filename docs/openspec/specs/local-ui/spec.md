# SPEC-0005: Local Insights UI

## Overview

The Reduit **local insights UI** is an optional, server-rendered HTMX
surface for a human to inspect what the cache has **derived** — extracted
attachments, per-contact facts, message/mailbox metadata coverage, and
cache/sync/embedding statistics. It is deliberately **not** a mail reader:
there is no mailbox → conversation → message browsing, no keyword or
semantic search UI, and no live-update stream. The stdio MCP (SPEC-0006,
ADR-0017) is the primary read surface for the cache; Proton's own clients
are where mail is read; this UI exists only for the glanceable,
web-shaped views an agent chat is bad at (ADR-0024).

> **Scope note.** This spec previously described a full Local Browse &
> Search UI. That scope was withdrawn by ADR-0024 (2026-07-03; epic #75 and
> issues #102–#105 closed won't-fix). The security posture below carries
> over from the withdrawn spec unchanged.

Posture is local-first and least-privilege. The UI **binds loopback by
default and has no authentication** (ADR-0012): the single OS user *is*
the identity. Cached data is still hostile-influenced input (facts and
metadata derive from attacker-authored mail; attachments are
attacker-authored bytes), so the UI needs nothing off-origin — a strict
CSP over self-hosted assets, `html/template` auto-escaping on every
untrusted string, and path-contained media serving. To prevent behavioral
drift, the UI reads through the **same `store` methods as the MCP tools**
(ADR-0017); it is read-only end to end.

Governing: ADR-0024 (insights scope), ADR-0005 (frontend stack, narrowed),
ADR-0012 (single-user local-first), ADR-0006 (SQLite cache), ADR-0017
(stdio MCP + shared store, no drift).

## Requirements

### Requirement: Loopback Default With Non-Loopback Warning

The UI server MUST bind `127.0.0.1` by default. When configured to bind a
non-loopback address, it MUST log a prominent warning naming the exposure
and MUST NOT add authentication to compensate (ADR-0011 fronting guidance
applies instead).

#### Scenario: Default bind is loopback

- **WHEN** `reduit serve` starts with no bind configuration
- **THEN** the server SHALL listen on a loopback address only

#### Scenario: Non-loopback bind warns

- **WHEN** the operator configures a non-loopback bind address
- **THEN** the server SHALL start but SHALL log a prominent warning that
  the insights UI is unauthenticated and now network-exposed

### Requirement: No Authentication

The UI MUST NOT implement authentication, sessions, or user identity: the
operating-system user is the identity (ADR-0012). There is no login page,
no token, and no cookie-based state.

#### Scenario: No auth surface exists

- **WHEN** any UI route is requested
- **THEN** the response SHALL NOT redirect to a login flow, set an
  identity cookie, or vary on any credential

### Requirement: Strict Content-Security-Policy, Self-Only Assets

Every HTML response MUST carry a strict CSP permitting only self-hosted
assets; the UI MUST function with no off-origin request of any kind
(styles, scripts, fonts, images). Inline script MUST NOT be used.

#### Scenario: CSP on every page

- **WHEN** any UI page is served
- **THEN** it SHALL include a CSP restricting sources to `'self'` (with at
  most hash-allowed inline style), and the page SHALL render fully with the
  network blocked to all non-loopback hosts

### Requirement: Untrusted Content Is Escaped

Every string that derives from mail content — attachment filenames, fact
text, contact names/addresses, subjects, label names — MUST pass through
`html/template` contextual auto-escaping. The UI MUST NOT mark any
mail-derived value as safe HTML.

#### Scenario: Hostile fact text is inert

- **WHEN** a contact fact whose text contains `<script>` markup is rendered
- **THEN** the markup SHALL be displayed as text, not executed or
  interpreted

### Requirement: Attachment Listing And Path-Contained Serving

The UI SHALL list cached attachments (filename, MIME type, size, owning
message metadata) and serve extracted attachment content for viewing or
download. Serving MUST be path-contained: only files within reduit's own
data directory are servable, resolved paths MUST be verified inside that
root, and traversal attempts MUST be rejected.

#### Scenario: Attachment listing

- **WHEN** the attachments view is requested
- **THEN** the UI SHALL render the cached attachments with filename, MIME
  type, size, and owning-message metadata, read via the shared store

#### Scenario: Traversal is rejected

- **WHEN** an attachment request resolves outside reduit's data root
  (e.g. via `..` or an absolute path)
- **THEN** the server SHALL refuse it without touching the file

### Requirement: Contact Facts With Citations

The UI SHALL render per-contact extracted facts with their citations
(the source message's metadata), read via the same store methods as the
MCP's fact tools (SPEC-0011). The view is read-only: fact editing, merging,
and denylisting remain CLI/MCP operations.

#### Scenario: Facts with citations

- **WHEN** a contact's view is requested
- **THEN** the UI SHALL render that contact's facts each with its source
  citation, and SHALL NOT offer mutation controls

### Requirement: Metadata And Stats

The UI SHALL render cache-level insight pages: per-mailbox message counts
and date coverage, sync run history (from `sync_runs`), attachment
extraction coverage, embedding/indexing progress, and storage size — the
operational "how healthy and complete is my cache" view. All values come
from the shared store; the UI computes nothing the store cannot answer.

#### Scenario: Stats page

- **WHEN** the stats view is requested
- **THEN** it SHALL render per-mailbox counts, date coverage, last sync
  runs with their summaries, extraction/embedding coverage, and store size

### Requirement: Read-Only Shared-Store Access

Every UI handler MUST read through the same `store` methods the MCP tools
use and MUST NOT write to the store, call Proton, or trigger sync/extract
work. The UI SHALL degrade gracefully offline: it renders whatever the
cache holds (SPEC-0002 offline behavior).

#### Scenario: No writes, no network

- **WHEN** any UI request is handled
- **THEN** it SHALL perform no store writes and no Proton API calls

#### Scenario: Works offline

- **WHEN** the machine has no network connectivity
- **THEN** all insights pages SHALL render from the cache

### Requirement: Withdrawn Surfaces Stay Withdrawn

The UI MUST NOT grow message browsing, conversation views, a search UI, or
live-update streams (SSE/WebSocket) without a superseding ADR revisiting
ADR-0024.

#### Scenario: No browse or search routes

- **WHEN** the UI's route surface is enumerated
- **THEN** it SHALL contain no conversation/message browsing route and no
  search endpoint
