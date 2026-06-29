# SPEC-0006: MCP Tool Surface

## Overview

The MCP server is Reduit's **primary** surface (ADR-0017): it is how
Claude and other agents search, read, and act on the user's Proton
mail. It is a stdio MCP server built on the official
`github.com/modelcontextprotocol/go-sdk`, launched as a subprocess by
the user's own MCP client (`reduit mcp`). There is no network
listener, no OIDC, no account record, and no auth handshake — the
process runs with the authority of the single local OS user
(ADR-0012). Logs go to stderr so they never corrupt the JSON-RPC
stream on stdout.

The retrieval tools are **citation-faithful**: every result a tool
returns carries exact provenance (`message_id`, stable `hash`,
`mailbox`, `conversation`/`sender`, `source`, `timestamp`) so an agent
cites precisely and a human can open the same message in the loopback
UI (ADR-0005). `search_messages` is hybrid — FTS5 keyword search fused
with best-effort vector search (ADR-0015) via reciprocal-rank fusion —
and degrades to keyword-only when embeddings or the LLM endpoint are
unavailable. Read tools surface transcripts, surrounding context,
attachments and their extracted text (SPEC-0009), links, and cited
contact facts (SPEC-0011). A single mutating tool, `send`, submits
mail via go-proton-api (SPEC-0010/ADR-0020) and is the only tool that
writes. Every tool is a thin adapter over the same `store` methods the
UI uses, so behavior cannot drift between surfaces.

Governing: ADR-0017 (stdio MCP + hybrid RAG), ADR-0012 (single-user
local pivot), ADR-0005 (loopback UI / shared store), ADR-0015
(embeddings/vector backend), ADR-0016 (attachment extraction),
ADR-0019 (contact facts), ADR-0020 (outbound send), SPEC-0007 (Local
Cache Store), SPEC-0009 (Attachment Extraction), SPEC-0010 (Outbound
Send), SPEC-0011 (Contact Facts).

## Requirements

### Requirement: Stdio Transport, No Auth

The MCP server MUST speak stdio JSON-RPC and be launched as a
subprocess by the user's MCP client via `reduit mcp`. It MUST NOT open
a network listener, require a bearer token, or perform any
authentication: it runs with the authority of the local OS user. All
diagnostic and log output MUST go to stderr so stdout carries only the
JSON-RPC protocol stream. An optional loopback streamable-HTTP mode
MAY exist for clients that need it, but stdio is the default.

#### Scenario: Server launched over stdio

- **WHEN** an MCP client spawns `reduit mcp` as a subprocess and
  performs the MCP initialize handshake over stdin/stdout
- **THEN** the server SHALL complete the handshake and serve tool
  calls over the stdio JSON-RPC stream, having opened no network
  socket

#### Scenario: Logs never corrupt the protocol stream

- **WHEN** the server emits a log line, warning, or error at any
  point during a session
- **THEN** it SHALL write that output to stderr only; stdout SHALL
  carry exclusively well-formed JSON-RPC messages

#### Scenario: No bearer token is required

- **WHEN** a tool call arrives over the stdio transport with no
  credential of any kind
- **THEN** the server SHALL execute the tool with the local user's
  authority; it SHALL NOT reject the call for missing authentication

### Requirement: Citation Contract on Every Retrieval Result

Every retrieval result the server returns MUST carry its coordinates:
`message_id`, the stable content `hash`, `mailbox`,
`conversation`/`sender`, `source`, and `timestamp`. The server MUST
NOT return a passage, transcript line, attachment snippet, link, or
contact fact without the coordinates needed to cite it and open it in
the UI.

#### Scenario: Search hit carries full provenance

- **WHEN** any retrieval tool (`search_messages`, transcript,
  context, attachment text, contact facts) returns a result item
- **THEN** the item SHALL include `message_id`, stable `hash`,
  `mailbox`, `conversation`/`sender`, `source`, and `timestamp`

#### Scenario: No coordinate-less passage is ever returned

- **WHEN** a result would otherwise be returned without one or more
  of its required coordinates
- **THEN** the server SHALL treat that as a defect and SHALL NOT emit
  the bare passage; a result is either fully cited or omitted

### Requirement: Hybrid `search_messages`

`search_messages` MUST run FTS5 keyword search and best-effort vector
search (ADR-0015) and fuse the two ranked lists with reciprocal-rank
fusion (`score = Σ 1/(60 + rank)`), because bm25 and cosine scores are
not directly comparable. When embeddings or the LLM endpoint are
unavailable, it MUST degrade to keyword-only rather than failing. It
MUST support filters for mailbox, sender, date range, and the presence
of attachments or links.

#### Scenario: Keyword and vector results are rank-fused

- **WHEN** `search_messages` runs with a reachable embedding endpoint
  and existing vectors
- **THEN** it SHALL compute an FTS5 keyword ranking and a vector
  similarity ranking and SHALL fuse them with reciprocal-rank fusion
  (`score = Σ 1/(60 + rank)`), returning a single ranked, cited result
  list

#### Scenario: Degrade to keyword-only when vectors are absent

- **WHEN** the embedding endpoint is unreachable or no vectors exist
  for the corpus
- **THEN** `search_messages` SHALL return keyword-only results rather
  than erroring; results SHALL still be fully cited

#### Scenario: Filters narrow the candidate set

- **WHEN** `search_messages` is called with any of `mailbox`,
  `sender`, a date range, `has_attachment`, or `has_link`
- **THEN** the server SHALL restrict both the keyword and vector
  passes to candidates matching those filters before fusion

### Requirement: Read Tools Over the Cache

The server MUST expose read tools that retrieve a single message, a
conversation transcript, and the surrounding context of a message;
list a message's attachments and fetch an attachment's extracted text
(SPEC-0009); list a message's links; and return a contact's cited
facts (SPEC-0011). All read tools MUST source their data from the
local cache via the same `store` methods the UI uses and MUST return
cited results.

#### Scenario: Get message and transcript

- **WHEN** an agent calls the get-message or conversation-transcript
  tool with a `message_id`/`conversation` reference
- **THEN** the server SHALL return the message or the ordered
  transcript from the cache, each line carrying the citation
  coordinates

#### Scenario: List attachments and fetch extracted text

- **WHEN** an agent lists a message's attachments and then fetches an
  attachment's extracted text
- **THEN** the server SHALL return the attachment list and the cached
  extracted text (SPEC-0009), with provenance back to the
  `(source_message_hash, attachment_id)`

#### Scenario: Get a contact's cited facts

- **WHEN** an agent requests a contact's facts
- **THEN** the server SHALL return the deduped, cited facts
  (SPEC-0011), each carrying its `source_message_hash` so the source
  can be opened

### Requirement: The `send` Tool Is the Only Mutating Tool

The server MUST expose exactly one mutating tool, `send`, which
submits mail via go-proton-api (ADR-0020/SPEC-0010). Every other tool
MUST be read-only over the cache. `send` MUST require explicit,
unambiguous invocation with the fields from-mailbox, recipients,
subject, and body, and MUST NOT fire as a silent or automatic side
effect of any other operation.

#### Scenario: Send requires explicit fields

- **WHEN** the `send` tool is invoked missing any of from-mailbox,
  recipients, subject, or body
- **THEN** the server SHALL reject the call with a structured
  validation error and SHALL NOT submit any mail

#### Scenario: Send never fires implicitly

- **WHEN** any read or search tool is invoked
- **THEN** the server SHALL NOT, as a side effect, compose or submit
  mail; submission happens only through an explicit `send` invocation

#### Scenario: No other tool writes

- **WHEN** any tool other than `send` is invoked
- **THEN** that tool SHALL perform read-only operations over the
  cache and SHALL make no write to Proton

### Requirement: Multi-Mailbox Operation

Tools MUST operate across all of the user's mailboxes by default and
MUST accept a `mailbox` filter that scopes the operation to a single
mailbox (ADR-0012).

#### Scenario: Search spans all mailboxes by default

- **WHEN** a retrieval tool is invoked without a `mailbox` filter
- **THEN** the server SHALL search across every configured mailbox

#### Scenario: Mailbox filter scopes to one mailbox

- **WHEN** a retrieval tool is invoked with a `mailbox` filter
- **THEN** the server SHALL restrict the operation to that mailbox
  only

### Requirement: Thin Adapter Over the Store

Every tool MUST call the same `store` methods the loopback UI uses
(ADR-0005) — search, transcript/context, list attachments/links,
fetch attachment text, contact facts, send — so keyword, semantic, and
media behavior cannot drift between the MCP surface and the UI. A tool
MUST NOT implement its own query path that bypasses the store.

#### Scenario: Tools and UI share store methods

- **WHEN** a tool resolves a search, transcript, attachment-text, or
  facts request
- **THEN** it SHALL invoke the same `store` method the UI invokes for
  that operation, with no parallel or divergent query path

### Requirement: In-Memory Round-Trip Testability

The tool surface MUST be exercisable via an in-memory client↔server
transport (`NewInMemoryTransports`) so tests drive the real tools as a
client sees them, with no spawned process or socket.

#### Scenario: Round-trip test exercises a tool

- **WHEN** the test suite connects a client to the server over an
  in-memory transport and calls a tool
- **THEN** the test SHALL receive the same typed, cited result a real
  MCP client would receive over stdio

## Out of Scope

- HTTP+SSE transport with OIDC bearer auth and per-account/per-user
  MCP tokens (ADR-0008 design; deleted by ADR-0017 — no listener, no
  IdP, no account records).
- Journal / "on this day" tools — deferred until journal generation
  produces the entries those tools would read.
- Any tool that bypasses the `store` to query Proton or the cache
  directly.
- Folder/label CRUD and other mutating mail operations beyond `send`.
- Concurrent multi-client access to one server process (stdio is one
  client session per spawned process; this is a personal tool).
