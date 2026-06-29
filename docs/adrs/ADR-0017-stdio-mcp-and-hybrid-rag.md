# ADR-0017: stdio MCP server and citation-faithful hybrid RAG

- **Status:** accepted
- **Date:** 2026-06-29
- **Deciders:** Joe Stump
- **Supersedes:** [ADR-0008](ADR-0008-embedded-mcp-server.md) (embedded HTTP+SSE
  MCP server with OIDC bearer auth)

## Context and Problem Statement

The MCP server is now Reduit's **primary** surface (ADR-0012): it is how Claude
and other agents search, read, and act on the user's Proton mail. ADR-0008
designed MCP as an HTTP+SSE endpoint mounted on the shared HTTPS listener, behind
OIDC bearer tokens, scoped to a Reduit account record. None of that survives the
single-user local pivot: there is no HTTPS listener, no OIDC, no account record.

Two things need deciding: the transport/SDK, and how the retrieval tools shape
results so agent answers are citation-faithful. This mirrors `msgbrowse`'s
ADR-0004.

## Decision Drivers

- **Local, no auth, launched by the client.** A single-user local tool should be
  launched as a subprocess by the user's own MCP client (Claude Desktop/Code) over
  stdio — no network listener, no token to manage.
- **Citation-faithful.** Every retrieved passage must carry exact provenance so
  answers can cite precisely and a human can jump to the source.
- **No drift between surfaces.** MCP and the loopback UI (ADR-0005) must share the
  same store methods so keyword/semantic/media behavior cannot diverge.
- **Multi-mailbox.** Tools operate across (or filter to) the user's N mailboxes
  (ADR-0012).
- **Read and write.** Beyond retrieval, the surface includes the send capability
  (ADR-0020) — the one mutating tool.

## Considered Options

1. **stdio MCP via the official `github.com/modelcontextprotocol/go-sdk`.** Typed
   `AddTool[In, Out]` with inferred JSON Schema; stdio transport launched by the
   client; optional loopback streamable-HTTP for special cases.
2. **Keep HTTP+SSE + OIDC (ADR-0008).** Rejected — depends on the deleted network
   listener and IdP; wrong trust model for a local tool.
3. **`mark3labs/mcp-go`.** A viable third-party SDK, but the official SDK is the
   spec-tracking, canonical choice (matching `msgbrowse`).

## Decision Outcome

**Chosen: option 1 — stdio MCP, official Go SDK, citation-faithful hybrid RAG.**

- **Transport.** `reduit mcp` speaks **stdio** and is launched by the MCP client
  as a subprocess (the `command`/`args` config the client already understands). An
  optional loopback streamable-HTTP mode MAY exist for clients that need it; the
  default is stdio. No auth — the process runs as the local user (ADR-0012). Logs
  go to **stderr** so they never corrupt the JSON-RPC stream on stdout.
- **SDK.** The official `github.com/modelcontextprotocol/go-sdk`; typed tool
  definitions infer and validate their JSON Schemas. `NewInMemoryTransports`
  enables full client↔server round-trip integration tests.
- **`search_messages` is hybrid + citation-faithful.** It runs FTS5 keyword search
  and (best-effort) vector search (ADR-0015) and fuses them with **reciprocal-rank
  fusion** (`score = Σ 1/(60 + rank)`) — rank fusion because bm25 and cosine scores
  are not comparable. If the embedding endpoint or vectors are unavailable it
  **degrades to keyword-only** rather than failing. Every result carries
  `message_id`, stable `hash`, `mailbox`, `conversation/sender`, `source`, and
  `timestamp`, so the model cites exactly and the human can open the message in the
  UI.
- **Thin adapter over the store.** Tools call the same `store` methods the UI uses
  (search, transcript/context, list attachments/links, fetch attachment text,
  contact facts). Retrieval, attachment, and facts tools surface the work of
  ADR-0014/0015/0016/0019 with provenance.
- **Mutating tool: send.** A `send` tool composes and submits mail via Proton
  (ADR-0020). It is the sole tool that writes; everything else is read-only over
  the cache.

### Consequences

**Positive**

- No network listener, no OIDC, no token plumbing — the agent surface is a local
  subprocess with the local user's authority.
- Uniform, self-citing results make RAG answers traceable to source messages.
- A future `sqlite-vec` backend (ADR-0015) changes only `store` internals; the
  tools are unaffected.

**Negative**

- stdio means one client session per spawned process; multi-client concurrent
  access is not a goal (it is a personal tool).
- The send tool gives an agent a write path to the user's mail; it must be clearly
  scoped and, per ADR-0020, guarded (e.g. explicit confirmation / not silently
  autonomous).

**Operational**

- Configure the client with `command: reduit`, `args: ["--data-dir", "…", "mcp"]`.
- The official SDK floors the Go toolchain at a recent version (documented in the
  README build prerequisites), consistent with `msgbrowse`.
