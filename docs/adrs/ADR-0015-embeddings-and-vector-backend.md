# ADR-0015: Embeddings and vector backend

- **Status:** accepted
- **Date:** 2026-06-29
- **Deciders:** Joe Stump

## Context and Problem Statement

Semantic search and RAG over the local mail cache (ADR-0014) need per-message
(and per-attachment-chunk, ADR-0016) embeddings and a way to search them by
vector similarity. Two choices: how vectors are computed, and how they are
stored and queried inside the single SQLite store (ADR-0006). The scale is a
personal/family mail corpus on one machine — large enough to matter, small
enough that exotic infrastructure is unwarranted. This mirrors the same decision
in `msgbrowse` (its ADR-0002).

## Decision Drivers

- **Local by default.** Embedding should run against a local model out of the box
  so no mail content leaves the machine (ADR-0018); a hosted endpoint is an opt-in
  override.
- **No heavy infra.** No external vector database, no separate service to deploy.
  One SQLite file is the whole store.
- **Toolchain-free install.** Must coexist with the pure-Go SQLite driver
  (ADR-0006) so `go install` stays C-toolchain-free; any native vector extension
  must be optional, not required.
- **Re-sync safe.** Vectors must survive idempotent re-sync — keyed by the stable
  message/chunk identity, not a row id that re-import churns (ADR-0014).
- **Multiple models coexist.** Switching embedding models later must not require
  wiping existing vectors.

## Considered Options

1. **Brute-force cosine over a filtered candidate set.** Store vectors as BLOBs in
   SQLite; for a query, embed it once, then cosine-scan the candidates the
   keyword/filters already narrowed to. Pure Go, no extension.
2. **`sqlite-vec` extension.** A native SQLite vector index for ANN search. Faster
   at large N, but a native extension (build/load story) on top of the driver.
3. **External vector DB (Qdrant, etc.).** Rejected — reintroduces a service and a
   network dependency, against ADR-0012/0018.

## Decision Outcome

**Chosen: option 1 as the default, option 2 as an optional accelerator.**

- **Default: brute-force cosine.** Vectors are stored in an `embeddings` table
  keyed by `(message_or_chunk_hash, model)` with the dimension and the raw vector
  bytes. Semantic search embeds the query once (ADR-0018) and cosine-scans the
  candidate set produced by the keyword/metadata filters — so the brute-force pass
  is over a narrowed set, not the whole corpus. At personal-mailbox scale this is
  fast enough and needs zero extra infrastructure.
- **Optional: `sqlite-vec`.** A future accelerator behind a build/config flag for
  operators with very large corpora. It changes only the store's vector
  read/write path; the search API, MCP tools (ADR-0017), and UI are unaffected.
- **Keying by stable hash, multi-model.** `PRIMARY KEY (hash, model)` and **no FK
  to messages** — vectors are keyed by content hash so re-sync (ADR-0014) never
  wipes them, and multiple embedding models can coexist for A/B or migration.
- **Computed in batches, on demand.** `reduit embed` computes missing vectors in
  batches via the LLM client (ADR-0018). Browsing and keyword search work with no
  embeddings and no LLM at all; semantic search degrades gracefully to
  keyword-only when vectors/endpoint are absent (the fusion rule lives in
  ADR-0017).

### Consequences

**Positive**

- Zero added infrastructure; one SQLite file remains the entire store.
- Pure-Go default preserves toolchain-free `go install` (ADR-0006).
- Re-sync-safe, multi-model vector storage; swapping models is additive.

**Negative**

- Brute-force is O(candidates) per query; without good pre-filtering it would
  scale poorly — mitigated by always scanning a filtered set, and by the optional
  `sqlite-vec` path for large corpora.
- A second embedding model doubles vector storage for the overlapped messages.

**Operational**

- `reduit embed [--mailbox …] [--model …]` computes missing vectors; safe to
  re-run. Needs a reachable embedding endpoint (ADR-0018), local by default.
