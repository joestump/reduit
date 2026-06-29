# SPEC-0008: Embeddings & Semantic/Hybrid Search

## Overview

Reduit's retrieval surface is shared verbatim by the stdio MCP server
(ADR-0017) and the loopback UI (ADR-0005): both call the same `store`
methods so keyword, semantic, and hybrid behavior cannot drift between
the two. The bedrock is **keyword search over FTS5** — a bm25-ranked,
filterable full-text index that is *always* available, with no LLM, no
embeddings, and no network. Everything richer layers on top of that
floor and degrades back to it when the richer pieces are absent.

The richer layer is **vector semantic search**. `reduit embed` computes
per-message and per-chunk embeddings via the text/embedding model role
(ADR-0018), incrementally and in batches, only for content missing a
vector for the chosen model. Vectors live in the `embeddings` table
keyed by `(hash, model)` with the dimension and raw bytes, with **no FK
to messages** (ADR-0015) so idempotent re-sync (ADR-0014) never wipes
them and multiple models coexist. A query is embedded once, then scored
by **brute-force cosine over a candidate set already narrowed by the
keyword/metadata filters** — never the whole corpus; an optional
`sqlite-vec` accelerator changes only the store's vector path, not the
API. `search_messages` then **fuses** the keyword and vector result
lists with reciprocal-rank fusion (`score = Σ 1/(60 + rank)`) because
bm25 and cosine scores are not comparable.

Every byte that could leave the box obeys the single-egress boundary
(ADR-0018) and the per-conversation/sender denylist defined by SPEC-0001
(the `denylist` table); this spec only enforces it. The local default
sends nothing off-device. Extracted attachment text (SPEC-0009) participates in both
the FTS index and the embedding set, carrying provenance back to its
source attachment, so a hit on a PDF's body text cites the PDF.

Governing: ADR-0015 (embeddings & vector backend), ADR-0017 (stdio MCP
& hybrid RAG), ADR-0018 (single LLM egress & denylist), ADR-0006
(SQLite store), SPEC-0009 (attachment extraction — this spec consumes
its output), SPEC-0001 (mailbox model — `mailbox_id` scoping).

## Requirements

### Requirement: Keyword Search Is Always Available

The system SHALL provide bm25-ranked full-text keyword search over the
`messages_fts` FTS5 external-content index without requiring any LLM
endpoint, embedding, or network access. Keyword search SHALL be
filterable by mailbox, sender, date range, has-attachment, and
has-link. It SHALL be the floor every other search mode degrades to.

#### Scenario: Keyword search runs with no LLM configured

- **WHEN** a search is issued and no embedding endpoint is reachable and
  no vectors exist
- **THEN** the system SHALL execute the FTS5 keyword query and return
  bm25-ranked results without error, contacting no network endpoint

#### Scenario: Results are bm25-ranked

- **WHEN** a keyword query matches multiple messages
- **THEN** the system SHALL order results by the FTS5 `bm25()` ranking
  so the most relevant matches appear first

#### Scenario: Metadata filters narrow the keyword set

- **WHEN** a caller supplies any of `mailbox`, `sender`, a date range,
  `has_attachment`, or `has_link`
- **THEN** the system SHALL restrict matches to rows satisfying those
  filters before ranking, and SHALL combine multiple filters
  conjunctively

### Requirement: Incremental Embedding Generation

`reduit embed [--mailbox …] [--model …]` SHALL compute vectors only for
messages and chunks that lack a vector for the selected model,
processing them in batches via the text/embedding model role (ADR-0018).
It SHALL be safe to re-run: a second invocation over unchanged content
SHALL compute nothing. It SHALL require a reachable embedding endpoint
(local by default) and SHALL fail cleanly, without partial corruption,
when none is reachable.

#### Scenario: Only missing vectors are computed

- **WHEN** `reduit embed` runs over a corpus where some messages already
  have a vector for the target model
- **THEN** the system SHALL embed only the messages and chunks with no
  `(hash, model)` row for that model and SHALL skip those already
  embedded

#### Scenario: Re-running embed is a no-op

- **WHEN** `reduit embed` is run a second time with no new or changed
  content for the same model
- **THEN** the system SHALL compute no embeddings and SHALL leave the
  `embeddings` table unchanged

#### Scenario: Embedding is batched

- **WHEN** many messages or chunks require embedding
- **THEN** the system SHALL submit them to the model in batches rather
  than one request per item

#### Scenario: Embedding fails cleanly with no endpoint

- **WHEN** `reduit embed` is invoked and no embedding endpoint is
  reachable
- **THEN** the system SHALL report a clear error, SHALL NOT write
  partial or placeholder vectors, and SHALL leave existing vectors and
  keyword search fully functional

#### Scenario: Scope flags restrict the run

- **WHEN** `--mailbox` or `--model` is supplied
- **THEN** the system SHALL embed only content for the named mailbox
  and/or compute vectors for the named model, leaving other mailboxes
  and other models' vectors untouched

### Requirement: Vector Storage Keyed by Hash and Model

Vectors SHALL be stored in the `embeddings` table with primary key
`(hash, model)`, carrying the vector `dim` and the raw vector bytes.
The table SHALL have **no foreign key to `messages`** so re-sync never
orphans or wipes vectors, and multiple embedding models SHALL coexist
for the same content hash.

#### Scenario: A vector is stored by content hash and model

- **WHEN** the embedder produces a vector for a message or chunk
- **THEN** the system SHALL upsert a row keyed by the content `hash` and
  the `model` name, storing the vector `dim` and the raw bytes

#### Scenario: Re-sync does not wipe vectors

- **WHEN** an idempotent re-sync (ADR-0014) re-imports messages whose
  content hash is unchanged
- **THEN** the existing `embeddings` rows for those hashes SHALL remain
  intact, because no FK ties them to the churned `messages` rows

#### Scenario: Two models coexist for one message

- **WHEN** the same content hash is embedded under two different model
  names
- **THEN** the system SHALL retain both rows, one per `(hash, model)`,
  without either overwriting the other

### Requirement: Semantic Search Over a Filtered Candidate Set

Semantic search SHALL embed the query exactly once via the
text/embedding role and SHALL rank by brute-force cosine similarity
over **only the candidate set already narrowed by the keyword/metadata
filters**, not the whole corpus. An optional `sqlite-vec` accelerator
MAY replace the brute-force scan; enabling it SHALL change only the
store's vector read/write path and SHALL NOT change the search API or
results contract.

#### Scenario: The query is embedded once

- **WHEN** a semantic search runs
- **THEN** the system SHALL make exactly one embedding call for the
  query string and SHALL reuse that vector for the entire cosine pass

#### Scenario: Cosine scans the narrowed set, not the corpus

- **WHEN** keyword/metadata filters narrow the candidates to a subset of
  the corpus
- **THEN** the brute-force cosine pass SHALL score only that subset's
  vectors, not every vector in `embeddings`

#### Scenario: sqlite-vec changes only the store path

- **WHEN** the optional `sqlite-vec` accelerator is enabled
- **THEN** the system SHALL produce the same shape of ranked results
  through the same `store` method, with only the internal vector scan
  swapped, and MCP/UI callers SHALL require no change

### Requirement: Hybrid Reciprocal-Rank Fusion

`search_messages` SHALL fuse the keyword result list and the vector
result list using reciprocal-rank fusion, scoring each result by
`Σ 1/(60 + rank)` across the lists it appears in, because bm25 and
cosine scores are not directly comparable. The fused order SHALL be
returned to MCP (ADR-0017) and UI callers identically. This spec
(SPEC-0008) is the normative owner of the RRF ranking definition
(the `Σ 1/(60 + rank)` formula and the constant `60`); SPEC-0006's
`search_messages` tool references this requirement rather than
redefining it, so the ranking is defined in exactly one place.

#### Scenario: Keyword and vector lists are fused by RRF

- **WHEN** both a keyword list and a vector list are available for a
  query
- **THEN** the system SHALL compute each result's fused score as the sum
  of `1/(60 + rank)` over its rank in each list and SHALL order results
  by that fused score

#### Scenario: Native scores are not mixed directly

- **WHEN** fusing the two lists
- **THEN** the system SHALL fuse on rank position, and SHALL NOT add,
  average, or otherwise combine raw bm25 and cosine scores directly

### Requirement: Graceful Degradation to Keyword-Only

When embeddings or the embedding endpoint are unavailable, hybrid search
SHALL degrade to keyword-only results rather than failing. The keyword
half SHALL always run; the absence of the vector half SHALL never error
the overall search.

#### Scenario: No endpoint degrades to keyword-only

- **WHEN** `search_messages` runs and the embedding endpoint is
  unreachable
- **THEN** the system SHALL return bm25-ranked keyword results and SHALL
  NOT fail the request

#### Scenario: No vectors degrade to keyword-only

- **WHEN** a query's candidate messages have no vectors for any model
- **THEN** the system SHALL return keyword-only results rather than an
  empty or errored response

### Requirement: Safe Snippet Highlighting

Result snippets SHALL be produced from untrusted message content. The
system SHALL escape snippet text before applying highlight markers, so
that message content can never inject markup into the highlighted
output.

#### Scenario: Snippet content is escaped before highlighting

- **WHEN** a snippet is built around a matched term in a message body
- **THEN** the system SHALL escape the surrounding message text first
  and SHALL apply highlight markers only around the matched span, so
  active markup in the message body cannot survive into the snippet

### Requirement: Attachment Text Participates in Search

Extracted attachment text produced by SPEC-0009 SHALL be indexed in
FTS5 and embedded alongside message bodies, and SHALL carry provenance
back to its source attachment so a hit on attachment text cites that
attachment. This spec consumes the extracted text; it does not perform
the extraction.

#### Scenario: Attachment text is keyword-searchable

- **WHEN** a query matches text that came from an attachment's extracted
  content
- **THEN** the system SHALL return the result and SHALL identify the
  source attachment (and its parent message) as provenance

#### Scenario: Attachment text is embedded with provenance

- **WHEN** `reduit embed` runs over content that includes extracted
  attachment text
- **THEN** the system SHALL embed that text keyed by its content hash
  like a message body, and a semantic hit on it SHALL resolve to the
  originating attachment and message

### Requirement: Search Honors the Single-Egress Boundary

Query embedding and content embedding SHALL pass only through the single
LLM egress (ADR-0018) and SHALL respect the per-conversation/sender
denylist defined by SPEC-0001 (the `denylist` table): content named on
the denylist SHALL never be embedded or sent to any model. With the local default configured, search SHALL send
nothing off-device.

#### Scenario: Denylisted content is never embedded

- **WHEN** `reduit embed` encounters a message or attachment whose
  conversation or sender is on the denylist (SPEC-0001)
- **THEN** the system SHALL skip it, SHALL NOT send its content to any
  model, and SHALL NOT write a vector for it

#### Scenario: Local default sends nothing off-device

- **WHEN** the text/embedding role is configured to the local default
  (LiteLLM → Ollama, `nomic-embed-text`)
- **THEN** query and content embedding SHALL stay on-device and no mail
  content SHALL leave the machine

#### Scenario: Embedding routes only through the single egress

- **WHEN** any search or embed path needs a vector
- **THEN** it SHALL obtain that vector via `internal/llm` (the sole
  egress) and SHALL NOT open its own outbound connection

## Out of Scope

- External vector databases (Qdrant and the like) — rejected by
  ADR-0015; one SQLite file is the whole store. The only acceleration is
  the optional in-file `sqlite-vec` path.
- Cross-encoder or LLM-based reranking of fused results — deferred; RRF
  is the fusion mechanism for v1.
- Training, fine-tuning, or distilling embedding models — Reduit only
  *calls* an embedding model through the single egress.
- The attachment **extraction** pipeline itself — SPEC-0009 owns OCR /
  vision / text extraction; this spec only consumes the extracted text
  it produces.
- Embedding-model migration tooling beyond the additive multi-model
  storage that `(hash, model)` keying already permits.
