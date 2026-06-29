# ADR-0016: Attachment extraction and indexing for RAG

- **Status:** accepted
- **Date:** 2026-06-29
- **Deciders:** Joe Stump

## Context and Problem Statement

Email is not just message bodies — much of the signal lives in **attachments**:
PDFs, office documents, images (receipts, screenshots, photos), and voice notes.
For semantic search, RAG, and MCP (ADR-0017) to be useful over real mail, the
*content* of attachments must be extractable into searchable, embeddable text,
and exposed to agents with provenance back to the message that carried them.

This is a deliberate first-class capability, not an afterthought. It is broader
than `msgbrowse`'s ADR-0014 (which only transcodes images for display): Reduit
must turn attachment payloads into indexed text. It is also the heaviest and most
sensitive egress surface if a hosted model is ever used (image/audio bytes), so
the heavy paths must be **opt-in** and able to target a **different model** than
the cheap text embedder (per the confirmed refactor decisions and ADR-0018).

## Decision Drivers

- **Text extraction is the core win** and is cheap and local for the common
  document types; it should be on by default.
- **Media understanding is heavy and sensitive.** OCR, vision captioning, and
  audio transcription send raw bytes to a model — a much larger egress than text.
  These must be opt-in and separately configurable.
- **Two model roles.** A lightweight text/embedding model and a separate
  **multimodal** model (vision/OCR/audio) so media handling can point at a
  different endpoint (e.g. local text embeddings + a hosted multimodal model, or
  vice-versa).
- **Provenance.** Every extracted chunk must trace back to its attachment and
  message (ADR-0017 citations).
- **Re-sync safe and cached.** Extraction is keyed by stable attachment identity
  and cached so re-sync (ADR-0014) and re-embed (ADR-0015) don't redo expensive
  work.

## Considered Options

1. **Index attachment filenames/metadata only.** Cheapest; misses the actual
   content. Rejected as insufficient.
2. **Tiered extraction: text always-on, media opt-in.** Extract text from
   documents by default; OCR/vision/audio behind explicit opt-in flags and the
   multimodal model role.
3. **Send every attachment to a multimodal model.** Richest, but inverts the
   privacy default and is expensive; rejected as a default.

## Decision Outcome

**Chosen: option 2 — tiered extraction.**

- **Tier 1 — text, always on, local.** Extract embedded text from text-bearing
  documents (PDF, plain text, and common office formats) using Go libraries / a
  local extractor. No model call; nothing leaves the machine. Extracted text is
  chunked and fed to embeddings (ADR-0015) and FTS (ADR-0006).
- **Tier 2 — media, opt-in, multimodal model.** OCR of image attachments, vision
  captions/descriptions, and audio transcription of voice notes are **off by
  default**. When enabled, they call the **multimodal model role** (ADR-0018),
  which MAY be a different endpoint than the text/embedding model. Enabling these
  against a *hosted* multimodal model is the one place raw image/audio bytes leave
  the device; SECURITY.md documents this explicitly.
- **Per-conversation / per-sender denylist.** A conversation or sender on the
  privacy denylist (ADR-0018) has its attachments excluded from any model call,
  for any tier-2 feature.
- **Caching & provenance.** Extracted text and media-derived text are cached in
  the store keyed by stable attachment identity, with a `(source_message_hash,
  attachment_id)` provenance link. Re-sync and re-embed reuse the cache; nothing
  is re-extracted or re-sent unless the attachment changed or the relevant model
  changed.
- **External converters where needed.** Heavy or format-specific conversions
  (e.g. HEIC→JPEG before OCR/vision, à la `msgbrowse` ADR-0014) shell out to an
  external converter rather than pulling native image codecs into the binary.
- **MCP exposure.** Attachment-derived text participates in hybrid search and is
  retrievable through dedicated MCP tools (`list_attachments`, fetch attachment
  text) with citations (ADR-0017).

### Consequences

**Positive**

- Real attachment content becomes searchable and RAG-able, a major step over
  body-only indexing.
- The expensive/sensitive media paths are opt-in and isolated to a separately
  configured model — privacy default stays local and cheap.
- Caching keeps re-sync/re-embed inexpensive.

**Negative**

- Tier-1 extraction adds document-parsing dependencies and the usual parser
  robustness/security concerns (malformed files must fail safe, never fatal).
- Tier-2, if pointed at a hosted multimodal model, is a heavy and sensitive
  egress; the default-off posture and denylist are the mitigations.

**Operational**

- Config exposes a text/embedding model and a multimodal model independently
  (ADR-0018), plus per-feature opt-in flags for OCR/vision/audio.
- `reduit embed` (or a dedicated extract step) populates and reuses the extraction
  cache; safe to re-run.
</content>
