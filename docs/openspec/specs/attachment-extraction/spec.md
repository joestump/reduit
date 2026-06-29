# SPEC-0009: Attachment Extraction & Indexing

## Overview

Much of a mailbox's signal lives in **attachments** — PDFs, office
documents, receipts and screenshots, voice notes. Reduit turns those
payloads into searchable, embeddable text so that hybrid search
(SPEC-0008) and the MCP tool surface (SPEC-0006) operate over the
*content* of attachments, not just their filenames. This is a
first-class capability, broader than `msgbrowse`'s display-only image
transcode (its ADR-0014): Reduit indexes attachment content, with
provenance back to the message that carried it.

Extraction is **tiered** (ADR-0016). **Tier 1 — text — is always-on
and fully local**: embedded text is pulled from text-bearing documents
(PDF, plain text, common office formats) by local Go libraries or a
local extractor, with **no model call**, stored in
`attachments.extracted_text`, chunked, embedded (SPEC-0008), and
FTS-indexed. **Tier 2 — media — is opt-in and routes to the multimodal
model role (ADR-0018)**: OCR of images, vision captions/descriptions,
and audio transcription are **off by default**; enabling them against a
*hosted* multimodal model is the single heaviest and most sensitive
egress Reduit has (raw image/audio bytes leaving the device) and MUST
be documented as such. The privacy denylist (ADR-0018) excludes a
conversation or sender from any tier-2 model call entirely.

Extraction is cached by **stable attachment identity** with a
`(source_message_hash, attachment_id)` provenance link, so re-sync
(SPEC-0002) and re-embed (SPEC-0008) reuse the cache and nothing is
re-extracted or re-sent unless the attachment or the relevant model
changed. The archive is hostile input: a crafted or corrupt attachment
MUST fail safe — logged and skipped — and MUST NEVER crash the
pipeline.

Governing: ADR-0016 (attachment extraction & indexing), ADR-0018 (LLM
access, two model roles, denylist, single egress), ADR-0006 (SQLite
store; `extracted_text`, hash-keyed derived data), SPEC-0008
(embeddings & hybrid search), SPEC-0006 (MCP tool surface, citations),
SPEC-0002 (sync & cache).

## Requirements

### Requirement: Tier-1 Text Extraction Is Always-On and Local

For every cached attachment whose type is text-bearing (PDF, plain
text, common office formats), the system SHALL extract embedded text
using local Go libraries or a local extractor, with **no model call and
no network egress**. The result SHALL be stored in
`attachments.extracted_text`, then chunked, embedded (SPEC-0008), and
FTS-indexed (ADR-0006). Tier-1 extraction SHALL NOT be gated behind any
opt-in flag.

#### Scenario: PDF text extracted locally with no model call

- **WHEN** a cached attachment is a text-bearing PDF
- **THEN** the system SHALL extract its embedded text locally, store it
  in `attachments.extracted_text`, and make no outbound model or
  network call to do so

#### Scenario: Extracted text is chunked, embedded, and FTS-indexed

- **WHEN** Tier-1 extraction produces `extracted_text` for an
  attachment
- **THEN** the system SHALL chunk that text and hand the chunks to the
  embedding pipeline (SPEC-0008) and the FTS5 index (ADR-0006) so the
  attachment's content is reachable by hybrid search

#### Scenario: Office and plain-text documents extracted locally

- **WHEN** a cached attachment is plain text or a common office format
- **THEN** the system SHALL extract its embedded text locally and store
  it in `attachments.extracted_text`, with no model call

#### Scenario: Non-text-bearing types are not Tier-1 extracted

- **WHEN** a cached attachment carries no extractable embedded text
  (e.g. a photo with no text layer)
- **THEN** Tier-1 SHALL leave `extracted_text` empty for that
  attachment and SHALL NOT invoke a model; any text from it is a
  Tier-2 concern (OCR/vision), subject to opt-in

### Requirement: Tier-2 Media Extraction Is Opt-In via the Multimodal Role

OCR of image attachments, vision captions/descriptions, and audio
transcription of voice notes SHALL be **off by default** and each
SHALL be independently enabled by an explicit opt-in flag. When
enabled, these features SHALL route through the **multimodal model
role** (ADR-0018) — never the text/embedding role — and the resulting
media-derived text SHALL be stored and indexed exactly as Tier-1
text. Pointing the multimodal role at a *hosted* model is the heaviest,
most sensitive egress (raw image/audio bytes) and SHALL be documented
as such in SECURITY.md.

#### Scenario: OCR/vision/audio are off by default

- **WHEN** Reduit runs with no Tier-2 flags set
- **THEN** the system SHALL NOT perform OCR, vision captioning, or
  audio transcription, and SHALL make no multimodal model call for any
  attachment

#### Scenario: Enabled Tier-2 feature uses the multimodal role

- **WHEN** an operator enables OCR, vision, or audio and a qualifying
  attachment is processed
- **THEN** the system SHALL call the **multimodal model role**
  (ADR-0018) for that feature, SHALL NOT use the text/embedding role,
  and SHALL store the returned text as media-derived `extracted_text`
  for chunking, embedding, and FTS indexing

#### Scenario: Hosted multimodal egress is documented

- **WHEN** the multimodal role is configured to a hosted endpoint and a
  Tier-2 feature is enabled
- **THEN** this constitutes raw image/audio bytes leaving the device
  and SHALL be documented in SECURITY.md as the heaviest, most
  sensitive egress; the local default posture (ADR-0018) SHALL remain
  the out-of-the-box behavior

#### Scenario: Each Tier-2 feature is independently toggled

- **WHEN** the operator enables OCR but leaves vision and audio off
- **THEN** the system SHALL perform OCR only and SHALL NOT invoke
  vision captioning or audio transcription

### Requirement: Denylist Excludes Attachments From All Model Calls

An attachment carried by a message whose conversation or sender is on
the privacy denylist (ADR-0018) SHALL NEVER be sent to any model, for
any Tier-2 feature, regardless of which opt-in flags are set. The
denylist check SHALL be enforced before any multimodal call is
prepared.

#### Scenario: Denylisted conversation's attachment is never sent

- **WHEN** OCR/vision/audio is enabled and an attachment belongs to a
  message on a denylisted conversation or sender
- **THEN** the system SHALL skip every Tier-2 model call for that
  attachment and SHALL NOT transmit its bytes to any model endpoint

#### Scenario: Denylist outranks an enabled feature flag

- **WHEN** a Tier-2 feature flag is on but the attachment's
  conversation/sender is denylisted
- **THEN** the denylist SHALL take precedence and the attachment SHALL
  be treated as if the feature were disabled for it

#### Scenario: Tier-1 still runs for denylisted attachments

- **WHEN** an attachment on a denylisted conversation is text-bearing
- **THEN** local Tier-1 extraction MAY still run (it makes no model
  call); only model-bound Tier-2 features are suppressed by the
  denylist

### Requirement: Caching and Provenance by Stable Attachment Identity

Extracted text (Tier-1 and media-derived) SHALL be cached keyed by
**stable attachment identity**, carrying a `(source_message_hash,
attachment_id)` provenance link back to the message that supplied it.
Re-sync (SPEC-0002) and re-embed (SPEC-0008) SHALL reuse the cache.
Nothing SHALL be re-extracted or re-sent to a model unless the
attachment changed or the relevant model (extractor or multimodal
role) changed.

#### Scenario: Re-sync reuses cached extracted text

- **WHEN** a message is re-synced and its attachment's stable identity
  is unchanged
- **THEN** the system SHALL reuse the cached `extracted_text` and SHALL
  NOT re-extract it or re-invoke any model

#### Scenario: Provenance link is recorded

- **WHEN** extracted text is cached for an attachment
- **THEN** the record SHALL carry the `(source_message_hash,
  attachment_id)` link so consumers (SPEC-0006, SPEC-0008) can cite the
  exact source message and attachment

#### Scenario: Model change invalidates Tier-2 cache

- **WHEN** the multimodal model role is reconfigured and a previously
  processed attachment is re-examined
- **THEN** the system MAY re-run the affected Tier-2 feature for that
  attachment, keyed by the new model identity, rather than serving
  stale media-derived text

#### Scenario: Unchanged attachment is never re-sent to a model

- **WHEN** re-embed or re-extract runs over an attachment whose
  identity and relevant model are unchanged
- **THEN** the system SHALL NOT transmit the attachment to any model
  endpoint a second time

### Requirement: Heavy Conversions Shell Out to an External Converter

Format-specific or heavy conversions required before extraction — e.g.
HEIC→JPEG ahead of OCR or vision — SHALL be performed by shelling out
to an external converter discovered on `PATH`, rather than pulling
native image/media codecs into the binary. The converter SHALL be
invoked with fixed tool names and file-path arguments (no shell), and
its absence SHALL degrade gracefully rather than aborting the pipeline.

#### Scenario: HEIC is transcoded by an external converter

- **WHEN** a Tier-2 feature is enabled for a HEIC image attachment
- **THEN** the system SHALL transcode it to a model-ingestible format
  (e.g. JPEG) via an external converter on `PATH` before sending it to
  the multimodal role, keeping native codecs out of the binary

#### Scenario: Missing converter degrades gracefully

- **WHEN** no suitable external converter is present on `PATH` and a
  conversion is required
- **THEN** the system SHALL log the gap once and skip that attachment's
  Tier-2 step, and SHALL NOT crash or abort extraction of other
  attachments

### Requirement: Malformed Attachments Fail Safe

The attachment archive is hostile input. A crafted, corrupt, or
unparseable attachment SHALL fail safe: the error SHALL be logged, the
attachment SHALL be skipped, and processing of other attachments and
messages SHALL continue. A malformed file SHALL NEVER crash, hang
indefinitely, or otherwise take down the extraction pipeline.

#### Scenario: Corrupt document is logged and skipped

- **WHEN** Tier-1 extraction encounters a corrupt or malformed document
- **THEN** the system SHALL log the failure with provenance, leave that
  attachment's `extracted_text` empty, and continue with the next
  attachment

#### Scenario: A bad attachment does not crash the pipeline

- **WHEN** any single attachment triggers a parser panic, decode
  failure, or runaway resource use
- **THEN** the failure SHALL be contained to that attachment, the
  pipeline SHALL recover, and the overall extraction run SHALL complete

### Requirement: Extracted Text Participates in Search and MCP

Attachment-derived text SHALL participate in hybrid search (SPEC-0008)
and SHALL be retrievable through the MCP tool surface (SPEC-0006): an
agent SHALL be able to list a message's attachments (`list_attachments`)
and fetch an attachment's extracted text, with citations back to the
`(source_message_hash, attachment_id)` provenance.

#### Scenario: Attachment text is searchable

- **WHEN** a hybrid search matches content that originates from an
  attachment's `extracted_text`
- **THEN** the result SHALL surface that attachment hit alongside
  body/transcript hits, carrying its source provenance

#### Scenario: MCP exposes attachment listing and text with citations

- **WHEN** an agent calls `list_attachments` for a message and then
  fetches an attachment's extracted text
- **THEN** the server SHALL return the attachment list and the cached
  extracted text, each carrying the `(source_message_hash,
  attachment_id)` citation (SPEC-0006)

### Requirement: Per-Feature Opt-In and Multimodal Role Config

The configuration surface SHALL expose independent opt-in flags for OCR,
vision, and audio (Tier-2), and SHALL expose the **multimodal model
role** (endpoint, model name, key) independently of the text/embedding
role (ADR-0018). Keys SHALL come from the environment. Tier-1 text
extraction SHALL require no configuration to run.

#### Scenario: Tier-2 flags are explicit and independent

- **WHEN** the operator inspects the config surface
- **THEN** there SHALL be separate, default-off flags for OCR, vision,
  and audio, each independently settable

#### Scenario: Multimodal role configured separately from text role

- **WHEN** the operator configures Tier-2 features against a different
  endpoint than the text/embedding role
- **THEN** the multimodal role's base URL, model name, and key SHALL be
  configurable independently (ADR-0018), with the key supplied via the
  environment, never committed

## Out of Scope

- **Serving or rendering attachments in the UI** — display, galleries,
  inline media, and transcode-for-display are owned by the local UI
  (SPEC-0005); this spec extracts and indexes text, it does not serve
  bytes to a browser.
- **Editing or generating attachments** — Reduit reads attachments to
  index them; it does not create, modify, or write back attachment
  files.
- **The embedding and search algorithms themselves** — chunking is
  invoked here, but vector indexing, hybrid ranking, and the search
  query path are owned by SPEC-0008.
- **The single-egress LLM client and denylist mechanism** — defined by
  ADR-0018 / the LLM-access spec; this spec consumes the multimodal
  role and honors the denylist, it does not define them.
