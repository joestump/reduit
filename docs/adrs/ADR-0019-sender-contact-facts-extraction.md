# ADR-0019: Sender / contact facts extraction

- **Status:** accepted
- **Date:** 2026-06-29
- **Deciders:** Joe Stump

## Context and Problem Statement

A lot of the value in a mail archive is *who* you correspond with and *what is
true about them and your dealings* — addresses, order numbers, account
identifiers, recurring topics, relationships, commitments. Surfacing these as
durable, **cited** facts per correspondent makes search and RAG dramatically more
useful than raw message retrieval alone. `msgbrowse` does exactly this for chat
contacts (its ADR-0011 / `contact-facts` spec); Reduit adopts the same approach,
keyed on email correspondents.

## Decision Drivers

- **Cited, not hallucinated.** Every fact must point back to the specific message
  it was drawn from, so it can be verified and trusted.
- **Incremental.** Re-running extraction must only process new messages since the
  last run, not re-scan the whole corpus — and must be idempotent.
- **Deduped per contact.** The same fact restated across many emails should
  collapse to one entry.
- **Provenance survives re-sync.** Facts must key off stable message identity, so
  re-sync (ADR-0014) never orphans or duplicates them.
- **Privacy-respecting.** Extraction is an LLM feature and obeys the single-egress
  boundary and the per-thread denylist (ADR-0018).

## Considered Options

1. **Incremental, cited, deduped extraction keyed by stable hash.** A per-contact
   cursor (last processed message hash + model) drives an LLM pass that emits facts
   with a category and a `source_message_hash`; facts dedupe per contact via a
   content hash.
2. **One-shot whole-corpus summarization.** Re-summarize everything each run.
   Rejected — expensive, non-incremental, and weak on provenance.
3. **No facts; rely on raw retrieval.** Rejected — the user explicitly wants this
   capability.

## Decision Outcome

**Chosen: option 1 — incremental, cited, deduped, hash-keyed extraction.**

- **Unit: the contact.** Facts attach to a `contact` (a correspondent identity;
  the contacts/identifiers layer in ADR-0006), not to a raw email address, so a
  person with several addresses accrues one fact set. (Identity reconciliation
  follows the store's contact model; manual where ambiguous.)
- **Cited.** Each fact row carries `fact`, `category`, a `fact_hash` (for dedupe),
  the `source_message_hash`, and the model used. **No FK to messages** — provenance
  is by stable hash so re-sync doesn't break citations. `UNIQUE(contact_id,
  fact_hash)` dedupes restated facts.
- **Incremental cursor.** A per-contact `fact_state` records the last processed
  message hash + model; `reduit facts` processes only newer messages and is safe
  to re-run. Changing the model re-opens extraction without wiping prior facts.
- **LLM via the one egress.** Extraction uses the text/embedding model role
  (ADR-0018), obeys the per-conversation/sender **denylist**, and runs locally by
  default. With no endpoint, it fails cleanly and the rest of Reduit is unaffected.
- **Surfaced everywhere.** Facts are retrievable via an MCP tool with citations
  (ADR-0017) and shown in the contact-facts view of the TUI (ADR-0025); both
  read the same store method.

### Consequences

**Positive**

- Durable, verifiable, per-correspondent knowledge that makes RAG answers richer
  and lets agents cite "where did I get this."
- Incremental + deduped keeps cost bounded and output clean as mail grows.
- Hash-keyed provenance is re-sync-safe.

**Negative**

- Extraction quality depends on the model; cited provenance is the mitigation (a
  human/agent can always check the source message).
- It is an LLM cost and, if pointed at a hosted model, an egress of message text —
  governed by ADR-0018's default-local posture and denylist.

**Operational**

- `reduit facts [--mailbox …] [--contact …]` — incremental; safe to re-run.
- Excluded threads (denylist) never contribute facts.
