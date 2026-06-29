# ADR-0018: LLM access and single-egress privacy posture

- **Status:** accepted
- **Date:** 2026-06-29
- **Deciders:** Joe Stump

## Context and Problem Statement

Reduit's intelligent features — embeddings (ADR-0015), attachment OCR/vision/audio
(ADR-0016), contact-fact extraction (ADR-0019), and any RAG composition — need an
LLM. Reduit holds the most sensitive data a person owns (their mail), so *where*
that data can go, and how narrow and auditable that boundary is, is itself an
architectural decision. `msgbrowse` settled this (its ADR-0008 client, ADR-0010
posture): exactly one configurable network egress, local by default, no
telemetry. Reduit adopts the same, with one addition: the confirmed requirement
for **two distinct model roles** (a text/embedding model and a multimodal model)
so heavy media handling can target a different endpoint than cheap text work.

## Decision Drivers

- **One auditable egress.** The set of places mail content can leave the box must
  be a single, reviewable line of config — not scattered HTTP calls.
- **Local by default.** Out of the box, point at a local proxy/model so nothing
  leaves the device; a hosted provider must be a deliberate edit.
- **No telemetry.** No analytics, no phone-home, ever.
- **Two model roles.** A lightweight text/embedding model and a separate
  multimodal model, independently configurable (endpoint, model name, key), so the
  operator can e.g. keep text local while sending nothing — or only media — to a
  hosted model, by choice.
- **Secrets via env.** API keys come from the environment, never baked into an
  image or a committed file.

## Considered Options

1. **One OpenAI-compatible client, local-default, with two configurable model
   roles.** A single `llm.Client` (`Embed`, `Chat`, `Vision`, `Transcribe`) is the
   sole egress; text and multimodal roles each have their own base URL / model /
   key, defaulting to a local LiteLLM proxy.
2. **Per-feature ad-hoc clients.** Each feature dials its own endpoint. Rejected —
   diffuses the egress boundary and makes the privacy story unauditable.
3. **Single model for everything.** Simpler config, but forces text and media
   through one endpoint; rejected given the confirmed dual-role requirement.

## Decision Outcome

**Chosen: option 1 — one client, single egress, two model roles, local default.**

- **Sole egress.** `internal/llm` is the only package that makes outbound network
  calls. Everything else (sync talks to Proton, which is a separate, necessary
  boundary owned by ADR-0001/0014/0020) routes model work through it. There is **no
  telemetry or analytics.**
- **OpenAI-compatible, local default.** The client speaks the OpenAI API shape and
  defaults to a local LiteLLM proxy (which can route to Ollama). Out of the box,
  embedding with `nomic-embed-text` and any chat run entirely on-device.
- **Two model roles, independently configured.**
  - **Text/embedding role** — used for `Embed` and text `Chat` (fact extraction,
    RAG). Default local.
  - **Multimodal role** — used for `Vision`/`Transcribe` (ADR-0016 tier-2 OCR,
    captions, audio). Independently configured base URL / model / key; opt-in
    features only. Pointing this at a hosted model is the heaviest, most sensitive
    egress (raw image/audio bytes) and is documented as such.
- **Keys via env.** `REDUIT_LLM_API_KEY` (and a separate key for the multimodal
  role if different), env or `_FILE` indirection only; never committed.
- **Privacy denylist.** A per-conversation / per-sender denylist names content
  that is **never** sent to any model, for any feature (embed, attachment media,
  facts). It is persisted in a `denylist` table — `(mailbox_id NULLABLE, kind,
  value, added_at)`, `kind ∈ {conversation, sender}`, a NULL `mailbox_id` applying
  to all mailboxes — and managed via `reduit denylist add|remove|list`. Its
  storage and management surface are **defined by SPEC-0001** (mailbox model, the
  owner of local config); the enforcing features (ADR-0015/0016/0019 and their
  specs) consult it before any model call. The local default plus this denylist
  keep the user in control of every byte that leaves.
- **Graceful absence.** With no reachable endpoint, embedding/extraction features
  fail cleanly; browsing and keyword search keep working (ADR-0015/0017).

### Consequences

**Positive**

- The data-leaves-the-box boundary is a single, auditable, default-local line of
  config.
- Text can stay fully local while media handling is independently chosen — the
  dual-role requirement is met without widening the default.
- No telemetry; nothing about the user's mail or usage phones home.

**Negative**

- Two model roles mean more configuration surface than one; sensible local
  defaults mitigate this.
- Routing either role to a hosted provider widens egress; the multimodal role
  especially (raw bytes). The default-local posture and denylist are the guardrails,
  but the operator can override them.

**Operational**

- Configure the text/embedding role and (optionally) the multimodal role
  separately; supply keys via env.
- Keep the default local route for a fully on-device deployment; any hosted route
  is a deliberate, documented change.
