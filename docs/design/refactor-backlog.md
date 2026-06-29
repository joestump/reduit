# Refactor backlog — local-first implementation

**Generated:** 2026-06-29 · **Tracker:** gitea `joestump/reduit` · **Status:** ready to import

> **Why this is a doc, not Gitea issues.** The Gitea MCP server has no token in
> this environment (`get_me` / `pull_request_write` both return *"token is
> required"*), so issues/epics/projects can't be created from here. This file is
> the `/sdd:plan` fallback: the full breakdown, ready to become issues. Once the
> Gitea MCP token is configured, re-run `/sdd:plan` (or ask me) and these become
> real issues + projects with the labels, branches, and dependencies below.

Covers the **code refactor** implementing the 9 merged specs plus the deferred
follow-ups. Every `### Requirement:` across the specs maps to **exactly one**
story (traceability verified). Branch slugs follow CLAUDE.md (`feature/`,
`epic/`); issue numbers are assigned at creation.

## Hotspot / ordering note

Standard git-history hotspot analysis is **not predictive here** — the refactor
*replaces* the old relay/OIDC implementation wholesale, so the historically
churned files (`internal/server`, `cmd/.../serve.go`, `internal/tlsloader`,
`internal/auth`) are being deleted, not contended. The real serialization
constraint is **foundation → feature**, and the new shared hotspot is the
**store schema + goose migrations** (`internal/store`): every story that adds a
table or column must serialize behind, or coordinate with, the migration story
(F2). Treat `internal/store/migrations` as the one file to never parallelize.

---

## EPIC 0 — Foundation & Teardown  `epic/foundation-teardown`

Merge before any feature epic. These are the shared packages/types 2+ specs need.

| Story | Scope | Labels | Depends |
|---|---|---|---|
| **F0 Teardown** `feature/teardown-relay-oidc-tls` | Remove the relay (`go-imap`/`go-smtp`), OIDC/SCS, the three TLS listeners + `tlsloader`, the master-key envelope, multi-tenant store/migrations, and the #59–#64 hardening (master-key rotation, session invalidation, ownership triggers). Drop the now-dead deps from `go.mod`. | `foundation` | — |
| **F1 CI** `feature/ci-static-analysis-race-fmt` | Static analysis, test runner with **race detection**, formatting enforcement, wired into CI on every PR. | `foundation` `ci` | — |
| **F2 Store & migrations** `feature/store-schema-migrations` | `internal/store`: goose migrations + sqlx for the full new schema — `mailboxes, messages, attachments, links, contacts, contact_identifiers, embeddings, contact_facts, fact_state, sync_state, denylist, messages_fts(FTS5)`. Pure-Go `modernc` driver, WAL. *(Gov: ADR-0006; SPEC-0001 "Per-Mailbox Cache Scoping"; SPEC-0002 schema.)* | `foundation` | F0 |
| **F3 Keychain store** `feature/keychain-secret-store` | `internal/keychain`: cross-platform OS-keychain wrapper; keys `mailbox/<id>/{refresh_token,mailbox_passphrase}`. *(Gov: ADR-0013.)* | `foundation` | — |
| **F4 Config & CLI skeleton** `feature/cli-config-skeleton` | Cobra + Viper root `reduit`, config model (`defaults < file < REDUIT_* env < flags`), `data_dir`, slog. *(Gov: ADR-0012.)* | `foundation` | — |
| **F5 Proton client wrapper** `feature/proton-client-wrapper` | `internal/proton`: wrap `go-proton-api` — auth/SRP/2FA, OpenPGP decrypt, event stream, send surface. *(Gov: ADR-0001.)* | `foundation` | F4 |
| **F6 LLM client (two roles)** `feature/llm-client-two-roles` | `internal/llm`: one OpenAI-compatible client (sole egress), text/embedding + multimodal roles, local default. *(Gov: ADR-0018.)* | `foundation` | F4 |

---

## EPIC 1 — Mailbox model & onboarding  `epic/mailbox-and-onboarding`  (SPEC-0001, SPEC-0007)

| Story | Requirements covered | Depends |
|---|---|---|
| **S1.1 Mailbox entity & lifecycle** `feature/mailbox-entity-lifecycle` | SPEC-0001: Mailbox Identity · Multi-Mailbox · No Identity or Auth Layer · Per-Mailbox Cache Scoping · Mailbox Lifecycle and State | F2 |
| **S1.2 Secret references & keychain** `feature/mailbox-secret-references` | SPEC-0001: Secret References, Not Secrets · SPEC-0007: Secret Write, Read, and Delete · No Secret Leakage · Keyring Availability | F3, S1.1 |
| **S1.3 `reduit auth` flow** `feature/proton-auth-flow` | SPEC-0007: Add-Mailbox Flow · SRP and 2FA Handling · Mailbox Passphrase Capture and Key Unlock · Re-Auth Flow · Multi-Mailbox Add | F5, S1.2 |
| **S1.4 Privacy denylist** `feature/privacy-denylist-cli` | SPEC-0001: Privacy Denylist (`denylist` table + `reduit denylist add\|remove\|list`) | F2 |

---

## EPIC 2 — Sync & local cache  `epic/sync-and-cache`  (SPEC-0002)

| Story | Requirements covered | Depends |
|---|---|---|
| **S2.1 Sync engine** `feature/sync-engine` | Per-Mailbox Sync Isolation · Bootstrap Then Tail · Idempotent Stable-Hash Keying · Crash-Safety And Resumability · Rate-Limit Respect · Triggered Execution · Bookkeeping And Observability | F2, F4, F5 |
| **S2.2 Materialization & decrypt** `feature/sync-materialization` | Decrypt In The Pipeline · Contact Materialization · Link Extraction · FTS Upkeep · Offline Behavior | S2.1, S1.2 |

---

## EPIC 3 — Embeddings & search  `epic/embeddings-and-search`  (SPEC-0008)

| Story | Requirements covered | Depends |
|---|---|---|
| **S3.1 Keyword/FTS search** `feature/keyword-fts-search` | Keyword Search Is Always Available · Safe Snippet Highlighting | F2 |
| **S3.2 Embedding generation & storage** `feature/embedding-generation` | Incremental Embedding Generation · Vector Storage Keyed by Hash and Model · Search Honors the Single-Egress Boundary | F6, F2 |
| **S3.3 Semantic + hybrid RRF** `feature/hybrid-rrf-search` | Semantic Search Over a Filtered Candidate Set · Hybrid Reciprocal-Rank Fusion · Graceful Degradation to Keyword-Only · Attachment Text Participates in Search | S3.1, S3.2 |

---

## EPIC 4 — Attachment extraction  `epic/attachment-extraction`  (SPEC-0009)

| Story | Requirements covered | Depends |
|---|---|---|
| **S4.1 Tier-1 text extraction** `feature/attachment-text-extraction` | Tier-1 Text Extraction Is Always-On and Local · Caching and Provenance by Stable Attachment Identity · Heavy Conversions Shell Out to an External Converter · Malformed Attachments Fail Safe | F2, S2.2 |
| **S4.2 Tier-2 opt-in media** `feature/attachment-media-extraction` | Tier-2 Media Extraction Is Opt-In via the Multimodal Role · Denylist Excludes Attachments From All Model Calls · Per-Feature Opt-In and Multimodal Role Config · Extracted Text Participates in Search and MCP | S4.1, F6, S1.4 |

---

## EPIC 5 — Sender / contact facts  `epic/contact-facts`  (SPEC-0011)

| Story | Requirements covered | Depends |
|---|---|---|
| **S5.1 Fact extraction engine** `feature/fact-extraction-engine` | Incremental, Cited Fact Extraction · Citation by Stable Message Hash · Per-Contact Deduplication · Incremental Cursor in fact_state · Privacy — Single Egress and Denylist · Graceful Absence of an LLM Endpoint | F6, S2.2, S1.4 |
| **S5.2 Contact identity & surfacing** `feature/contact-identity-merge` | Facts Attach to a Contact, Not an Address · Manual Identity Reconciliation via `reduit contacts merge` · Surfacing via MCP and the UI Contact View | S5.1 |

---

## EPIC 6 — Outbound send  `epic/outbound-send`  (SPEC-0010)

| Story | Requirements covered | Depends |
|---|---|---|
| **S6.1 Send core** `feature/send-core` | Compose, Encrypt, and Submit via go-proton-api · Explicit From-Mailbox · One Routine, Two Surfaces · Recipient Encryption Modes · Attachments · No MTA Semantics · Local Reflection of Sent Mail | F5, S1.2, S2.1 |
| **S6.2 Send safety surfaces** `feature/send-safety-confirmation` | Agent-Safe MCP Send · Explicit Confirmation Before Submit | S6.1, S7.1 |

---

## EPIC 7 — MCP tool surface  `epic/mcp-tool-surface`  (SPEC-0006)

MCP is **stdio**, not HTTP → no security checklist; testability is first-class.

| Story | Requirements covered | Depends |
|---|---|---|
| **S7.1 stdio server & adapter** `feature/mcp-stdio-server` | Stdio Transport, No Auth · Thin Adapter Over the Store · In-Memory Round-Trip Testability | F2 |
| **S7.2 Retrieval tools** `feature/mcp-retrieval-tools` | Citation Contract on Every Retrieval Result · Hybrid `search_messages` · Read Tools Over the Cache · Multi-Mailbox Operation | S7.1, S3.3 |
| **S7.3 send tool** `feature/mcp-send-tool` | The `send` Tool Is the Only Mutating Tool | S7.1, S6.1 |

---

## EPIC 8 — Local browse & search UI  `epic/local-ui`  (SPEC-0005)

UI-touching → **companion test stories required** (template render + HTMX). The
server stories expose HTTP → **Security Checklist** required on each at creation.

| Story | Requirements covered | Depends |
|---|---|---|
| **S8.1 UI server & hardening** `feature/ui-server-hardening` | Loopback Default With Non-Loopback Warning · No Authentication · Strict Content-Security-Policy, Self-Only Assets · Untrusted Content Is Escaped | F2 |
| **S8.1-T Tests** `feature/ui-server-hardening-tests` | Template render + CSP/escaping tests. *Covers S8.1.* | S8.1 |
| **S8.2 Browse, search & media** `feature/ui-browse-search-media` | Browse Mailboxes, Conversations, and Messages · Keyword and Semantic Search Over the Shared Store · Attachment and Media Serving · Contact View With Cited Facts · Optional Live Updates via SSE | S8.1, S3.3, S5.2 |
| **S8.2-T Tests** `feature/ui-browse-search-media-tests` | Template render + HTMX integration + media path-traversal tests. *Covers S8.2.* | S8.2 |

---

## EPIC 9 — Docs & deploy follow-ups  `epic/docs-and-deploy`

| Story | Scope | Depends |
|---|---|---|
| **S9.1 Top-level docs** `feature/rewrite-readme-arch-security` | Rewrite README.md; author ARCHITECTURE.md + SECURITY.md (mirror `msgbrowse`; SECURITY headline = the decrypted local-cache asset + OS-FDE reliance). | — |
| **S9.2 Deploy & Make cleanup** `feature/deploy-make-cleanup` | Strip multi-listener/TLS/OIDC from Makefile/Dockerfile/`deploy/`; make Docker optional; primary distribution `go install`. (Ops side of F0.) | F0 |

---

## Dependency graph (implementation order)

```
Foundation (merge first):
  F0 teardown · F1 CI · F2 store+migrations · F3 keychain · F4 cli/config · F5 proton · F6 llm

Wave 1 (after foundation):
  S1.1 → S1.2 → S1.3        (mailbox → secrets → auth)
  S1.4 denylist             (parallel, needs F2)
  S2.1 sync engine          (needs F2,F4,F5) → S2.2 materialization (needs S1.2)
  S3.1 keyword search       (parallel, needs F2)
  S7.1 mcp server           (parallel, needs F2)
  S8.1 ui server (+S8.1-T)  (parallel, needs F2)

Wave 2:
  S3.2 embeddings → S3.3 hybrid     (needs F6)
  S4.1 attach text → S4.2 media     (needs S2.2, F6, S1.4)
  S5.1 facts → S5.2 contact identity(needs S2.2, F6, S1.4)
  S6.1 send core                    (needs F5,S1.2,S2.1)
  S7.2 retrieval tools              (needs S3.3)

Wave 3:
  S6.2 send safety        (needs S6.1, S7.1)
  S7.3 mcp send tool      (needs S7.1, S6.1)
  S8.2 browse/search/media (+S8.2-T)  (needs S3.3, S5.2)

Always serialize on: internal/store migrations (F2 hotspot).
```

## To turn this into Gitea issues
1. Configure the Gitea MCP server with a token (or expose one to the agent env).
2. Re-run `/sdd:plan <spec>` per epic — it will create the epic, stories,
   `foundation`/`ci`/`test` labels, per-epic project + milestone, branch +
   PR-convention sections, and native dependency links, using this mapping.
3. Run `/sdd:prime` at the start of each implementation session, then `/sdd:work`.
