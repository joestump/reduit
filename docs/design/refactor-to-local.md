# Refactor: from multi-user OIDC relay to single-user local Proton RAG

**Status:** in progress · **Started:** 2026-06-29 · **Owner:** Joe Stump

## Why

The original Reduit is a single shared, network-exposed, multi-tenant daemon
that holds every family member's Proton refresh token and mailbox passphrase at
rest under one service master key, gated by an external OIDC IdP. That is exactly
the *central party you must trust with the keys to your mail* that Proton exists
to eliminate: compromise the one host and you compromise everyone's Proton.

Reduit pivots to be **"msgbrowse for Proton Mail"** — a per-person, local-only Go
CLI that authenticates to Proton, incrementally **caches** mail into local SQLite
(the Proton API is rate-limited, so a local cache is mandatory for offline RAG),
embeds messages **and attachments** locally, and serves that over a **stdio MCP**
(primary), a local send path, and an optional loopback browse UI. No relay
(Proton Bridge already serves IMAP/SMTP), no OIDC, no shared daemon, no
master-key vault. Secrets live in the OS keychain.

The convergence target is the sibling project `msgbrowse` (`~/src/msgbrowse`);
its ADRs and `SECURITY.md` are the reference posture.

## Confirmed decisions (2026-06-29)

1. **Local cache may be unencrypted at the app layer.** Rely on OS full-disk
   encryption; document it. No SQLCipher work. *(Mitigating defenses exist on the
   target machine; deferred.)*
2. **Sending is required.** Reduit retains an outbound path (CLI `send` + MCP
   `send` tool) via `go-proton-api`. Reduit is read **and** write against Proton;
   only the local cache is derived.
3. **Attachments: text extraction always-on; OCR / vision / audio opt-in.** Two
   model roles in config — a text/embedding model and a separate **multimodal**
   model — so media handling can target a different endpoint than the embedder.
4. **Multi-mailbox from v1.** Schema and CLI/UI handle N Proton mailboxes from the
   first release (operator already runs 2 accounts).
5. **Local embedding default.** LiteLLM → Ollama (`nomic-embed-text`); out of the
   box nothing leaves the machine.
6. **Sender/contact facts: in.** First-class ADR + spec (msgbrowse ADR-0011 / its
   `contact-facts` spec analog).

## Target architecture

```
cmd/reduit            thin main()
└── internal/cli      Cobra + Viper  (defaults < file < REDUIT_* env < flags)
    ├── proton        go-proton-api: SRP/2FA/passphrase unlock, OpenPGP decrypt, event stream, send
    ├── keychain      OS keychain secret store (refresh token + mailbox passphrase, per mailbox)
    ├── sync          incremental pull from Proton's event stream → local cache (rate-limit aware)
    ├── store         SQLite: mailboxes, messages, attachments, FTS5, embeddings, contacts, facts
    ├── attach        attachment text extraction (PDF/office/OCR/vision/audio) for embeddings + MCP
    ├── llm           OpenAI-compatible client (sole egress) — embed / chat / vision / transcribe
    ├── embed         batch embedding orchestration
    ├── facts         incremental, cited sender/contact-fact extraction (LLM)
    ├── mcp           stdio MCP server (citation-faithful hybrid RAG over the cache; send tool)
    └── web           loopback HTMX browse/search UI (no auth)
```

The one place Reduit is *harder* than msgbrowse: the source is the **live,
rate-limited, encrypted** Proton API, not a static decrypted export. The
event-stream / cursor logic in the original SPEC-0002 is the most valuable thing
to carry forward — repointed from "materialize IMAP state" to "materialize a
local RAG cache."

## ADR disposition

| ADR | Disposition | Successor / note |
| --- | --- | --- |
| 0001 go-proton-api | Keep · reframe | Now feeds sync/cache + decrypt + send, not a relay |
| 0002 multi-tenant | **Superseded** | → ADR-0012 |
| 0003 master-key envelope | **Superseded** | → ADR-0013 |
| 0004 OIDC auth | **Superseded** | → ADR-0012 (no control plane) |
| 0005 frontend stack | Keep · reframe | Same stack; UI is browse/search, secondary to MCP |
| 0006 SQLite store | **Rewrite** | New cache schema; drop secret columns; add FTS5 + vectors |
| 0007 emersion IMAP/SMTP | **Superseded** | → ADR-0012 (no relay) |
| 0008 embedded MCP (HTTP+SSE+OIDC) | **Superseded** | → ADR-0017 |
| 0009 TLS disk hot-reload | **Superseded** | → ADR-0012 (no network TLS listeners) |
| 0010 multi-account per user | **Superseded** | → ADR-0012 (multi-mailbox kept; OIDC users layer dropped) |
| 0011 HTTP proxy mode | **Superseded** | → ADR-0012 (loopback-only) |

### New ADRs

| ADR | Title | Mirrors |
| --- | --- | --- |
| 0012 | Single-user, local-first, per-person binary (multi-mailbox) | msgbrowse posture |
| 0013 | Secrets in the OS keychain | — |
| 0014 | Local sync-and-cache from the Proton event stream | *(net-new)* |
| 0015 | Embeddings & vector backend (brute-force default, sqlite-vec optional) | msgbrowse ADR-0002 |
| 0016 | Attachment extraction & indexing for RAG | msgbrowse ADR-0014 (broadened) |
| 0017 | stdio MCP server + citation-faithful hybrid RAG | msgbrowse ADR-0004 |
| 0018 | LLM access & single-egress posture (dual model roles) | msgbrowse ADR-0008/0010 |
| 0019 | Sender/contact facts extraction | msgbrowse ADR-0011 |
| 0020 | Outbound send via go-proton-api | *(net-new)* |

## Spec (OpenSpec) disposition

| Spec | Disposition | Becomes |
| --- | --- | --- |
| 0001 Account Model | Rewrite | Local **Mailbox model** — N Proton mailboxes, keychain secret refs, cache namespace |
| 0002 Sync Worker | Rewrite | **Sync & Local Cache** — event-stream → SQLite, idempotent, rate-limit aware |
| 0003 IMAP Server | **Retire** | — |
| 0004 SMTP Server | **Retire** | Send moves to MCP/CLI (new Outbound Send spec) |
| 0005 Admin UI Flows | Rewrite | **Local Browse & Search UI** — loopback, no auth |
| 0006 MCP Tool Surface | Rewrite | **stdio MCP RAG surface** (primary spec) |

### New specs

- Onboarding & Proton Auth (SRP / 2FA / mailbox passphrase → keychain)
- Embeddings & Semantic/Hybrid Search
- Attachment Extraction & Indexing
- Outbound Send
- Sender/Contact Facts

## Top-level doc impact

- **CLAUDE.md** — Stack: drop go-imap/go-smtp, OIDC libs, scs; add embeddings/vector
  lib, keychain lib, OpenAI-compatible client. Out-of-scope: add "IMAP/SMTP relay —
  use Proton Bridge." Deployment: drop Pocket ID / Caddy / cert-mount / ops01 DNS.
- **README.md** — relay → local Proton search/RAG; msgbrowse-style quickstart.
- **ARCHITECTURE.md / SECURITY.md** — author both (mirror msgbrowse).
- **Makefile / Dockerfile / deploy/** — remove multi-listener/TLS/OIDC; the
  #59–#64 security-hardening run (master-key rotation, session invalidation, TLS
  builder, ownership triggers) becomes moot and is removed. Docker optional.

## Execution order

1. **Cornerstone ADRs** (0012, 0013) + retire 0002/0003/0004/0007/0009/0010/0011. ← *in progress*
2. **Capability ADRs** (0014–0020) + retire 0008 + rewrite 0006 + reframe 0001/0005.
3. **Specs**: Mailbox → Onboarding/Auth → Sync/Cache → Attachments → Embeddings/Search
   → Outbound Send → MCP surface → Web UI → Contact Facts. Retire 0003/0004 specs.
4. **Top-level docs** (CLAUDE.md, README, ARCHITECTURE, SECURITY, Makefile/deploy).
5. **Code refactor** — separate pass, after the doc layer settles.
