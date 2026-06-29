# Reduit

A sovereign, **single-user, local-first** tool for Proton Mail. A
per-person Go CLI that authenticates to Proton, incrementally **caches**
mail into a local SQLite store, embeds messages and attachments locally,
and serves semantic/hybrid **search + RAG over a stdio MCP** (primary), a
local send path, and an optional loopback browse UI. Nothing is
network-exposed; secrets live in the OS keychain. The model is
"msgbrowse for Proton Mail" (see `~/src/msgbrowse`).

Reduit is **not** an IMAP/SMTP relay — for a standard mail client, run
[Proton Bridge](https://proton.me/mail/bridge) alongside it.

## Status

Pre-alpha, **mid-refactor**. As of 2026-06-29 the project pivoted from a
multi-user OIDC relay to the single-user local-first design above; see
[docs/design/refactor-to-local.md](docs/design/refactor-to-local.md) and
ADR-0012. The ADRs and specs reflect the new design; the code is being
brought in line. No functional release yet.

## Stack

- **Language:** Go 1.25+
- **Proton client:** [`github.com/ProtonMail/go-proton-api`](https://github.com/ProtonMail/go-proton-api) — auth, decrypt-on-sync, and send (ADR-0001)
- **Persistent store:** SQLite via `github.com/jmoiron/sqlx` + [`github.com/pressly/goose`](https://github.com/pressly/goose), pure-Go [`modernc.org/sqlite`](https://gitlab.com/cznic/sqlite) (FTS5 built in) (ADR-0006)
- **Secrets:** OS keychain via a cross-platform wrapper (e.g. [`github.com/zalando/go-keyring`](https://github.com/zalando/go-keyring)) — macOS Keychain / libsecret / Windows CredMan (ADR-0013)
- **Embeddings / vectors:** brute-force cosine over SQLite BLOBs by default; optional `sqlite-vec` (ADR-0015)
- **LLM access:** one OpenAI-compatible client (sole egress), local default via LiteLLM → Ollama; two model roles (text/embedding + multimodal) (ADR-0018)
- **MCP:** [`github.com/modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk) over **stdio** (ADR-0017)
- **CLI:** Cobra + Viper
- **Frontend:** HTMX + Tailwind CSS + DaisyUI + Hero Icons, loopback-only, no auth (ADR-0005); SSE only where a screen needs it
- **Logging:** `log/slog` (stderr for the MCP server)
- **Build:** Make + multi-stage Dockerfile (Docker optional; primary distribution is `go install`)

## Conventions

- **ADRs in `docs/adrs/`**, MADR format. **OpenSpecs in `docs/openspec/`**, paired `spec.md` + `design.md`. The design plugin (`/sdd:*` commands) is the primary architecture-governance tool.
- **Branch naming:** `feat/{number}-{slug}`, `fix/{number}-{slug}`, `chore/{number}-{slug}`, `docs/{number}-{slug}`, `ci/{number}-{slug}`.
- **PR Convention:** Title = issue title; body must include `Closes #N`; target `main`.
- **Lifecycle labels:** `queued` → `in-progress` → `in-review` → `merged` (managed by `/design:work`).
- **Adversarial PR review:** Two reviewer agents per PR (one hostile, one spec-compliance). No PR merges without review.
- **Pre-PR pair flow:** Driver implements + commits locally; Navigator reviews diff before push.
- **Lint before PR:** `make fmt && make lint` mandatory before opening PRs.
- **Governing comments:** `// Governing: ADR-XXXX (short), SPEC-XXXX REQ "..."` inline at non-obvious decision sites.
- **Module path:** `github.com/joestump/reduit`.

## Out of scope

- **The IMAP/SMTP relay** — Reduit no longer serves IMAPS/SMTPS. Run Proton Bridge alongside it for a standard mail client (ADR-0012).
- **Multi-user / OIDC / a network control plane** — single local user, no auth, no IdP (ADR-0012).
- Proton Drive
- Proton Calendar (full surface — basic event read may come later)
- Bridge-style GUI
- In-process TLS / ACME — there is no public listener; the optional UI binds to loopback (ADR-0005/0012).

## Deployment context

- **Runs locally, per person.** Reduit installs on each user's own machine (`go install`, or the optional Docker image), runs as the local OS user, and holds only that user's Proton mailboxes. There is no shared host, no central deployment, no OIDC IdP, and no public DNS/TLS to provision.
- **Secrets:** the OS keychain on the machine Reduit runs on (ADR-0013). On a headless host, the operator unlocks the keyring out of band.
- **LLM endpoint:** a local LiteLLM → Ollama by default, so nothing leaves the machine; pointing a model role at a hosted provider is a deliberate, documented opt-in (ADR-0018).
- **Mail client:** Proton Bridge (run separately) covers IMAP/SMTP; Reduit covers search, RAG, MCP, and send.

## Visual Identity

Used by the `gemini-mockup` skill and any future UI work.

- **Mode:** Dark mode is the canonical surface. Light mode MAY be supported later via DaisyUI's theme system, but every mockup and design artifact starts dark.
- **Palette:**
  - **Primary:** deep indigo. Anchor around `#4F46E5` (Tailwind `indigo-600`); buttons and active states sit here.
  - **Surfaces:** slate greys. Page background is near-black slate (`#0F172A` / `slate-900`); cards sit on `#1E293B` (`slate-800`); borders / dividers `#334155` (`slate-700`).
  - **Foreground:** soft off-white (`#E2E8F0` / `slate-200`) for primary text; dim (`#94A3B8` / `slate-400`) for secondary; subtle (`#64748B` / `slate-500`) for tertiary metadata.
  - **Accent:** single warm tone — a desaturated amber/copper (`#F59E0B` / `amber-500` or a slightly toned-down variant). Reserved for important state callouts (live sync, alerts, the singular call-to-action). Not a second primary.
  - **Status colors:** muted, dark-mode-friendly: green `#10B981` (success), rose `#F43F5E` (error), sky `#0EA5E9` (info). Never neon.
- **Typography:** [Inter](https://rsms.me/inter/) at multiple weights (400 regular for body, 500 medium for labels, 600 semibold for headings). Tabular figures for numerics. Fall back to system geometric sans if Inter is unavailable.
- **Component framework:** DaisyUI 5 on Tailwind 4. Use DaisyUI components (`btn`, `card`, `modal`, `alert`, `table`, `badge`, `tabs`) as the base; project-specific overrides via Tailwind utilities only when DaisyUI's variants don't cover the case.
- **Iconography:** [Heroicons](https://heroicons.com/) outlined variants at 24×24, 1.5px stroke. Solid variants only for active/selected states. Inlined as SVG via Go template helpers — never icon fonts, never CDN.
- **Motif:** subtle alpine / Swiss-fortress. The login screen and empty states MAY use a faint mountain-silhouette band at the bottom or as a soft background gradient. Restraint over decoration — no skeumorphic textures, no grain overlays, no animated gradients. The metaphor is fortified clarity, not visual noise.
- **Whitespace:** generous. Cards have ≥24px internal padding. Sections separated by ≥32px. The default density is "comfortable", not "compact" — Reduit is family-grade software, not a Bloomberg terminal.
- **Browser-chrome URL pattern (for mockups):** `https://reduit.<host>/<route>` where `<host>` is the operator's chosen domain (e.g., `reduit.family.tld`, `reduit.stump.rocks`). Default in mockups: `reduit.family.tld` so the multi-user-family use case is visible at a glance.
- **Sample data conventions in mockups:** family-style names (Joe, Hannah, Maya, Sage), realistic email subjects (school logistics, receipts, sports schedules), recent timestamps, mixed read/unread states. Not corporate-feeling sample data.

## Architecture Context

This project uses the [design plugin](https://github.com/joestump/claude-plugin-design) for architecture governance.

- Architecture Decision Records are in `docs/adrs/`
- Specifications are in `docs/openspec/specs/`

### Design Plugin Skills

| Skill | Purpose |
|-------|---------|
| `/design:adr` | Create a new Architecture Decision Record |
| `/design:spec` | Create a new specification |
| `/design:list` | List all ADRs and specs with status |
| `/design:status` | Update the status of an ADR or spec |
| `/design:docs` | Generate a documentation site |
| `/design:init` | Set up CLAUDE.md with architecture context |
| `/design:prime` | Load architecture context into session |
| `/design:check` | Quick-check code against ADRs and specs for drift |
| `/design:audit` | Comprehensive design artifact alignment audit |
| `/design:discover` | Discover implicit architecture from existing code |
| `/design:plan` | Break a spec into trackable issues with project grouping and branch conventions |
| `/design:organize` | Retroactively group issues into tracker-native projects |
| `/design:enrich` | Add branch naming and PR conventions to existing issues |
| `/design:work` | Pick up tracker issues and implement them in parallel using git worktrees |
| `/design:review` | Review and merge PRs using reviewer-responder agent pairs |

Run `/design:prime [topic]` at the start of a session to load relevant ADRs and specs into context.

### Governing Comments

When implementing code governed by ADRs or specs, leave comments referencing the governing artifacts:

```
// Governing: ADR-0013 (secrets in OS keychain), SPEC-0001 REQ "Mailbox Identity"
```

These comments help future sessions (and `/design:check`) trace implementation back to decisions.

### Workflow

1. **Decide**: `/design:adr` — record the architectural decision
2. **Specify**: `/design:spec` — formalize requirements with RFC 2119 language
3. **Plan**: `/design:plan` — break the spec into trackable issues in your tracker
4. **Enrich**: `/design:organize` and `/design:enrich` — add projects and branch conventions
5. **Build**: `/design:work` — pick up issues and implement in parallel using git worktrees
6. **Review**: `/design:review` — review and merge PRs with spec-aware code review
7. **Validate**: `/design:check` and `/design:audit` to catch drift

### Session Coordination

When orchestrating multiple design plugin skills in a single session (e.g., running `/design:work` on several issues), use `TeamCreate` to coordinate agents. Do not spawn ad-hoc background agents for work that requires coordination — `SendMessage` only works within a Team, and isolated agents cannot see sibling file claims or type creations.

### Design Plugin Configuration

#### Tracker

- **Type**: gitea
- **Host**: gitea.stump.rocks
- **Owner**: joestump
- **Repo**: reduit

#### Branch Conventions

- **Enabled**: true
- **Prefix**: feat
- **Slug Max Length**: 50

#### PR Conventions

- **Enabled**: true
- **Close Keyword**: Closes
- **Ref Keyword**: Part of
- **Include Spec Reference**: true

#### Worktrees

- **Base Dir**: .claude/worktrees/
- **Max Agents**: 4
- **Auto Cleanup**: false
- **PR Mode**: ready

#### Review

- **Max Pairs**: 2
- **Merge Strategy**: squash
- **Auto Cleanup**: false

- **Max parallel agents**: 4
