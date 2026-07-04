# Reduit

A sovereign, **single-user, local-first** tool for Proton Mail. A
per-person Go CLI that authenticates to Proton, incrementally **caches**
mail into a local SQLite store, embeds messages and attachments locally,
and serves semantic/hybrid **search + RAG over a stdio MCP** (primary), a
local send path, and a **Bubble Tea TUI** (`reduit tui`) for human
browsing. Nothing is network-exposed; secrets live in the OS keychain.
The model is "msgbrowse for Proton Mail" (see `~/src/msgbrowse`).

Reduit is **not** an IMAP/SMTP relay — for a standard mail client, run
[Proton Bridge](https://proton.me/mail/bridge) alongside it.

## Status

Pre-alpha, **mid-refactor**. Two pivots have landed:

- **2026-06-29** — from a multi-user OIDC relay to the single-user
  local-first design above (ADR-0012).
- **2026-07-03** — the human surface pivoted from an HTMX web UI to a
  Bubble Tea TUI in a mutt-inspired design language (ADR-0025, SPEC-0005).

The 2026-07-04 artifact reset deleted the relay-era ADRs
(0002/0004/0005/0007/0009/0010/0011) outright rather than keeping them as
history — nothing in production references them, and pre-alpha grants that
latitude. ADRs 0022/0023/0025 are `accepted`. Code is being brought in
line; no functional release yet.

## Stack

- **Language:** Go 1.25+
- **Proton client:** [`github.com/ProtonMail/go-proton-api`](https://github.com/ProtonMail/go-proton-api) — auth, decrypt-on-sync, and send (ADR-0001)
- **Persistent store:** SQLite via `github.com/jmoiron/sqlx` + [`github.com/pressly/goose`](https://github.com/pressly/goose), pure-Go [`modernc.org/sqlite`](https://gitlab.com/cznic/sqlite) (FTS5 built in) (ADR-0006)
- **Secrets:** OS keychain via a cross-platform wrapper (e.g. [`github.com/zalando/go-keyring`](https://github.com/zalando/go-keyring)) — macOS Keychain / libsecret / Windows CredMan (ADR-0013)
- **Embeddings / vectors:** brute-force cosine over SQLite BLOBs by default; optional `sqlite-vec` (ADR-0015)
- **LLM access:** one OpenAI-compatible client (sole egress), local default via LiteLLM → Ollama; two model roles (text/embedding + multimodal) (ADR-0018)
- **MCP:** [`github.com/modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk) over **stdio** (ADR-0017)
- **CLI:** Cobra + Viper
- **TUI:** [`charmbracelet/bubbletea`](https://github.com/charmbracelet/bubbletea) + [`bubbles`](https://github.com/charmbracelet/bubbles) + [`lipgloss`](https://github.com/charmbracelet/lipgloss), full-screen mutt-inspired design language (ADR-0025, SPEC-0005). No HTTP UI, no HTML, no CSP.
- **Logging:** `log/slog` behind [`charmbracelet/log`](https://github.com/charmbracelet/log) as the handler (ADR-0022); stderr only
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
- **Any HTTP listener.** The human surface is the Bubble Tea TUI (ADR-0025); there is no web UI, no HTTP server for the UI, no CSP, no TLS. `reduit serve` remains a non-UI stub reserved for possible future MCP-over-HTTP or a loopback media companion.

## Deployment context

- **Runs locally, per person.** Reduit installs on each user's own machine (`go install`, or the optional Docker image), runs as the local OS user, and holds only that user's Proton mailboxes. There is no shared host, no central deployment, no OIDC IdP, and no public DNS/TLS to provision.
- **Secrets:** the OS keychain on the machine Reduit runs on (ADR-0013). On a headless host, the operator unlocks the keyring out of band.
- **LLM endpoint:** a local LiteLLM → Ollama by default, so nothing leaves the machine; pointing a model role at a hosted provider is a deliberate, documented opt-in (ADR-0018).
- **Mail client:** Proton Bridge (run separately) covers IMAP/SMTP; Reduit covers search, RAG, MCP, and send.

## Visual Identity

The canonical style reference is [`docs/openspec/specs/local-ui/design.md`](docs/openspec/specs/local-ui/design.md) (the "Bubbletea TUI Design System" section). This section is a short summary; when the two disagree, `design.md` wins.

- **Surface:** a full-screen Bubble Tea TUI. There is no web UI, no HTML, no browser mockup surface.
- **Aesthetic:** cutesy-cyberpunk / Tron — kawaii meets anime, imagined as a homage to `mutt` built by a genius 13-year-old Japanese gamer/coder girl. Neon phosphor on a blue-black void, playful lowercase voice, dense keyboard-first interaction that stays *alive* rather than austere.
- **Palette:** void/surfaces `#08080F → #1E1E38`; brand Charm purple `#7D56F4` + hot pink `#FF5FA2`; Tron accents cyan `#4EE6FF` + mint `#00F0A8`; phosphor text `#F4F4FF` fading to dim indigo-grey; gold/coral for warn/danger. **No CSS glow/drop-shadow simulation** — terminals cannot render halos; emphasis comes from foreground/background color, bold, border style/color, and adaptive light/dark colors via lipgloss.
- **Typography:** monospace-first. Body/UI **JetBrains Mono**; chunky display/wordmarks **Space Mono** (tracking ~-0.04em); pixel eyebrows/badges **Silkscreen**. Hierarchy comes from weight/size/color, never font family.
- **Borders & layout:** Lip Gloss rounded border (`╭ ╮ ╰ ╯`) is the signature. Focus shifts the border to cyan; the active index/table row carries a pink inset rail (mutt's `>` cursor analog). Cell-aware spacing on a 4px base.
- **Motion:** quick and springy (Harmonica-style), 120–340ms; braille/dots/moon spinners; a cyan block cursor blinks `steps(1)` ~1.06s. All motion MUST honor `prefers-reduced-motion` (spinners freeze, progress jumps to end).
- **Iconography:** base layer is plain Unicode + box-drawing glyphs that render in any terminal font (nav `↑↓←→`, status `✓ ✗ ◆ ● ○ •`, prompt `❯ › $`, spinners `⣾⣽⣻⢿⡿⣟⣯⣷`, progress `█ ▓ ▒ ░`, borders `─ │ ╭ ╮ ╰ ╯`). Optional Nerd-Fonts enhancement layer for richer glyphs, gated behind detection or explicit opt-in, with a plain-Unicode fallback for every Nerd-Font glyph. Never assume a Nerd Font is present.
- **Voice:** playful, warm, lowercase; address the user as "you"; a dim `key • action` help footer on every view.

Notes for skills that used to generate mockups:
- `gemini-mockup` (browser-chrome, DaisyUI-driven) is retired for Reduit. Do not use it. If a mockup of a TUI screen is genuinely needed, generate an ANSI/screenshot of a running Bubble Tea program instead.
- `reduit.family.tld` browser URL patterns and family sample data (Hannah/Maya/Sage subjects) are dead conventions from the web-UI era; ignore them.

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
