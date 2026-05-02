# Reduit

A sovereign, multi-user Proton Mail relay for self-hosters. Headless
daemon serving standard SMTPS + IMAPS over the network so several
Proton accounts can be used with any email client. Includes an
integrated MCP server for Proton-specific operations.

## Status

Pre-alpha. Architecture and specs are being written. No functional
release yet.

## Stack

- **Language:** Go 1.25+
- **Proton client:** [`github.com/ProtonMail/go-proton-api`](https://github.com/ProtonMail/go-proton-api)
- **IMAP server:** [`github.com/emersion/go-imap`](https://github.com/emersion/go-imap) (v2)
- **SMTP submission:** [`github.com/emersion/go-smtp`](https://github.com/emersion/go-smtp)
- **HTTP control plane:** stdlib `net/http`
- **OIDC:** [`github.com/zitadel/oidc`](https://github.com/zitadel/oidc) or [`github.com/coreos/go-oidc`](https://github.com/coreos/go-oidc)
- **Sessions:** [`github.com/alexedwards/scs`](https://github.com/alexedwards/scs)
- **Persistent store:** SQLite via `github.com/jmoiron/sqlx` + [`github.com/pressly/goose`](https://github.com/pressly/goose)
- **Encryption-at-rest:** `golang.org/x/crypto/chacha20poly1305` or `filippo.io/age`
- **MCP:** [`github.com/modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk)
- **CLI:** Cobra + Viper
- **Frontend:** HTMX + SSE + Tailwind CSS + DaisyUI + Hero Icons
- **Logging:** `log/slog`
- **TLS:** stdlib `crypto/tls`, certs read from disk, hot-reloaded via `fsnotify`
- **Build:** Make + multi-stage Dockerfile

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

- Proton Drive
- Proton Calendar (full surface — basic event read may come later)
- Bridge-style GUI
- ACME / autocert in-process (use certbot or Caddy in front; Reduit reads cert files from disk)

## Deployment context

- **Target host:** stumpcloud (Joe's self-hosted infrastructure). Specifically `ie01.dub.stump.rocks` or similar; no GPU, see relevant memory.
- **TLS frontend:** Caddy or Traefik in front of Reduit; certbot handles ACME on whatever host. Reduit reads certs from a mounted volume.
- **OIDC IdP:** Pocket ID. OIDC clients are provisioned via the `joestump.pocket_id` Ansible collection — never via the Pocket ID UI.
- **Service DNS:** likely `reduit.ops01.stump.rocks` per the ops01 DNS convention.

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
// Governing: ADR-0001 (chose JWT over sessions), SPEC-0003 REQ "Token Validation"
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

- **Type**: github
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
