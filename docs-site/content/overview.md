---
title: Reduit
sidebar_label: Overview
slug: /
---

# Reduit

> Docs are being rebuilt around the new architecture. Nothing on this site is current.

**Reduit** is a sovereign, single-user, local-first tool for Proton Mail — a per-person Go binary with a stdio MCP server for agents, a Bubble Tea TUI (`reduit tui`) for humans, and a local send path. It is **not** an IMAP/SMTP relay.

## Where the truth lives right now

While these docs are being rebuilt:

- **Source of truth for architecture** — the ADRs and specs in the [repository](https://gitea.stump.rocks/joestump/reduit):
  - [`docs/adrs/`](https://gitea.stump.rocks/joestump/reduit/src/branch/main/docs/adrs)
  - [`docs/openspec/specs/`](https://gitea.stump.rocks/joestump/reduit/src/branch/main/docs/openspec/specs)
- **Governing decisions** — start with:
  - [ADR-0012](https://gitea.stump.rocks/joestump/reduit/src/branch/main/docs/adrs/ADR-0012-single-user-local-first.md) — single-user, local-first
  - [ADR-0017](https://gitea.stump.rocks/joestump/reduit/src/branch/main/docs/adrs/ADR-0017-stdio-mcp-and-hybrid-rag.md) — stdio MCP + hybrid RAG
  - [ADR-0025](https://gitea.stump.rocks/joestump/reduit/src/branch/main/docs/adrs/ADR-0025-local-tui-bubbletea.md) — Bubble Tea TUI, mutt design language
- **Current work** — [epic #167](https://gitea.stump.rocks/joestump/reduit/issues/167) is the TUI implementation

## What was removed on 2026-07-04

The previous version of this site documented Reduit as a multi-user Proton Mail relay with IMAPS/SMTPS listeners, OIDC login, and an HTMX web UI. **All of that is gone.** The project pivoted to single-user local-first ([ADR-0012](https://gitea.stump.rocks/joestump/reduit/src/branch/main/docs/adrs/ADR-0012-single-user-local-first.md), 2026-06-29) and then to a TUI-only human surface ([ADR-0025](https://gitea.stump.rocks/joestump/reduit/src/branch/main/docs/adrs/ADR-0025-local-tui-bubbletea.md), 2026-07-03). The relay-era ADRs (0002/0004/0005/0007/0009/0010/0011) were deleted outright since Reduit is pre-alpha and nothing depended on them.

The docs site will be rebuilt against the new architecture after the TUI ships.

:::note Status
**Pre-alpha, mid-refactor.** No functional release yet.
:::
