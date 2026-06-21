---
title: Reduit
sidebar_label: Overview
slug: /
---

# Reduit

> A sovereign Proton Mail outpost. Multi-user, headless, self-hosted.

**Reduit** (French: *redoubt*) is a self-hosted Proton Mail relay. It serves
several Proton accounts as standard **IMAPS** and **SMTPS** endpoints over the
network, so any mail client — phone, laptop, Apple Mail, `mutt`, whatever — can
use a Proton account without running Proton Bridge on every device. It also
embeds a **Model Context Protocol (MCP)** server, so agents like **Claude Code**
can read, search, label, and send mail on a per-account basis.

The name comes from the Swiss WWII *Reduit National* — withdrawal into
self-sufficient Alpine fortresses to preserve sovereignty under siege. Reduit
applies the same idea to mail: your family or team keeps using Proton without
surrendering daily operation to a desktop GUI on every laptop.

## What Reduit gives you

- **Multi-user.** Built for households and teams where several people each have
  a Proton account. One daemon, many accounts, OIDC-gated.
- **Standards-out.** IMAPS (993) and SMTPS submission (465) over TLS, so every
  mail client just works — see [Connecting Apple Mail](/guides/apple-mail).
- **Agent-ready.** A built-in MCP server exposes read, write, and send tools per
  account — see [Claude Code (MCP)](/guides/claude-code).
- **Headless.** A daemon configured by env + YAML and deployed via Docker. No
  GUI to babysit, no Bridge on each device.
- **Sovereign.** SQLite store, encryption-at-rest under a service master key,
  TLS certs read from disk. You own the box and the data.

## How it fits together

```text
                          ┌─────────────────────────────────────────┐
   Apple Mail / mutt ─────▶  IMAPS :993   ┐                          │
   Apple Mail / mutt ─────▶  SMTPS :465   ┼──▶  Reduit daemon  ──▶  Proton Mail
   Claude Code (MCP) ─────▶  HTTPS :443   ┘     (go-proton-api)      (per account)
                          │   /mcp + admin UI                        │
                          └─────────────────────────────────────────┘
                              ▲
                              │ OIDC login (Pocket ID, Authelia, …)
                              │ TLS terminated here or at a proxy in front
```

Reduit authenticates **operators** (the humans who manage accounts) with OIDC,
and authenticates **mail clients / agents** with per-account credentials it
issues itself — an IMAP/SMTP password and one or more MCP bearer tokens. Your
Proton password and 2FA never leave the initial account-linking step.

## Start here

- **[Getting Started](/guides/getting-started)** — deploy Reduit, generate the
  master key, wire up OIDC, and link your first Proton account.
- **[Configuration](/guides/configuration)** — every env var and YAML key.
- **[Behind a Reverse Proxy](/guides/reverse-proxy)** — run with `tls.disabled`
  behind Caddy or Traefik.
- **[Connecting Apple Mail](/guides/apple-mail)** — IMAPS/SMTPS settings for
  macOS and iOS Mail.
- **[Claude Code (MCP)](/guides/claude-code)** — issue a token and use the mail
  tools from an agent.

## Architecture

The design is documented as [Architecture Decision Records](/decisions) (ADRs)
and [Specifications](/specs) (OpenSpec), generated directly from the source
repository. Start with [ADR-0008](/decisions/ADR-0008-embedded-mcp-server) for
the embedded MCP server and [SPEC-0006](/specs/mcp-tool-surface/spec) for the
tool surface.

:::note Status
Reduit is **pre-alpha** — architecture and specs are stabilising. These docs
track the source tree; commands and config keys are accurate to the current
`main`, but expect change before a tagged release.
:::
