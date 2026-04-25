# Reduit

> A sovereign Proton Mail outpost. Multi-user, headless, self-hosted.

**Reduit** (French: *redoubt*) is a self-hosted Proton Mail relay. It serves
several Proton accounts as standard SMTP and IMAPS endpoints over the
network, so any mail client — phone, laptop, mutt, whatever — can use a
Proton account without running Proton Bridge on every device.

The name comes from the Swiss WWII *Reduit National* — the strategy of
withdrawal into self-sufficient Alpine fortresses to preserve sovereignty
under siege. Reduit-the-software is the same idea applied to mail: your
family or team can keep using Proton without surrendering daily operation
to a desktop GUI on each user's laptop.

## Status

🚧 **Pre-alpha.** Architecture and specs are being written. No functional
release yet.

## What Reduit is

- **Multi-user.** Designed from the start for households / teams where
  several people each have a Proton account.
- **Headless.** Daemon. No GUI. Configured via env + YAML, deployed via
  Docker.
- **Standards-out.** Speaks SMTP submission and IMAPS over TLS to your
  email clients. Uses Proton Mail Bridge's official Go client
  ([`go-proton-api`](https://github.com/ProtonMail/go-proton-api))
  upstream.
- **OIDC.** Initial setup and ongoing per-user account management is
  gated by OIDC SSO (Pocket ID by default; any OIDC provider should
  work).
- **MCP-enabled.** Includes an integrated Model Context Protocol server
  exposing Proton-specific operations (labels, system folders, search)
  that standard IMAP/SMTP clients can't model cleanly.
- **TLS via disk.** Reads cert + key from disk, hot-reloads on file
  change. Bring your own certbot or Caddy; Reduit doesn't do ACME.

## What Reduit is not

- **Not Proton Bridge.** Bridge is single-user, GUI, localhost-only.
  Reduit is multi-user, headless, network-exposed.
- **Not [hydroxide](https://github.com/emersion/hydroxide).** Hydroxide
  is single-user and based on a 2017-era reverse-engineered Proton
  client; Reduit is multi-user and built on Proton AG's officially
  maintained Go client.
- **Not a Proton Drive / Calendar replacement.** Mail only (for now).
- **Not free of operational overhead.** It's still your job to run
  certbot / Caddy in front, point DNS, configure email clients, keep
  the host alive, back up the SQLite store.

## Architecture

See [`docs/adrs/`](docs/adrs/) for architectural decisions and
[`docs/openspec/`](docs/openspec/) for specifications.

## License

[MIT](LICENSE) — copyright © 2026 Joe Stump.
