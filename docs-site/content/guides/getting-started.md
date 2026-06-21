---
title: Getting Started
sidebar_label: Getting Started
sidebar_position: 1
---

# Getting Started

This guide takes a fresh host to a running Reduit with one Proton account linked
and reachable from a mail client. It assumes Docker and a DNS name pointed at
your host (e.g. `reduit.family.tld`).

## Prerequisites

- **A host** you control (Reduit's reference target is a small Linux box — no
  GPU, modest RAM).
- **Docker** + Docker Compose.
- **TLS certificates** for your Reduit hostname. Reduit does **not** do ACME
  itself — provision certs with certbot, Caddy, or Traefik. You can either give
  Reduit the cert files directly, or terminate TLS at a proxy and run Reduit in
  [`tls.disabled` mode](/guides/reverse-proxy).
- **An OIDC provider** for operator login. [Pocket ID](https://pocket-id.org) is
  the reference IdP, but any compliant provider works (Authelia, Keycloak,
  Okta).
- **A Proton account** (paid plan, so API access is available) for each user.

## 1. Lay out the deployment

Create a working directory with a `docker-compose.yml`, a `reduit.yaml`, and a
`data/` directory for the SQLite store and master key. A reference compose file
lives in the repo at `deploy/compose/docker-compose.yml`:

```yaml
services:
  reduit:
    image: ghcr.io/joestump/reduit:latest
    restart: unless-stopped
    ports:
      - "443:443"   # HTTPS — admin UI + MCP
      - "993:993"   # IMAPS
      - "465:465"   # SMTPS submission
    volumes:
      - ./data:/var/lib/reduit                       # SQLite DB + master.key
      - ./reduit.yaml:/etc/reduit/reduit.yaml:ro     # config
      - /etc/letsencrypt/live/reduit.family.tld/fullchain.pem:/etc/reduit/tls/fullchain.pem:ro
      - /etc/letsencrypt/live/reduit.family.tld/privkey.pem:/etc/reduit/tls/privkey.pem:ro
    environment:
      REDUIT_OIDC_CLIENT_SECRET: "${REDUIT_OIDC_CLIENT_SECRET}"
```

See [Configuration](/guides/configuration) for the full `reduit.yaml`.

## 2. Generate the service master key

Reduit encrypts sensitive data at rest (Proton session material, the
per-account IMAP passwords) under a single **service master key**. Generate it
once:

```bash
docker compose run --rm reduit master-key generate
```

This writes `master.key` into `/var/lib/reduit` (your `./data` mount).

:::danger Back this key up out of band
Losing `master.key` means **total, unrecoverable data loss** — every encrypted
record becomes garbage. Store a copy somewhere safe and separate from the host.
:::

## 3. Run database migrations

Reduit ships its schema migrations embedded in the binary. Apply them to a fresh
(or upgraded) database:

```bash
docker compose run --rm reduit migrate
```

## 4. Configure OIDC (operator login)

The admin UI is gated behind OIDC. Point Reduit at your IdP and register Reduit
as a client there with the redirect URL `https://reduit.family.tld/auth/callback`.

```yaml
oidc:
  issuer_url:   https://pocketid.family.tld
  client_id:    reduit
  redirect_url: https://reduit.family.tld/auth/callback
  scopes: [openid, profile, email]
  auto_create: true     # first login auto-creates the operator account
  admin_subjects: []    # add OIDC `sub`s here to grant admin
```

Keep the client secret out of the file — pass it as
`REDUIT_OIDC_CLIENT_SECRET` (or `REDUIT_OIDC_CLIENT_SECRET_FILE`).

:::tip First login becomes admin
The **first OIDC subject to log in** is promoted to admin automatically. After
that, add further admin `sub`s to `oidc.admin_subjects`.
:::

## 5. Start the daemon

```bash
docker compose up -d
docker compose logs -f reduit
```

Browse to `https://reduit.family.tld` and sign in through your IdP. You land on
the admin dashboard as the first (admin) operator.

## 6. Link a Proton account

From the dashboard, **add an account** and complete the Proton login wizard
(username, password, and 2FA / human-verification as Proton requires). Reduit
stores the resulting Proton session encrypted under the master key; your Proton
password is not retained. A background **sync worker** then begins mirroring the
mailbox so IMAP and MCP see live mail.

## 7. Connect a client or agent

Once an account is linked, open its **Credentials** page in the dashboard to get
the IMAP/SMTP login, then:

- **Mail client?** Follow [Connecting Apple Mail](/guides/apple-mail).
- **Claude Code / an agent?** Follow [Claude Code (MCP)](/guides/claude-code).

## CLI reference

Reduit's container entrypoint is the `reduit` binary:

| Command | Purpose |
|---------|---------|
| `reduit serve` | Run the daemon (default for the container). |
| `reduit migrate` | Apply embedded database migrations. |
| `reduit master-key generate` | Create the service master key (once). |

Run any of them ad-hoc with `docker compose run --rm reduit <command>`.
