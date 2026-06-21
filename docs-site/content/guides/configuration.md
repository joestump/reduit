---
title: Configuration
sidebar_label: Configuration
sidebar_position: 2
---

# Configuration

Reduit is configured by a YAML file (default `/etc/reduit/reduit.yaml`, or
`--config /path`) layered with environment variables. **Secrets should come from
the environment, not the file.**

## Environment variables

Every YAML key has an environment-variable equivalent: uppercase, prefixed with
`REDUIT_`, with nesting joined by underscores.

| YAML | Environment variable |
|------|----------------------|
| `oidc.client_secret` | `REDUIT_OIDC_CLIENT_SECRET` |
| `server.http_addr` | `REDUIT_SERVER_HTTP_ADDR` |
| `logger.level` | `REDUIT_LOGGER_LEVEL` |

### `_FILE` secret indirection

Any `REDUIT_*` variable also supports a `_FILE` variant whose value is a **path**
to a file containing the secret — the Docker/Kubernetes secrets convention:

```yaml
REDUIT_OIDC_CLIENT_SECRET_FILE: /run/secrets/oidc_client_secret
```

When both forms are set, the `_FILE` variant wins. Trailing whitespace
(including the newline Docker appends) is stripped. A `_FILE` pointer to a
missing file is a **hard error at startup**.

## Full reference

```yaml
server:
  http_addr: ":443"     # Admin UI + MCP (HTTPS)
  imap_addr: ":993"     # IMAPS
  smtp_addr: ":465"     # SMTPS submission
  metrics_addr: ""      # e.g. "127.0.0.1:9090" to expose Prometheus

tls:
  # Reduit reads certs from disk and hot-reloads them (ADR-0009).
  # Provision via certbot, Caddy, Traefik, etc. Reduit does NOT do ACME.
  cert_path: /etc/reduit/tls/fullchain.pem
  key_path:  /etc/reduit/tls/privkey.pem
  # disabled: true   # plaintext HTTP for the admin/MCP listener ONLY when
  #                  # behind a TLS-terminating proxy — see the reverse-proxy guide.

master_key:
  # Service master key (ADR-0003). Generate once: `reduit master-key generate`.
  # Back this file up out of band — loss = total data loss.
  path: /var/lib/reduit/master.key

store:
  path: /var/lib/reduit/reduit.db
  # migrations_dir: /opt/reduit/migrations   # override embedded migrations

oidc:
  issuer_url:    https://pocketid.family.tld
  client_id:     reduit
  # client_secret: keep in REDUIT_OIDC_CLIENT_SECRET, not here.
  redirect_url:  https://reduit.family.tld/auth/callback
  scopes:
    - openid
    - profile
    - email
  admin_subjects: []   # additional admin OIDC `sub`s (first login is auto-admin)
  auto_create: true    # if false, an unknown `sub` is rejected instead of created

logger:
  level:  info     # debug | info | warn | error
  format: text     # text | json
```

## Sections

### `server`

| Key | Default | Notes |
|-----|---------|-------|
| `http_addr` | `:443` | Admin UI **and** the `/mcp` endpoint (HTTPS). |
| `imap_addr` | `:993` | IMAPS listener. Must be **empty** when `tls.disabled` is true. |
| `smtp_addr` | `:465` | SMTPS submission. Must be **empty** when `tls.disabled` is true. |
| `metrics_addr` | `""` | Bind a Prometheus endpoint, e.g. `127.0.0.1:9090`. Empty = off. |

### `tls`

Reduit reads `cert_path` / `key_path` from disk and **hot-reloads** them on
change (ADR-0009), so certbot/Caddy renewals take effect without a restart. Set
`disabled: true` only behind a trusted TLS-terminating proxy — see
[Behind a Reverse Proxy](/guides/reverse-proxy).

### `master_key`

Points at the service master key that encrypts data at rest (ADR-0003).
Generate it once with `reduit master-key generate` and **back it up** — there is
no recovery path if it is lost.

### `store`

SQLite database location. Migrations are embedded in the binary; set
`migrations_dir` only to override them. Run `reduit migrate` to apply.

### `oidc`

Operator (human) authentication for the admin UI (ADR-0004, SPEC-0005). Register
Reduit at your IdP with `redirect_url`. The first `sub` to log in becomes admin;
add more admin `sub`s to `admin_subjects`. With `auto_create: false`, only known
subjects may log in.

### `logger`

`level` is `debug | info | warn | error`; `format` is `text | json`. Use `json`
when shipping logs to Loki/Elasticsearch.

## Retention

The sync worker prunes its local cache on an interval. Where exposed, the
relevant keys are `store.retention_period` and `store.sweep_interval` (durations,
e.g. `720h`). Leave them unset to accept the built-in defaults.
