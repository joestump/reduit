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

## Design Plugin Configuration

- **Max parallel agents**: 4
