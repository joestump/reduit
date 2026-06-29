# ADR-0012: Single-user, local-first, per-person binary

- **Status:** accepted
- **Date:** 2026-06-29
- **Deciders:** Joe Stump
- **Supersedes:** [ADR-0002](ADR-0002-multi-tenant-data-model.md) (multi-tenant
  data model), [ADR-0004](ADR-0004-oidc-control-plane-auth.md) (OIDC control
  plane), [ADR-0007](ADR-0007-imap-and-smtp-protocol-libraries.md) (IMAP/SMTP
  relay libraries), [ADR-0009](ADR-0009-tls-via-disk-with-hot-reload.md) (TLS
  listeners), [ADR-0010](ADR-0010-multi-account-per-user.md) (multi-account per
  OIDC user), [ADR-0011](ADR-0011-http-mode-for-reverse-proxy-fronting.md) (HTTP
  reverse-proxy mode)

## Context and Problem Statement

Reduit was designed (ADR-0002) as a single shared, network-exposed,
multi-tenant daemon. One host serves IMAPS/SMTPS to several people's mail
clients, holds every account's Proton refresh token and mailbox passphrase at
rest (ADR-0003), and gates the control plane behind an external OIDC IdP
(ADR-0004, ADR-0010).

That topology reintroduces the exact thing Proton exists to remove: **a central
party that must be trusted with the keys to everyone's mail.** Compromise the one
host — its disk, its master key, its OIDC session store, or any of its three
network listeners — and you compromise every family member's Proton account at
once. The relay also duplicates [Proton Bridge](https://proton.me/mail/bridge),
which already serves IMAP/SMTP from a local process; Reduit's network-and-OIDC
machinery bought multi-user reach at the cost of becoming the single point of
total compromise.

The actual unmet need is not *another mail server*. It is **local semantic
search, RAG, and agent access over Proton mail** — a surface Bridge does not
provide and that cannot exist without a local, rate-limit-friendly cache of
decrypted mail. That need is inherently per-person and local. This ADR resets
the architecture around it.

## Decision Drivers

- **No central trust.** No single host or key may unlock more than one person's
  mail. The blast radius of a compromise must be one person, ideally one device.
- **No second trusted party.** Dropping the OIDC IdP removes an entire external
  dependency (Pocket ID) from the trust and uptime story.
- **Don't rebuild Bridge.** IMAP/SMTP for arbitrary clients is a solved problem;
  Reduit should not own a relay it cannot differentiate.
- **Local-first, like `msgbrowse`.** The sibling project establishes the posture:
  one binary per person, loopback-only, secrets in the OS keychain, one auditable
  network egress, stdio MCP launched by the user's own client.
- **One human, several mailboxes.** The operator already runs two Proton accounts
  (personal + family). Per-person does **not** mean per-mailbox; one install must
  serve N Proton mailboxes for the one local user.

## Considered Options

1. **Keep the shared multi-tenant relay, harden it further.** Continue ADR-0002's
   model; invest more in master-key rotation, session invalidation, TLS hardening
   (the #59–#64 work).
2. **Single-user, local-first, per-person binary.** No relay, no OIDC, no shared
   daemon. One binary per person on their own machine, serving only that person's
   Proton mailboxes; secrets in the OS keychain; loopback UI; stdio MCP.
3. **Single-user but keep a loopback IMAP/SMTP bridge.** Drop multi-tenancy and
   OIDC but retain the emersion-based relay bound to localhost — i.e., become
   Proton Bridge plus search.

## Decision Outcome

**Chosen: option 2 — single-user, local-first, per-person binary.**

- **One install, one human, no auth.** Reduit runs as the local OS user. There is
  no login, no OIDC, no session store, no admin allowlist. The threat model loses
  the network attacker and the central-vault attacker entirely (see ADR-0013 for
  secrets, ADR-0018 for the egress boundary).
- **No relay.** The IMAPS (993), SMTPS (465), and HTTPS control-plane listeners
  are removed, along with the emersion `go-imap`/`go-smtp` dependencies
  (ADR-0007) and the on-disk TLS machinery (ADR-0009, ADR-0011). Operators who
  want IMAP/SMTP for a standard mail client run Proton Bridge alongside Reduit.
- **Multi-mailbox from v1.** A single install serves **N Proton mailboxes** for
  the one local user. Each mailbox is a local configuration row (`mailboxes`)
  with its own keychain secret reference (ADR-0013) and its own cache namespace
  in the shared SQLite store (ADR-0006). There is **no `users` table and no OIDC
  `subject`** — the OS user *is* the identity. This preserves ADR-0010's real
  requirement (one person, many Proton accounts) while deleting its OIDC
  mechanism.
- **Surfaces.** The product faces are (a) a **stdio MCP server** (ADR-0017,
  primary), (b) a **CLI** for sync/embed/send/admin, and (c) an **optional
  loopback HTMX UI** (ADR-0005, reframed) for human browsing. All three read the
  same SQLite store, so behavior cannot drift between them.
- **Read and write.** Reduit reads/syncs from Proton (ADR-0014) and **sends**
  through it (ADR-0020). Only the local cache is derived state.

### Consequences

**Positive**

- The central-trust problem is gone by construction: there is no shared host, no
  master key over other people's secrets, no network-exposed vault, no IdP. A
  compromise is scoped to one person's machine.
- Massive surface reduction: three network listeners, the OIDC RP, the session
  store, the TLS hot-reload loader, and the multi-tenant routing layer all
  disappear, taking the #59–#64 hardening work with them (it becomes moot).
- The product gains a clear reason to exist over Bridge — local RAG/MCP over mail —
  instead of competing with it.

**Negative**

- Loses "use any mail client over the network." That capability now belongs to
  Proton Bridge, which the operator runs separately. Reduit no longer serves
  phones/other devices directly.
- Multi-user-on-one-host is gone. Each person runs and updates their own binary;
  there is no central place to administer the family.
- "Local-first" makes the **decrypted local cache** the new sensitive asset
  (accepted, mitigated by OS disk encryption — see the refactor plan and
  forthcoming SECURITY.md).

**Operational**

- Distribution is `go install` / a single static binary per person, not a shared
  Docker deployment. Docker becomes an optional convenience (ADR-0018 egress).
- Existing multi-tenant migrations, OIDC config, and TLS/cert plumbing are removed
  in the code refactor that follows the doc layer.
</content>
