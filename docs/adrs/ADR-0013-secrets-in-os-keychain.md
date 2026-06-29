# ADR-0013: Secrets in the OS keychain

- **Status:** accepted
- **Date:** 2026-06-29
- **Deciders:** Joe Stump
- **Supersedes:** [ADR-0003](ADR-0003-encryption-at-rest-scheme.md)
  (service-master-key envelope encryption)

## Context and Problem Statement

ADR-0003 protected at-rest secrets — Proton refresh tokens, mailbox passphrases,
and the per-user IMAP/SMTP passwords — with a service master key on disk that
envelope-encrypts a per-account data key. That scheme exists to let one shared,
headless, multi-tenant daemon hold *everyone's* secrets and restart unattended.

ADR-0012 deletes that daemon. Reduit is now a single-user, local, per-person
binary. Two of the three secret classes vanish outright: there are no per-user
IMAP/SMTP passwords (no relay), and there is no other user whose secrets a master
key must also unlock. What remains is, per Proton mailbox the local user
configures:

- the **Proton refresh token** (renews the access token), and
- the **mailbox passphrase** (unlocks the OpenPGP private keys to decrypt mail
  and to send).

The master-key envelope is now overkill *and* a liability: it persists a single
on-disk key that decrypts everything, plus the operational trap ADR-0003 itself
flagged (a silently-generated key the operator never backed up = latent total
loss). A single-user desktop tool should instead use the secret store the OS
already provides.

## Decision Drivers

- **No on-disk master key.** Nothing on disk should, by itself, decrypt the
  user's Proton secrets.
- **Use platform facilities.** `msgbrowse` treats the OS Keychain as the secret
  boundary; matching that keeps the posture consistent across the two tools.
- **Headless restart still works.** Sync workers must resume after a reboot
  without a human re-typing a passphrase — so the secret must be retrievable
  non-interactively from the platform store (subject to the OS's own unlock).
- **Multi-mailbox.** N mailboxes means N independent secret entries, namespaced
  per mailbox, never co-mingled under one key.

## Considered Options

1. **Keep the master-key envelope (ADR-0003), single-user.** Encrypt the two
   remaining secrets under an on-disk master key.
2. **OS keychain.** Store each mailbox's secrets as named entries in the platform
   secret service: macOS Keychain, Linux Secret Service (libsecret / GNOME
   Keyring / KWallet) via D-Bus, Windows Credential Manager.
3. **Prompt / in-memory only.** Never persist the passphrase; prompt at startup.
   *Rejected in the refactor decisions — breaks unattended restart.*

## Decision Outcome

**Chosen: option 2 — store secrets in the OS keychain.**

- **Library.** A cross-platform Go keychain wrapper (e.g.
  `github.com/zalando/go-keyring`) abstracting macOS Keychain, libsecret, and
  Windows Credential Manager. The exact dependency is pinned in ADR-0006's
  go.mod work; the contract here is "named secret in the platform store," not a
  specific package.
- **Keying.** Service name `reduit`; account key `mailbox/<mailbox_id>/<kind>`
  where `<kind>` ∈ {`refresh_token`, `mailbox_passphrase`}. `<mailbox_id>` is the
  local UUIDv7 from the `mailboxes` row (ADR-0006). Secrets are **per mailbox**;
  there is no shared key spanning mailboxes.
- **What lives where.** The keychain holds only the two live secrets. The SQLite
  store holds the *reference* (the `mailbox_id`) and all derived, non-secret
  state. Secret columns from ADR-0003/0006 (`key_envelope`, encrypted token/
  passphrase blobs) are **removed** from the schema.
- **No app-layer master key.** There is no `master.key` file, no
  `reduit master-key` command, and no envelope. The OS unlock (login keychain /
  session keyring) is the trust gate.
- **Headless / server-y hosts.** On a host without an interactive keyring session,
  the operator unlocks the keyring out of band (e.g. a headless libsecret
  collection unlocked at boot). Reduit documents this rather than reintroducing
  its own key file. *(If a future deployment genuinely needs file-based secrets,
  that is a new ADR, opt-in, and loudly caveated — not the default.)*

### Consequences

**Positive**

- No single on-disk artifact decrypts the user's mail. The "backup leak = total
  compromise" and "lost unbacked-up master key = total loss" failure modes from
  ADR-0003 are both gone.
- Per-mailbox secret isolation falls out naturally from distinct keychain entries.
- One less bespoke subsystem to build and secure (no envelope crypto, no key
  rotation command, no umask/0600 file handling — the #59 work is moot).

**Negative**

- Adds a platform dependency on a working secret service. Linux server hosts
  without a desktop session need a deliberately unlocked keyring; this is
  documented operator setup, not automatic.
- Keychain access prompts/behavior differ per platform and must be handled and
  documented (first-run authorization on macOS, D-Bus collection unlock on Linux).

**Operational**

- First-run `reduit auth` for a mailbox writes its two secrets to the keychain;
  removing a mailbox deletes its keychain entries.
- The local SQLite cache itself is **not** app-layer encrypted (accepted in the
  refactor decisions — rely on OS full-disk encryption). The keychain protects
  the *credentials*; FDE protects the *derived plaintext cache*. See ADR-0012 and
  SECURITY.md.
