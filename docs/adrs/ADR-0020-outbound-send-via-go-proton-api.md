# ADR-0020: Outbound send via go-proton-api

- **Status:** accepted
- **Date:** 2026-06-29
- **Deciders:** Joe Stump

## Context and Problem Statement

Reduit must be able to **send** mail, not only read and search it (a confirmed
requirement). Dropping the relay (ADR-0012) removed the `emersion/go-smtp`
submission server (ADR-0007), so the question is how outbound mail leaves Reduit
now. Reduit is otherwise local-first and reads/syncs from Proton (ADR-0014); send
is the one place it **writes** to Proton, which makes it the sharpest capability
to get right — it mutates the user's real mailbox and, exposed via MCP (ADR-0017),
hands an agent a write path.

## Decision Drivers

- **No SMTP server.** There is no listener; send is an internal capability, not a
  protocol endpoint.
- **Proton-native encryption.** Outbound mail must be composed and encrypted the
  Proton way (OpenPGP, recipient key handling) — which `go-proton-api` (ADR-0001)
  already implements, the same client used for read/sync/decrypt.
- **Multi-mailbox.** Send must be explicit about *which* of the user's N mailboxes
  (ADR-0012) it sends from.
- **Safe under agent control.** As an MCP tool, send is the one mutating tool; it
  must not fire silently or ambiguously.
- **Auditable.** Sent mail should be recorded/visible locally like everything else.

## Considered Options

1. **Send through `go-proton-api` directly (CLI verb + MCP tool).** Compose →
   encrypt → submit via the existing Proton client; no SMTP anywhere.
2. **Keep a loopback SMTP submission endpoint.** Re-add `go-smtp` bound to
   localhost so a mail client can submit. Rejected — reintroduces a listener and a
   protocol layer ADR-0012 just removed, for no gain over a direct API call.
3. **Defer send to Proton Bridge.** Tell users to send via Bridge. Rejected — the
   user wants send in Reduit (and agents need a send tool); offloading it breaks
   the MCP write path.

## Decision Outcome

**Chosen: option 1 — direct send via `go-proton-api`.**

- **Composition & encryption.** Reduit builds the message and submits it through
  `go-proton-api`, reusing that client's OpenPGP/recipient-key handling. The
  mailbox passphrase (keychain, ADR-0013) unlocks the signing/encryption keys.
- **Explicit from-mailbox.** Every send names the source mailbox; there is no
  implicit default that could send from the wrong account.
- **Two surfaces, one path.** A CLI verb (`reduit send …`) and an MCP `send` tool
  (ADR-0017) call the same internal send routine, so behavior cannot diverge.
- **Agent safety.** The MCP `send` tool is the **only** mutating tool. It is
  designed to require explicit, unambiguous invocation (clear required fields:
  from-mailbox, recipients, subject, body; no silent/auto-send), so an agent
  cannot fire mail as a side effect. The exact confirmation UX is a spec detail
  (Outbound Send spec) but the principle is fixed here.
- **Local record.** Sent messages are reflected in the local cache (via the next
  sync picking up the Sent folder, and/or an immediate local insert), so sends are
  visible and searchable like received mail.
- **No queue/relay semantics.** This is submission of a user-composed message, not
  an MTA. There is no spooling, retry-as-a-server, or onward relay; a failed send
  surfaces an error to the caller.

### Consequences

**Positive**

- Send reuses the one Proton client already in the binary; no SMTP server, no new
  protocol surface.
- Proton-native encryption is inherited, not reimplemented.
- One internal routine backs both CLI and MCP, keeping behavior consistent and
  agent-send guarded.

**Negative**

- Send is a real write to the user's mailbox and, via MCP, an agent-accessible
  one; the "explicit invocation only" guard is essential and must be honored in
  the spec and implementation.
- Reflecting sent mail locally depends on either a follow-up sync or a careful
  local insert to avoid a duplicate when sync later sees the Sent item
  (reconciled by the idempotent keying of ADR-0014).

**Operational**

- `reduit send --from <mailbox> --to … --subject … [body/attachments]`.
- The MCP `send` tool mirrors it with the same required fields and explicit
  invocation.
</content>
