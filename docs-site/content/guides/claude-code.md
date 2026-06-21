---
title: Claude Code (MCP)
sidebar_label: Claude Code (MCP)
sidebar_position: 5
---

# Claude Code (MCP)

Reduit embeds a **Model Context Protocol (MCP)** server
([ADR-0008](/decisions/ADR-0008-embedded-mcp-server),
[SPEC-0006](/specs/mcp-tool-surface/spec)) so agents like **Claude Code** can
read, search, organise, and send mail for a single Proton account — with no
Proton credentials and no Bridge on the machine running the agent.

The MCP server is served over the same HTTPS listener as the admin UI, at
**`/mcp`**, as a streamable HTTP MCP endpoint. Access is authorised by a
**per-account bearer token** you issue from the dashboard.

## 1. Issue an MCP token

Tokens are account-scoped and issued from the dashboard
([SPEC-0006](/specs/mcp-tool-surface/spec) REQ *Token Issuance and Revocation*):

1. Open the account, then its **MCP Tokens** page
   (`/accounts/{id}/mcp-tokens`).
2. Click **Issue token** and give it a label (e.g. *laptop-claude-code*).
3. The plaintext token — prefixed **`rdmcp_`** — is shown **exactly once** in a
   modal. Copy it now.

:::warning Shown once, stored hashed
Reduit persists only a SHA-256 hash of the token; the plaintext is never logged
and never shown again. Lost it? Revoke and issue a new one. Revocation is
immediate from the same page.
:::

A token grants access to **one account's** mailbox — the account it was issued
under. Issue separate tokens per account and per machine so you can revoke them
independently.

## 2. Add the server to Claude Code

The endpoint is `https://reduit.family.tld/mcp` and the token goes in an
`Authorization: Bearer` header.

### CLI

```bash
claude mcp add --transport http reduit \
  https://reduit.family.tld/mcp \
  --header "Authorization: Bearer rdmcp_your_token_here"
```

### Project config (`.mcp.json`)

Commit a `.mcp.json` to share the server across a project (keep the **token out
of source control** — use an env var):

```json
{
  "mcpServers": {
    "reduit": {
      "type": "http",
      "url": "https://reduit.family.tld/mcp",
      "headers": {
        "Authorization": "Bearer ${REDUIT_MCP_TOKEN}"
      }
    }
  }
}
```

Then run Claude Code with `REDUIT_MCP_TOKEN` set in the environment. Verify the
connection with `/mcp` inside Claude Code, or `claude mcp list` from the shell.

## 3. The tool surface

Once connected, the agent has these tools (all scoped to the token's account):

### Read

| Tool | What it does |
|------|--------------|
| `list_messages` | List messages in a folder (system folder or `Labels/<name>`), paginated, with an optional subject-substring filter. |
| `get_message` | Fetch one message by Proton ID. `format=metadata` (default) returns headers + parsed fields; `format=raw` streams the full RFC822 source as base64 chunks (capped at 16 MiB). |
| `search_messages` | Search messages by subject substring across all mail, paginated. |
| `list_labels` | List the account's labels and folders with the Proton label IDs that `add_label` / `remove_label` accept. |

### Organise (write)

| Tool | What it does |
|------|--------------|
| `add_label` | Apply a Proton label to a message. Idempotent. |
| `remove_label` | Remove a Proton label from a message. Idempotent. |
| `move_to_folder` | Move a message to a folder (system name or `Labels/<name>`). Idempotent. |
| `mark_read` | Mark one or more messages read. Idempotent. |
| `mark_unread` | Mark one or more messages unread. Idempotent. |

### Send & attachments

| Tool | What it does |
|------|--------------|
| `send_message` | Send an email. Proton-recipient encryption is applied automatically by the outbox — the caller never specifies an encryption mode. |
| `download_attachment` | Download one attachment's decrypted bytes, streamed as ordered base64 chunks (16 MiB cap; larger attachments are truncated and flagged). |

The write and send tools are deliberately **idempotent** so an agent can retry
safely.

## Multiple accounts

A bearer token already names its account, so point Claude Code at `/mcp` and
you're done. Operators authenticating with an **OIDC session** instead of a
token can target a specific account with the `/accounts/{id}/mcp` route (or the
`X-Reduit-Account` header) — useful when one human manages several accounts.

## Security notes

- **Scope:** one token → one account. No token can reach another account's mail.
- **Transport:** bearer over TLS. Treat `rdmcp_` tokens like passwords; keep
  them in env vars or a secret manager, never in committed config.
- **Revocation:** immediate, from the **MCP Tokens** page. Revoke per device.
- **Auditability:** only the token hash is stored; issuance and revocation are
  CSRF-protected operator actions.
