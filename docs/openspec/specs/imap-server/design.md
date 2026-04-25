# Design: IMAP Server (SPEC-0003)

## Architecture

The IMAP server is one TCP listener (port 993) terminating TLS,
running an `emersion/go-imap` v2 server with a Reduit-implemented
`Backend`. The Backend resolves SASL identity to an account, then
returns a per-session object that delegates IMAP operations to the
account's local state in SQLite + the sync worker's pubsub.

```mermaid
flowchart LR
    Client[email client] -- IMAPS/993 --> Listener[TLS Listener]
    Listener -- ClientHello --> CertLoader[fsnotify-watched cert loader]
    Listener -- accepted conn --> GoIMAP[go-imap server]
    GoIMAP -- AUTH PLAIN --> Backend[Reduit Backend]
    Backend -- lookup user@host --> AcctSvc[Account Service]
    AcctSvc -- bcrypt verify --> DB[(SQLite)]
    Backend -- per-session --> Session[Session{account, mailbox}]
    Session -- LIST/SELECT/FETCH --> MailboxStore[Mailbox Store]
    Session -- IDLE --> PubSub[in-process pubsub]
    PubSub -. notify .-> Session
    SyncWorker[Sync Worker] -- publish updates --> PubSub
```

## Key data structures

- `mailboxes(account_id, name, uidvalidity, uidnext, attributes)` —
  one row per (account, mailbox) including system folders and Proton
  labels.
- `messages(account_id, mailbox_id, uid, proton_message_id, flags,
  internal_date, size, ...)` — Reduit's local view of each message
  in each mailbox.
- `uid_assignments(account_id, mailbox_id, proton_message_id, uid)` —
  ensures stable UIDs across Proton-message-ID re-additions (label
  remove → re-add gets a new UID).

## Folder mapping

Proton has a fixed set of system locations and a flat namespace of
user-defined labels. IMAP exposes a hierarchical folder tree.

| Proton concept | IMAP folder |
|---|---|
| `Inbox` system folder | `INBOX` |
| `Sent` | `Sent` |
| `Drafts` | `Drafts` |
| `Trash` | `Trash` |
| `Spam` | `Spam` |
| `Archive` | `Archive` |
| `All Mail` | `All Mail` |
| User label `Receipts` | `Labels/Receipts` |
| User label `Family/Tax` | `Labels/Family/Tax` |

Moving between system folders translates to add/remove of system
labels in Proton (Proton's data model is "every message is everywhere
it's labeled"). Moving between user labels translates to user-label
add/remove. A message can appear in multiple `Labels/*` folders if it
has multiple labels — IMAP-wise this is correctly represented by the
same message UID showing up in multiple mailboxes (or, alternatively,
by us treating `All Mail` as the canonical location and `Labels/*` as
virtual views; v0.1 implementation choice deferred to ADR-0011).

## UID stability strategy

The cardinal IMAP rule: **UIDs are forever**. A client that sees UID
N in mailbox M expects to see the same message at UID N for the life
of the session and across sessions until UIDVALIDITY changes.

Reduit's approach:

- **Local UID assignment.** When a message is added to a mailbox, the
  worker increments `mailboxes.uidnext` atomically and writes the UID
  into `messages` (and `uid_assignments` for replay correctness).
- **UIDVALIDITY at mailbox creation.** Set to a monotonic timestamp
  (microseconds since epoch). Never changes unless the local store
  is rebuilt.
- **No reuse on re-addition.** If a Proton message is removed from
  and re-added to the same mailbox (label remove → add), it gets a
  fresh UID. `uid_assignments` is keyed by `(mailbox_id,
  proton_message_id)` and we never reuse rows; instead we expunge
  the old row and assign a new UID.

## TLS reload

The IMAP server's `tls.Config.GetCertificate` callback returns
`*tls.Certificate` from a shared loader. The loader watches both
`cert_path` and `key_path` via `fsnotify` (and their parent
directory, since certbot atomically renames the file). On change, the
loader parses the new cert+key, validates they match (`tls.X509KeyPair`
will fail if not), and atomically swaps the held pointer. Active TLS
sessions continue with their negotiated cert; new ClientHello
handshakes get the new cert.

## SASL identity resolution

The PLAIN response carries `\0username\0password`. We split, treat
the username as `local@host`, look up the account by:

1. Match against `accounts.email` directly, OR
2. Match against an alias table (deferred to v0.2 — for now, account
   has exactly one primary email matching the OIDC user's expected
   alias).

Then verify the password against `accounts.imap_password_hash` via
bcrypt or Argon2id. Failure = identical "AUTHENTICATIONFAILED"
response regardless of cause.

## Performance considerations

- **FETCH BODY[] on big messages**: Proton requires a full body fetch
  + decrypt. We cache decrypted bodies in a small per-account LRU (by
  Proton message ID, configurable size, default 32 MiB). LRU evicts
  on size or TTL (5min).
- **SEARCH on body**: v0.1 supports only header-based SEARCH that
  resolves against local `messages` rows (subject, from, to, date,
  flags). Body search routes to Proton's search API in v0.2+.
- **EXPUNGE batching**: clients may delete many messages in one
  session; we batch the corresponding Proton operations.

## Open questions

- **Multi-mailbox message rendering**: IMAP-wise a message in 3
  labels appears in 3 mailboxes. Each appearance gets its own UID.
  This is correct but expensive (3× UID assignments per message). v1
  may switch to a "labels are virtual" model where `All Mail` is the
  canonical mailbox and `Labels/*` are virtual filtered views with
  the same UIDs. Tracked in deferred ADR-0011.
- **CONDSTORE / QRESYNC**: not in v0.1. Means clients RESYNC on
  reconnect, which is OK for the size of mailboxes we expect.

## References

- ADR-0007 (emersion/go-imap)
- ADR-0009 (TLS via disk)
- SPEC-0001 (Account Model)
- SPEC-0002 (Sync Worker — pubsub source)
- ADR-0010 (deferred — UID stability formalization)
- ADR-0011 (deferred — label↔folder mapping formalization)
