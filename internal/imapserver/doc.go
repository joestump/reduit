// Package imapserver implements Reduit's IMAPS listener on top of
// `emersion/go-imap` v2's `Backend` and `Session` interfaces.
//
// This package owns:
//
//   - The TLS-only listener (port 993 by default). Cleartext IMAP and
//     STARTTLS are NOT offered. The `tls.Config.GetCertificate`
//     callback is wired to the hot-reloading cert loader from
//     `internal/tlsloader` (ADR-0009), so cert rotation does not
//     require an IMAP server restart.
//
//   - SASL PLAIN authentication, and only PLAIN. The `CAPABILITY`
//     response advertises `AUTH=PLAIN` and nothing else SASL-y. The
//     IMAP `LOGIN` command is also routed through the same backend
//     verifier so external code paths cannot bypass the audit log.
//
//   - Per-session lifetime tracking. A `Sessions` registry holds a
//     reference to every authenticated session indexed by account ID
//     so future suspension/deletion calls can drop them with
//     `* BYE Account suspended` within 1 second.
//
// What this package deliberately does NOT do (yet):
//
//   - UID stability / folder hierarchy / Proton system-folder mapping
//     (deferred to issue #19).
//   - IDLE live updates from the sync worker (deferred to issue #20).
//   - Mailbox content of any kind. `LIST` returns an empty mailbox
//     set; `SELECT` rejects every name with `NO Mailbox does not
//     exist`.
//
// Wiring of the listener into `cmd/reduit serve` is intentionally
// deferred until #15 / #18 / #21 all merge — see the v0.2
// consolidation PR.
//
// Governing: ADR-0007 (emersion/go-imap v2 + go-smtp), ADR-0009
// (TLS via on-disk cert files), SPEC-0003 (IMAP Server).
package imapserver
