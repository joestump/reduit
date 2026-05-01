// Package smtpserver implements Reduit's SMTPS submission listener on
// top of `emersion/go-smtp`'s `Backend` and `Session` interfaces.
//
// This package owns:
//
//   - The TLS-only listener (port 465 by default). Plaintext SMTP
//     submission and STARTTLS-from-cleartext are NOT offered. The
//     `tls.Config.GetCertificate` callback is wired to the hot-
//     reloading cert loader from `internal/tlsloader` (ADR-0009), so
//     cert rotation does not require an SMTP server restart.
//
//   - SASL PLAIN authentication, and only PLAIN. The EHLO advertises
//     `AUTH PLAIN` and nothing else SASL-y. The same `accounts.imap_
//     password_hash` column backs both IMAP (SPEC-0003) and SMTP, so
//     a user has exactly one relay password.
//
//   - MAIL FROM authorization against the authenticated account's
//     primary alias. Multi-alias support per SPEC-0004 awaits the
//     sync worker populating a per-alias table — for now, the only
//     authorised sender address is the SASL identity itself.
//
//   - Recipient and message-size limits, advertised via EHLO `SIZE`.
//     The size cap is enforced DURING streaming via the dataReader
//     so a 1 GiB attempt fails fast rather than buffering 1 GiB
//     before rejection.
//
//   - Per-session lifetime tracking. A `Sessions` registry holds a
//     reference to every authenticated session indexed by account ID
//     so suspension calls can drop them within 1 second (the SPEC-
//     0004 SLA).
//
// What this package deliberately does NOT do (yet):
//
//   - The outbox handoff to Proton submission (deferred to issue
//     #22). After DATA completes, the body is logged + dropped and
//     the SMTP response is `250 OK` from a stub. Story #22 replaces
//     the stub with a per-account outbox worker that performs
//     encryption + Proton submission.
//   - Per-account outbox concurrency caps (deferred to #22).
//   - Sent-folder materialization (deferred to #22 + sync worker).
//
// Wiring of the listener into `cmd/reduit serve` is intentionally
// deferred until #21 + #22 merge — see the v0.2 consolidation PR.
//
// Governing: ADR-0007 (emersion/go-imap v2 + go-smtp), ADR-0009
// (TLS via on-disk cert files), SPEC-0004 (SMTP Submission Server).
package smtpserver
