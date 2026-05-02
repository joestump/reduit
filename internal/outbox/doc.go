// Package outbox owns the per-account submission pipeline that takes
// an SMTP-accepted message, classifies its recipients (Proton-internal,
// external-with-key, external-no-key), produces the matching Proton
// message-package-set via go-proton-api, and submits it.
//
// Lifecycle:
//
//   - One Manager per process (typically constructed by the composition
//     root in cmd/reduit-server).
//   - Workers are minted lazily on first Submit per account and torn
//     down by Manager.Shutdown. Each worker owns a per-account
//     concurrency semaphore (default 4 in-flight sends).
//   - Submit is synchronous: it blocks until the upstream Proton call
//     succeeds, fails, or the configured submission timeout elapses.
//
// Synchronous-first is the SPEC-0004 contract. The SMTP DATA handler
// embeds the Submit call in its response path so a 250 OK reflects an
// actual Proton-side accept, not a queued-locally maybe.
//
// Submission timeout: when the upstream call has not returned within
// the configured deadline (default 60s, env REDUIT_SMTP_SUBMIT_TIMEOUT)
// the synchronous waiter returns ErrSubmissionTimedOut and the SMTP
// layer responds 451 4.4.7. Reduit does NOT run a server-side retry
// loop after a timeout — the sender's MTA re-attempting the SMTP
// submission per RFC 5321 is the canonical recovery path. The
// in-flight upstream call is left to unwind on its own (its next
// ctx-aware call observes the cancelled subCtx and returns); a best-
// effort audit row lands in `outbox_pending` for operator visibility.
//
// Encryption-mode selection (security-critical, see SelectMode for the
// full decision table):
//
//   - Proton-internal recipient + key returned → PGPInlineScheme to
//     the recipient's public key, signed by sender.
//   - External recipient + no key → ClearScheme (cleartext relay).
//   - External recipient + key returned → PGPInlineScheme (mirrors
//     Proton's "encrypt to outside" preference).
//   - Key-lookup error (network, 5xx, parse failure) → fail closed:
//     the entire submission is rejected. Treating a key-lookup error
//     as "fall through to cleartext" would silently downgrade a
//     Proton-internal recipient to a cleartext send. We reject
//     instead.
//
// Governing: SPEC-0004 REQs "Outbox Handoff and Synchronous
// Confirmation", "Encryption Pipeline", "Sent Folder Materialization",
// "Per-Account Outbox Concurrency Limit"; ADR-0001.
package outbox
