// Package proton is reduit's seam over the Proton Mail API.
//
// It wraps github.com/ProtonMail/go-proton-api (ADR-0001) behind a small,
// reduit-owned interface — Client — that the auth (SPEC-0007), sync
// (ADR-0014), and send (ADR-0020) layers depend on. The interface is
// expressed entirely in reduit domain types (no go-proton-api types leak
// across it), so those layers can be unit-tested against the in-package
// Fake without a live Proton account, and so an upstream API break is
// absorbed here rather than rippling through the codebase.
//
// What this package owns:
//   - Auth: SRP password auth + a TOTP 2FA state machine (SPEC-0007 REQ
//     "SRP and 2FA Handling"); mailbox-passphrase OpenPGP key unlock
//     (SPEC-0007 REQ "Mailbox Passphrase Capture and Key Unlock").
//   - Session: refresh-token rotation and the immutable proton_user_id
//     (SPEC-0007 REQ "Re-Auth Flow", "Multi-Mailbox Add").
//   - Events: cursor-based bootstrap + tail over the Proton event stream
//     for incremental sync (ADR-0014).
//   - Decrypt: message/attachment decryption with the unlocked keyring
//     (ADR-0014 "Decrypt in the pipeline").
//   - Send: the outbound submission surface (ADR-0020).
//
// What it deliberately does NOT own: the CLI prompt flow (#86), the sync
// loop and cache writes (#88, ADR-0014), and secret storage (the keychain,
// ADR-0013). Secrets enter and leave this package only as []byte arguments
// and return values; nothing here writes to disk, logs, or the database.
//
// Testability boundary. go-proton-api's network calls need a live server,
// so the concrete implementation (see gpa_client.go) is kept thin: it
// translates to/from upstream types and delegates straight to the
// *gpa.Client. The wrapper's own non-network logic — 2FA classification,
// error classification, event-cursor handling, and outgoing-message
// validation/composition — lives in pure helpers (auth.go, errors.go,
// events.go, send.go) that are unit-tested directly. The untestable
// live-server work (the actual HTTPS round-trips, recipient public-key
// resolution for send packaging) is pushed to the edge.
//
// Governing: ADR-0001 (go-proton-api as the Proton client), ADR-0014
// (local sync-and-cache / event stream), ADR-0020 (outbound send),
// SPEC-0007 (onboarding & Proton auth).
package proton
