-- +goose Up
-- +goose StatementBegin

-- Governing: ADR-0003 (master-key envelope encryption at rest),
--            ADR-0001 (go-proton-api session UID is REQUIRED by
--                /auth/v4/refresh on restart),
--            SPEC-0001 REQ "Encrypted Secret Storage"
--                (the Proton session UID is a credential-adjacent secret;
--                it is sealed under the per-account data key, never stored
--                in plaintext and never logged),
--            SPEC-0002 REQ "One Worker Per Active Account"
--                (persisting the UID lets the daemon re-auth + re-unlock
--                each active account on boot via protonlive.ReUnlock).
--
-- #28 added the per-account live unlocked proton.Client registry +
-- ReUnlock, but boot re-unlock was SKIPPED because the ephemeral Proton
-- *session UID* was not persisted: the wizard captured auth.UID at login
-- and discarded it, keeping only auth.UserID (the persistent
-- proton_user_id) plus the sealed refresh token and mailbox passphrase.
-- go-proton-api's /auth/v4/refresh needs the session UID, so a fresh
-- process could not re-auth from the refresh token alone. This column
-- closes that gap (#34): the wizard now seals auth.UID here at commit
-- time, and protonlive.Lifecycle re-unlocks each active account on boot.
--
-- Nullable BLOB: existing accounts created before this migration have no
-- sealed UID. OpenSessionUID returns ErrSecretNotPresent for a NULL/empty
-- column, which protonlive.Lifecycle treats as the pre-existing
-- "skip boot re-unlock, log once at WARN" missing-UID path -- so older
-- accounts keep working (their sync worker still runs; only boot body
-- decryption is degraded until the operator re-runs the wizard, which
-- both registers a live client AND seals the UID for next boot).

ALTER TABLE accounts ADD COLUMN session_uid_ciphertext BLOB;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- SQLite supports DROP COLUMN as of 3.35; modernc.org/sqlite ships a
-- recent enough engine for this to round-trip cleanly in tests.
ALTER TABLE accounts DROP COLUMN session_uid_ciphertext;
-- +goose StatementEnd
