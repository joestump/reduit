-- +goose Up
-- Governing: ADR-0013 (secrets in OS keychain — the session UID is NOT a secret,
--   it is session state that identifies the go-proton-api session, so it belongs
--   in the store, not the keychain). SPEC-0007 (auth flow, Re-Auth path).
--
-- session_uid is the go-proton-api session UID captured at Login. Proton's
-- /auth/v4/refresh requires it to identify the session; resuming with an empty
-- UID yields 10013 "Invalid refresh token". It is NULL for pre-migration rows,
-- which the resume paths detect and surface as a re-add prompt.
ALTER TABLE mailboxes ADD COLUMN session_uid TEXT;

-- +goose Down
ALTER TABLE mailboxes DROP COLUMN session_uid;
