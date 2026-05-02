# SPEC-0005 mockups

High-fidelity reference renders for the SPEC-0005 admin UI flows
(`docs/openspec/specs/admin-ui-flows/`). Generated via the
`gemini-mockup` skill against Reduit's visual identity (see project
`CLAUDE.md` § Visual Identity). These are reference targets, not
pixel-perfect specifications — implementation may diverge so long
as the SPEC-0005 requirements are met. Sample data uses family-style
names (Joe, Hannah, Maya, Sage Stump) per the project convention.

Filenames are stable; regenerating with the same name overwrites
cleanly.

## Issue #24 — add-Proton-account wizard

Tracked in [#24](https://github.com/joestump/reduit/issues/24).
HTMX multi-step wizard guiding the user through Proton account
setup. Spec: "Add-Proton-Account Wizard" requirement in
[`docs/openspec/specs/admin-ui-flows/spec.md`](../../openspec/specs/admin-ui-flows/spec.md).

| File | Screen |
|---|---|
| [`24-wizard-step-1-credentials.png`](24-wizard-step-1-credentials.png) | Step 1 — Proton email + password (empty state, "Reduit never stores your password" explainer) |
| [`24-wizard-step-2-2fa.png`](24-wizard-step-2-2fa.png) | Step 2 — TOTP 6-digit code entry, attempt 1 of 3 |
| [`24-wizard-step-3-mailbox-passphrase.png`](24-wizard-step-3-mailbox-passphrase.png) | Step 3 — Mailbox passphrase (separate from login password) |
| [`24-wizard-step-4-label-and-sync.png`](24-wizard-step-4-label-and-sync.png) | Step 4 — Friendly account label, owner badge, "Begin initial sync now" toggle |
| [`24-wizard-step-5-success.png`](24-wizard-step-5-success.png) | Step 5 — Success card with live initial-sync progress |
| [`24-wizard-error-credentials-rejected.png`](24-wizard-error-credentials-rejected.png) | Step 1 error state — credentials rejected by Proton (rose alert + invalid password border) |
| [`24-wizard-error-2fa-timeout.png`](24-wizard-error-2fa-timeout.png) | Step 2 error state — TOTP code expired before verification, attempt 2 of 3 |

### Notes for the implementer

- The 5-step indicator in the mockups (Credentials → Two-factor →
  Mailbox key → Label & sync → Done) is one possible visual; the spec
  itself only enumerates 3 functional steps + redirect. The extra
  "Label & sync" step is included because #24's user-task scope
  explicitly asked for a label/sync surface. Implementers can
  collapse it into step 3 or the redirect target if they prefer.
- An older reference set lives at
  [`docs/openspec/specs/admin-ui-flows/mockups/`](../../openspec/specs/admin-ui-flows/mockups/)
  (`03-`, `04-`, `05-` covering credentials, TOTP, passphrase). They
  predate the 5-step indicator and a couple of palette refinements.
  Refresh them in a follow-up if visual identity drifts further.

## Issue #25 — account dashboard + SSE sync status

Tracked in [#25](https://github.com/joestump/reduit/issues/25).
Covers the SPEC-0005 REQs "Account Dashboard" and "Sync Status via
SSE", including multi-user, single-account, error, and empty
states.

| File | Screen |
|---|---|
| [`25-dashboard-multi-account-healthy.png`](25-dashboard-multi-account-healthy.png) | Multi-account dashboard, 4 family accounts, all healthy |
| [`25-dashboard-syncing-active.png`](25-dashboard-syncing-active.png) | One account actively syncing — amber LIVE accent + progress bar (SSE-driven) |
| [`25-dashboard-error-auth-expired.png`](25-dashboard-error-auth-expired.png) | One account in error state — rose "Auth expired" badge + re-authenticate CTA |
| [`25-dashboard-empty-first-run.png`](25-dashboard-empty-first-run.png) | Post-OIDC-login empty state — hero card prompting "Add your first Proton account" |
| [`25-dashboard-single-account-focus.png`](25-dashboard-single-account-focus.png) | Single-account focus view — metadata + live SSE sync events feed |

Browser chrome shows `https://reduit.family.tld/<route>`.

## Regenerating

Invoke the `gemini-mockup` skill with the same filename — it
overwrites cleanly. Run a scan-in-arrears whenever the visual
identity in `CLAUDE.md` changes; see the skill's `SKILL.md` for the
workflow.
