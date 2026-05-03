# SPEC-0005 mockups — add-Proton-account wizard

High-fidelity reference mockups for the HTMX multi-step wizard that
guides a user through Proton account setup. Generated via the
`gemini-mockup` skill against Reduit's visual identity in `CLAUDE.md`
(dark mode, deep indigo `#4F46E5`, slate surfaces, Inter, DaisyUI 5,
Heroicons outlined, subtle alpine motif). Sample data uses
family-style names (Joe) per the project conventions.

These are **reference targets, not pixel-perfect specs** — the actual
implementation only has to satisfy the spec's `WHEN ... THEN ...`
scenarios under "Add-Proton-Account Wizard" in
[`docs/openspec/specs/admin-ui-flows/spec.md`](../../openspec/specs/admin-ui-flows/spec.md).

Issue: [#24](https://github.com/joestump/reduit/issues/24).

## Files

| File | Screen |
|---|---|
| [`24-wizard-step-1-credentials.png`](24-wizard-step-1-credentials.png) | Step 1 — Proton email + password (empty state, "Reduit never stores your password" explainer) |
| [`24-wizard-step-2-2fa.png`](24-wizard-step-2-2fa.png) | Step 2 — TOTP 6-digit code entry, attempt 1 of 3 |
| [`24-wizard-step-3-mailbox-passphrase.png`](24-wizard-step-3-mailbox-passphrase.png) | Step 3 — Mailbox passphrase (separate from login password) |
| [`24-wizard-step-4-label-and-sync.png`](24-wizard-step-4-label-and-sync.png) | Step 4 — Friendly account label, owner badge, "Begin initial sync now" toggle |
| [`24-wizard-step-5-success.png`](24-wizard-step-5-success.png) | Step 5 — Success card with live initial-sync progress |
| [`24-wizard-error-credentials-rejected.png`](24-wizard-error-credentials-rejected.png) | Step 1 error state — credentials rejected by Proton (rose alert + invalid password border) |
| [`24-wizard-error-2fa-timeout.png`](24-wizard-error-2fa-timeout.png) | Step 2 error state — TOTP code expired before verification, attempt 2 of 3 |

## Notes

- The 5-step indicator in the mockups (Credentials → Two-factor →
  Mailbox key → Label & sync → Done) is one possible visual; the spec
  itself only enumerates 3 functional steps + redirect. The extra
  "Label & sync" step is included here because the user-task scope
  for #24 explicitly asked for a label/sync surface. Implementers can
  collapse it into step 3 or the redirect target if they prefer.
- An older reference set lives at
  [`docs/openspec/specs/admin-ui-flows/mockups/`](../../openspec/specs/admin-ui-flows/mockups/)
  (`03-`, `04-`, `05-` covering credentials, TOTP, passphrase). They
  predate the 5-step indicator and a couple of palette refinements.
  They have not been regenerated in this PR — refresh them in a
  follow-up if the visual identity drifts further.

## Regenerating

Use the `gemini-mockup` skill with the same filename to overwrite
cleanly. The generator writes to a stable filename so reruns don't
fragment the index.
