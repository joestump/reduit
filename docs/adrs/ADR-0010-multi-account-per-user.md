# ADR-0010: Multi-Proton-Account Per User

- **Status:** accepted
- **Date:** 2026-05-02
- **Deciders:** Joe Stump

## Context and Problem Statement

> **Post-acceptance note (2026-06-11):** This decision has shipped. The
> users/accounts 1:N split described below is implemented (a `users`
> table sourced from OIDC, `accounts.user_id` FK, admin status computed
> at session-bind time), and **SPEC-0001 has since been updated to encode
> that 1:N model.** The 1:1 OIDC-subject↔account framing in the next
> paragraph is the *pre-decision* problem statement preserved for the
> historical record — it is no longer what SPEC-0001 says.

ADR-0002 (multi-tenant data model) and SPEC-0001 (Account Model) both
encode an implicit 1:1 binding between an OIDC subject and a Proton
mailbox: every "account" row is keyed by `oidc_subject UK`, and SPEC-0001
explicitly mandates "one OIDC subject maps to one account" with a
storage-layer uniqueness constraint to enforce it.

That assumption is wrong for a real Reduit operator. The project owner
has two Proton accounts (personal + family) and expects to surface both
through a single Pocket ID identity. The current design forces him to
either:

1. Run two parallel Pocket ID identities (`joe-personal`, `joe-family`)
   and re-authenticate to switch — operationally hostile, and the
   admin allowlist (`OIDC_ADMIN_SUBS`) has to list both.
2. Run two Reduit deployments — defeats the multi-tenant value
   proposition that ADR-0002 was written to deliver.

The multi-user framing in `CLAUDE.md` (Joe + Hannah + Maya + Sage) is
about **multiple humans on one Reduit**, not about each human being
limited to one Proton account. We need both: N humans, and each human
MAY own M Proton accounts.

The OIDC middleware shipped in #13 (#55) is already user-level —
`Principal.Subject` is the OIDC `sub` claim, decoupled from any
account row. So the protocol seam is already correct; the data model
has to catch up.

A second pressure point surfaced during round-1 review: the
"every account row carries an OIDC subject" shape conflates two
genuinely different things — an authenticated identity (sourced from
OIDC) and a Proton mailbox configuration (sourced from Proton). A
half-step refactor that just adds an `owner_oidc_sub` column to
`accounts` postpones the conflation rather than resolving it. Admin
status, account count = 0, and "look up a user without touching the
Proton-mailbox table" all want a first-class user row.

The project has not shipped. There are no production deployments and
no users to migrate. This means we can pick the cleanest shape and
write the migrations as if from scratch.

## Decision Drivers

- Project owner has two Proton accounts and wants both reachable
  through one Pocket ID identity.
- The 1:1 OIDC-sub-to-account binding contradicts the operator's
  actual workflow and forces operationally awkward workarounds.
- The OIDC middleware is already user-level; `Principal.Subject` is
  not bound to an account row.
- The relay protocol seam is already account-scoped: SASL
  (IMAPS/SMTPS) selects exactly one mailbox per session via the
  `account@host` username form. Mail clients are unaware of the
  human behind the mailbox.
- Admin gating today reads from the OIDC subjects allowlist, not
  from per-account rows. That layer is already user-level.
- Self-hosting use cases (a parent managing personal + family Proton
  accounts; a team admin managing a shared role-account alongside
  their own) generalize to "one human, multiple mailboxes."
- "User" and "account" are different things in the problem domain
  (an OIDC-authenticated human vs. a Proton mailbox row). A schema
  that conflates them propagates the conflation into every query.
- The project has not shipped — no migration / backfill compatibility
  is required. The cleanest shape wins.

## Considered Options

1. **Status quo: enforce 1:1.** Operators with multiple Proton
   accounts must register multiple OIDC identities. Rejected — see
   Context.
2. **Half-step: add `owner_oidc_sub` column on accounts.** Promote
   OIDC subject from a uniqueness key on `accounts` to an ownership
   attribute. A user (= OIDC subject) MAY own zero or more accounts.
   No `users` table. Rejected on the deeper-direction call: postpones
   the conflation between "OIDC identity" and "Proton mailbox row";
   admin status and zero-account users remain awkward.
3. **Full split: introduce a `users` table sourced from OIDC.**
   Row per OIDC subject; `accounts.user_id` foreign-keys to it;
   user-scoped attributes (display name, email, last login) live on
   the user row. Admin status is a derived attribute computed at
   session-bind time from the allowlist, NOT stored on the user row.
4. **Multi-OIDC-subject linking.** Allow a user to attach secondary
   OIDC identities to one Reduit "user" record. Solves a different,
   later problem; orthogonal to the multi-Proton-account need.

## Decision Outcome

**Chosen: option 3 — full split. Introduce a `users` table sourced
from OIDC; accounts foreign-key to users 1:N; admin status is computed
at request time from the OIDC subjects allowlist.**

Concretely:

- **User identity** is a row in a new `users` table, keyed by an
  internal UUIDv7 `id` and uniquely constrained on `oidc_subject`.
  The user row is created on first successful OIDC login. Optional
  attributes from the ID token (`email`, `display_name`) MAY be
  stored. `created_at` and `last_login_at` are tracked.
- **Account identity** remains a row in `accounts` keyed by UUIDv7.
  An account is one Proton mailbox configuration. The `accounts`
  table gains a `user_id` foreign key referencing `users(id)` with
  `ON DELETE CASCADE` (user removal cascades to accounts; see
  Lifecycle). The `oidc_subject` column on `accounts` is **removed**.
  The `is_admin` column on `accounts` is **removed**.
- A new uniqueness constraint on `accounts`: `UNIQUE (user_id,
  proton_user_id)`. A given user MUST NOT add the same Proton
  account twice. (Two distinct users could in theory each add a row
  for the same Proton mailbox; that's not the system's concern —
  access is gated by per-account relay credentials.)
- Account ownership is **immutable**. Reassigning an account from
  one user to another is out of scope; if it ever happens, it is a
  deliberate operator-tool action with its own audit story and is
  not part of this ADR.
- A user MAY have **zero accounts** in steady state. This is the
  state immediately after first-time OIDC login, before any
  add-account wizard run, and is a first-class supported state — the
  dashboard renders an empty-state CTA, the user is a regular
  authenticated user, no special-casing.
- **Admin status is computed, not stored.** At session-bind time
  (i.e., on every successful OIDC login), the system checks whether
  `Principal.Subject ∈ OIDC_ADMIN_SUBS` and tags the session
  accordingly. The user row carries no `is_admin` column; the
  account row carries no `is_admin` column. The allowlist is the
  single source of truth, set at startup via env var. (If allowlist
  hot-reload is wanted later it can be added without a schema
  change.)
- **First OIDC login does NOT auto-promote to admin.** A regular
  user is created. Admin requires the OIDC subject to be in
  `OIDC_ADMIN_SUBS`. If no admin has ever authenticated AND the
  allowlist has zero entries, the dashboard surfaces an explicit
  operator-configuration warning instructing the operator to set
  `OIDC_ADMIN_SUBS` and re-authenticate. The system never silently
  promotes anyone.
- The relay layer (IMAP/SMTP SASL) is unchanged. SASL still selects
  one account; a mail-client connection still targets exactly one
  mailbox. How many accounts the human owns is invisible to the
  protocol.

This ADR refines ADR-0002 in one specific way: "tenant" now means
**user**, not "account". One tenant (user) owns many accounts
(Proton mailboxes). The row-level isolation predicate `WHERE
account_id = ?` remains the load-bearing data-layer discipline for
per-account state; ownership filtering at the dashboard / management
layer becomes `WHERE user_id = ?`. ADR-0002's architectural posture
(single process, multi-tenant, per-account state) is unchanged in
substance.

### Migration approach

The project has not shipped. There is no production data to preserve
and no backwards-compatibility window to honor. The migration
approach is a **greenfield rewrite of the affected migrations**:

- The existing migration that created `accounts` with `oidc_subject`
  and `is_admin` columns is rewritten to omit those columns.
- A new earlier migration creates the `users` table.
- The `accounts` migration adds a `user_id` column with a foreign
  key to `users(id)` and `ON DELETE CASCADE`.
- Indexes on `users(oidc_subject)` (UNIQUE), `accounts(user_id)`,
  and `accounts(user_id, proton_user_id)` (UNIQUE) are created in
  the same migration that creates each respective table.
- No `up`-style data backfill is needed; the schema is ratcheted
  forward in place.

### Consequences

**Positive**

- Operators with multiple Proton accounts (the project owner, and
  almost certainly future self-hosters) get the natural workflow:
  log in once, see all your mailboxes, add another.
- The OIDC middleware (#55) requires no rework at the protocol
  seam — `Principal.Subject` is already user-level. The downstream
  refactor is to bind sessions to a `user_id` rather than (or in
  addition to) an `account_id` (see below).
- The add-account wizard becomes naturally repeatable; "add
  another" is the same flow, with no special-case for the second
  account.
- The admin model gets cleaner: admin is unambiguously a property of
  the human, computed from the allowlist on every login. There is
  no risk of a stored boolean drifting from the allowlist.
- "User exists with zero accounts" is a first-class supported
  state — no awkward sentinel rows, no auto-creation of a stub
  account.
- The `users` table is the natural home for future user-level
  attributes (preferences, secondary-OIDC linking, per-user audit
  trail).

**Negative**

- The `internal/auth/` foundation that just merged in #55
  (`session_owners` linking sessions to `account_id`,
  `RevokeSessionsForAccount`) needs a downstream refactor: link
  `session_owners` to `user_id` instead (or in addition);
  `RevokeSessionsForUser` becomes the primary revocation primitive.
  Account-level revocation MAY still make sense for niche admin
  actions (e.g., "an admin suspended one of my accounts" — only
  sessions bound to that one account need to drop). Both keys can
  coexist on `session_owners` if useful; pick during the refactor.
- The migrations that landed before this ADR will be **rewritten
  in place** rather than supplemented. This is acceptable because
  the project has not shipped.
- Dashboard and admin-management UX need updates (tracked in #25,
  the admin all-accounts table, etc.) to scope by `user_id` and
  group by user.

**Neutral**

- Per-account encryption (ADR-0003), per-account sync workers
  (SPEC-0002), per-account relay credentials (SPEC-0003 / SPEC-0004),
  and per-account MCP token scope (SPEC-0006) are all unchanged.
  They were never bound to OIDC subject; they were always bound to
  `account_id`.
- The `account_id` foreign-key discipline from ADR-0002 stays the
  load-bearing isolation primitive for all per-account state.
- The OIDC subjects allowlist (`OIDC_ADMIN_SUBS`) remains the
  admin source of truth; nothing about that contract changes.

### Implementation impact map (issues)

| Issue | Status | Impact |
|---|---|---|
| #13 (OIDC + session middleware) | merged in #55 | Protocol seam unchanged; downstream refactor needed to point `session_owners` at `user_id` and add `RevokeSessionsForUser`. Tracked as a separate companion issue. |
| #23 (OIDC login + first-run bootstrap) | open | First-run creates a regular `users` row only — no admin promotion, no account creation. Admin gating reads `OIDC_ADMIN_SUBS` at session-bind time. Operator-config warning surfaces when the allowlist is empty AND no admin has ever logged in. |
| #24 (add-Proton-account wizard) | open | Wording: "Add a Proton account" (not "your"). Repeatable: the same flow runs whenever the user wants to add another. The wizard creates the new `accounts` row with `user_id` set to the authenticated user. |
| #25 (account dashboard + SSE) | open | Dashboard scopes to "your accounts" (`WHERE user_id = ?`) and renders one card per owned account, plus an "Add another" CTA. Empty state (zero accounts) routes the user into the wizard or renders the explicit empty-state card. Admin view groups all accounts by user (display-friendly: by user email or display name, with `oidc_subject` available on hover/expand). |
| #26 (per-user creds rotation + admin actions) | open | Rotation is already account-scoped — no behavior change. Admin actions (suspend, delete) gain a "scoped to one account" framing (already true). Admin all-accounts view groups by user. |
| schema rewrite | new (#58 retargeted) | Greenfield rewrite of existing migrations: create `users`; create `accounts` with `user_id` FK + `(user_id, proton_user_id)` UK; drop `oidc_subject` and `is_admin` from `accounts` (never land them in the rewritten migration). |
| auth-foundation refactor | new companion issue | Retarget `session_owners.account_id` → `session_owners.user_id` (or add both); add `RevokeSessionsForUser`; move admin-allowlist resolution into the session-bind path; tests updated for the new shape. |

The schema-rewrite follow-up lands the actual goose migration plus
the data-layer query updates (`WHERE user_id = ?` on list-my-accounts
paths). The auth-foundation refactor lands the changes to the
package merged in #55.

## Pros and Cons of the Options

### Full split: `users` table sourced from OIDC (chosen)

- **Good:** Clean separation between "OIDC-authenticated identity"
  and "Proton-mailbox row" — matches the actual problem domain.
- **Good:** Admin is unambiguously a user-level computed attribute;
  no per-account boolean to drift.
- **Good:** Zero-account users are first-class — no sentinel rows.
- **Good:** Foreign-key integrity on ownership; cascade delete is
  natural.
- **Good:** Future user-level attributes have a home (preferences,
  secondary-OIDC, audit).
- **Bad:** Extra join on every list-my-accounts query (one indexed
  lookup; negligible at target scale).
- **Bad:** The auth foundation in #55 needs a downstream refactor.

### Half-step: `owner_oidc_sub` column on accounts (rejected)

- **Good:** Minimal schema delta; ownership is a single column.
- **Good:** No new join on the hot path.
- **Bad:** Postpones the conflation between "OIDC identity" and
  "Proton mailbox row" — every list query still has to filter on a
  string column carrying meaning that belongs in a different table.
- **Bad:** No row exists for a "user with zero accounts" — the
  state is implicit and leaks into every query.
- **Bad:** Admin status doesn't have a natural home; if added it
  duplicates the allowlist, if not added the read path is awkward.
- **Bad:** Future user-level attributes have nowhere to land
  without another migration.

### Multi-OIDC-subject linking (rejected, orthogonal)

- **Good:** Solves the "one human, multiple IdP identities" use
  case.
- **Bad:** Doesn't solve the actual problem in front of us (one
  IdP identity, multiple Proton accounts).
- **Bad:** Significantly larger spec surface (identity merge,
  primary-vs-secondary semantics, IdP trust model). A `users` table
  is a precondition for this anyway, so the chosen option leaves it
  on the table for later.

### Status quo (1:1) (rejected)

- **Good:** No change.
- **Bad:** Forces operators with multiple Proton accounts into
  awkward workarounds.

## References

- ADR-0002 (multi-tenant data model) — refined: "tenant" now means
  **user**, not "account". The row-level `account_id` isolation
  predicate is unchanged.
- ADR-0004 (OIDC control-plane auth) — `Principal.Subject` is the
  OIDC `sub` claim and is the natural-key for the `users` table.
- ADR-0006 (SQLite store) — schema migration follows the goose
  conventions established there.
- SPEC-0001 (Account Model) — restructured around two entities
  (User, Account) in the same PR as this ADR.
- SPEC-0005 (Admin UI Flows) — first-run bootstrap and dashboard
  reworked in the same PR.
- SPEC-0006 (MCP Tool Surface) — selector-precedence and
  authz-enumeration-oracle hardening in the same PR.
