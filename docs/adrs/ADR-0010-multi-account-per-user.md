# ADR-0010: Multi-Proton-Account Per User

- **Status:** proposed
- **Date:** 2026-05-02
- **Deciders:** Joe Stump

## Context and Problem Statement

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

The OIDC middleware shipped in #13 is already user-level — `Principal.Subject`
is the OIDC `sub` claim, decoupled from any account row. So the protocol
seam is already correct; the data model has to catch up.

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

## Considered Options

1. **Status quo: enforce 1:1.** Operators with multiple Proton
   accounts must register multiple OIDC identities. Rejected — see
   Context.
2. **Decouple user identity from account ownership.** Promote OIDC
   subject from a uniqueness key on `accounts` to an ownership
   attribute. A user (= OIDC subject) MAY own zero or more accounts.
3. **Introduce a normalized `users` table.** Row per OIDC subject;
   `accounts.user_id` foreign-keys to it; user-scoped attributes
   (display name, admin flag, preferences) move to the `users` row.
4. **Multi-OIDC-subject linking.** Allow a user to attach secondary
   OIDC identities to one Reduit "user" record. Solves a different,
   later problem; orthogonal to the multi-Proton-account need.

## Decision Outcome

**Chosen: option 2 — decouple user identity from account ownership,
with `owner_oidc_sub` carried as a column on `accounts`.**

Concretely:

- **User identity** is the OIDC `sub` claim, surfaced in-process as
  `Principal.Subject` (already shipped in #13). It is not a row in
  any table. Authentication establishes a user; it does not create
  or require an account.
- **Account identity** remains the existing UUIDv7 primary key on
  `accounts`. An account is one Proton mailbox.
- The `accounts` table gains an `owner_oidc_sub` column (text,
  not-null). It records the OIDC subject of the user who created the
  account.
- The current `oidc_subject UK` (uniqueness constraint on a single
  OIDC subject) is **dropped**.
- A new uniqueness constraint replaces it: `UNIQUE (owner_oidc_sub,
  proton_user_id)`. A given user MUST NOT add the same Proton
  account twice. (Two distinct users could in theory add the same
  Proton mailbox; that's not the system's concern — access is gated
  by per-account relay credentials.)
- Account ownership is **immutable**. Reassigning an account from
  one OIDC subject to another is out of scope; if it ever happens,
  it is a deliberate operator-tool action with its own audit story
  and is not part of this ADR.
- A user MAY have **zero accounts** in steady state. This is the
  state immediately after first-time OIDC login, before any
  add-account wizard run.
- First-run OIDC login MUST establish only the user identity (its
  admin status is decided by the allowlist as before). Account
  creation MUST be a separate, deliberate action through the
  add-account wizard.
- Admin status remains a user-level attribute, sourced from
  `OIDC_ADMIN_SUBS`. The current per-account `is_admin` boolean
  becomes a denormalized cache; the source of truth is the
  allowlist matched against the request's `Principal.Subject`. (See
  Consequences for the schema-migration follow-up.)
- The relay layer (IMAP/SMTP SASL) is unchanged. SASL still selects
  one account; a mail-client connection still targets exactly one
  mailbox. How many accounts the human owns is invisible to the
  protocol.

We do not introduce a `users` table (option 3). The single column
`owner_oidc_sub` is sufficient at the target scale (≤50 accounts per
host, ≤a dozen distinct humans). User-scoped attributes Reduit needs
today are all derivable from the OIDC ID token (display name, email)
or from environment configuration (admin allowlist). If user-row
attributes become a real concern later (per-user preferences,
secondary-OIDC linking), a `users` table is a non-breaking forward
migration: backfill from `DISTINCT owner_oidc_sub` and add the FK.

This ADR refines ADR-0002 in one specific way: the row-level
isolation predicate `WHERE account_id = ?` remains the core data-layer
discipline, but ownership filtering at the dashboard / management
layer becomes `WHERE owner_oidc_sub = ?`. ADR-0002's architectural
posture (single process, multi-tenant, per-account state) is
unchanged.

### Consequences

**Positive**

- Operators with multiple Proton accounts (the project owner, and
  almost certainly future self-hosters) get the natural workflow:
  log in once, see all your mailboxes, add another.
- The OIDC middleware (#13, just merged) requires no rework — it's
  already user-level.
- The add-account wizard (#24) becomes naturally repeatable; "add
  another" is the same flow, with no special-case for the second
  account.
- The admin model gets cleaner: admin is unambiguously a property of
  the human, not a property of one of their mailbox rows.
- Forward path to a `users` table is non-breaking — backfill from
  `owner_oidc_sub` whenever it becomes worth doing.

**Negative**

- Schema migration required: drop the OIDC-sub uniqueness, add the
  `owner_oidc_sub` column with backfill, add the
  `(owner_oidc_sub, proton_user_id)` uniqueness. Tracked as a
  follow-up issue (see below).
- The denormalized `accounts.is_admin` cache must be kept consistent
  with the allowlist on every login, or removed in favor of a
  request-time check against `Principal.Subject ∈ OIDC_ADMIN_SUBS`.
  Recommendation: remove the column; admin is a user attribute. Left
  to the schema-migration follow-up to land cleanly.
- Dashboard and admin-management UX need updates (#25, plus the
  admin all-accounts table) to group by owner.

**Neutral**

- Per-account encryption (ADR-0003), per-account sync workers
  (SPEC-0002), per-account relay credentials (SPEC-0003 / SPEC-0004),
  and per-account MCP token scope (SPEC-0006) are all unchanged. They
  were never bound to OIDC subject; they were always bound to
  `account_id`.
- The `account_id` foreign-key discipline from ADR-0002 stays the
  load-bearing isolation primitive for all per-account state.

### Implementation impact map (issues)

| Issue | Status | Impact |
|---|---|---|
| #13 (OIDC + session middleware) | merged | None. `Principal.Subject` is already user-level. |
| #23 (OIDC login + first-run bootstrap) | open | First-run bootstrap stops creating an account. It establishes the user identity, marks them admin if the allowlist is empty (the "first OIDC login becomes initial admin" rule), and routes to the add-account wizard. |
| #24 (add-Proton-account wizard) | open | Wording: "Add a Proton account" (not "your"). Repeatable: the same flow runs whenever the user wants to add another. Step 3 success returns to the dashboard, which now shows N accounts. |
| #25 (account dashboard + SSE) | open | Dashboard scopes to "your accounts" (`WHERE owner_oidc_sub = ?`) and renders one card per owned account, plus an "Add another" CTA. Empty state (zero accounts) routes the user into the wizard. Admin view groups all accounts by owner. |
| #26 (per-user creds rotation + admin actions) | open | Rotation is already account-scoped — no behavior change. Admin actions (suspend, delete) gain a "scoped to one account" framing (already true) and the admin all-accounts view groups by owner. |
| schema migration | new | Drop `oidc_subject` UK; add `owner_oidc_sub TEXT NOT NULL`; backfill from existing rows; add `UNIQUE (owner_oidc_sub, proton_user_id)`; remove or deprecate `is_admin`. Tracked as a separate issue. |

The schema-migration follow-up issue lands the actual goose migration
plus the data-layer query updates (`WHERE owner_oidc_sub = ?` on
list-my-accounts paths).

## Pros and Cons of the Options

### Decouple user from account, no `users` table (chosen)

- **Good:** Minimal schema delta; ownership is a single column.
- **Good:** No new join on the hot path. List-my-accounts is one
  predicate.
- **Good:** Forward path to a `users` table is non-breaking.
- **Bad:** Repeated string column for the OIDC subject; a `users`
  table would normalize. At ≤50-account scale this is irrelevant.

### Normalized `users` table

- **Good:** Clean home for user-level attributes.
- **Good:** Foreign-key integrity on ownership.
- **Bad:** Extra join on every list-my-accounts query.
- **Bad:** No real attributes to store yet — the table would be
  `(id, oidc_subject)` for v1, which is just a wrapper.
- **Bad:** Larger surface to migrate now for speculative future
  benefit.

### Multi-OIDC-subject linking

- **Good:** Solves the "one human, multiple IdP identities" use
  case.
- **Bad:** Doesn't solve the actual problem in front of us (one
  IdP identity, multiple Proton accounts).
- **Bad:** Significantly larger spec surface (identity merge,
  primary-vs-secondary semantics, IdP trust model).

### Status quo (1:1)

- **Good:** No change.
- **Bad:** Forces operators with multiple Proton accounts into
  awkward workarounds.

## References

- ADR-0002 (multi-tenant data model) — refines the per-OIDC-sub
  binding; the row-level `account_id` isolation predicate is
  unchanged.
- ADR-0004 (OIDC control-plane auth) — `Principal.Subject` is the
  user identity surface; this ADR formalizes the implication.
- ADR-0006 (SQLite store) — schema migration follows the goose
  conventions established there.
- SPEC-0001 (Account Model) — amended in the same PR as this ADR.
- SPEC-0005 (Admin UI Flows) — amended in the same PR as this ADR.
- SPEC-0006 (MCP Tool Surface) — confirmed unchanged (MCP tokens
  are already account-scoped).
