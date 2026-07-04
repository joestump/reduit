# SPEC-0013: Interactive Auth UI

## Overview

`reduit auth add` and `reduit auth refresh` gain a full-screen-style Bubble Tea
presentation for interactive terminals: focused `bubbles/textinput` fields
(masked for secrets, echoed for the TOTP), an activity spinner during the
network round-trips, and the run's log lines streaming below a pinned header —
reusing the pinned-header-over-scrolling-logs pattern of SPEC-0012. The auth
network sequence (`Login → SubmitTOTP → Unlock`, and the refresh cheap-resume
escalation) is unchanged and shared with the non-interactive path; the TUI only
collects input and shows progress. Non-interactive runs (piped stdin, automation,
tests) keep today's plain prompter output exactly. The expected, benign
`403 / 9101` scope diagnostic emitted during a refresh cheap-resume renders as an
informational notice rather than an error.

Decided in ADR-0026 (interactive auth TUI via Bubble Tea). Builds on ADR-0023
(sync progress UI — the pinned-header/log-injection pattern and TTY gate reused
here), ADR-0025 (the TUI design language), ADR-0022 (charmbracelet/log — the log
stream the notice handler wraps), ADR-0021 (Bridge-client app-version — the
human-verification error the login step maps), and SPEC-0007 (onboarding & auth —
the semantics and the No Secret Leakage invariant this presentation must hold).

Governing: ADR-0026, ADR-0023, ADR-0025, SPEC-0007.

## Requirements

### Requirement: Bubble Tea Auth Input

In an interactive terminal, `reduit auth add` and `reduit auth refresh` SHALL
collect the password, optional TOTP code, and mailbox passphrase with focused
`bubbles/textinput` fields inside a Bubble Tea program, styled in the TUI design
language (ADR-0025). Secret fields (password, passphrase) SHALL mask their input;
the TOTP field, which is not a secret, MAY echo.

#### Scenario: Secret fields do not echo

- **WHEN** the password or mailbox passphrase field is focused and the operator
  types
- **THEN** the typed characters SHALL NOT be rendered in the clear (the field
  masks them), preserving SPEC-0007 "No Secret Leakage" in the TUI path

#### Scenario: Fields appear in the auth sequence order

- **WHEN** the interactive flow runs
- **THEN** the program SHALL present the password field first; the TOTP field
  only if the account's second factor requires it; and the passphrase field after
  a successful login, each with a spinner shown while the intervening network call
  runs

### Requirement: TTY Gate And Non-Interactive Fallback

When stdin/stderr is not an interactive terminal (a pipe, a redirect,
automation, a test), `reduit auth add`/`auth refresh` SHALL NOT start the Bubble
Tea program and SHALL use exactly today's plain prompter path — the same prompts,
the same reads (`term.ReadPassword` / line reads), and no ANSI escape sequences
introduced by the auth UI. The TUI is a progressive enhancement, never a
requirement. The gate SHALL be evaluated once per invocation.

#### Scenario: Piped auth uses the plain prompter

- **WHEN** `reduit auth add <address>` runs with input piped or stdin not a TTY
- **THEN** no Bubble Tea program SHALL start, and the flow SHALL prompt and read
  exactly as it does today, so scripted/automated auth is unaffected

#### Scenario: Scripted prompter path is unchanged

- **WHEN** the auth flow is driven by a scripted (test) prompter
- **THEN** it SHALL exercise the same `interactiveAuth` sequence as before this
  capability existed, with no TUI dependency and no behavioral change

### Requirement: Network Steps Shared With Plain Path

The auth network sequence — `Login` (including the human-verification and
TOTP-only-2FA handling), `SubmitTOTP`, and `Unlock` — SHALL have a single
implementation used by BOTH the plain prompter path and the TUI model. The TUI
SHALL run these steps as commands off its UI goroutine; it SHALL NOT reimplement
the sequence or its error classification.

#### Scenario: One implementation, two front-ends

- **WHEN** the login/TOTP/unlock logic is inspected
- **THEN** the plain path and the TUI model SHALL both call the same step
  functions, so their behavior and error handling cannot diverge

#### Scenario: Human-verification error is surfaced identically

- **WHEN** `Login` returns a human-verification-required error (a non-Bridge
  app-version, per ADR-0021)
- **THEN** both paths SHALL surface the same actionable app-version error rather
  than attempting an in-app challenge

### Requirement: No Secret Leakage In The TUI

The Bubble Tea path SHALL uphold SPEC-0007 "No Secret Leakage": secret values
(password, passphrase) SHALL be masked on input, zeroed after use, and SHALL NOT
appear in any log record, notice, or rendered frame. The mailbox passphrase MAY
cross the program teardown only as the caller-owned return value the caller
zeroes; the password and TOTP SHALL be zeroed within the command that consumes
them.

#### Scenario: No secret in logs or notices

- **WHEN** the interactive TUI runs, including its streaming log region and any
  notice
- **THEN** no password, TOTP, or passphrase value SHALL appear in any emitted
  record or rendered line

#### Scenario: Passphrase lifecycle preserved across teardown

- **WHEN** the TUI unlocks successfully and tears down
- **THEN** the passphrase SHALL be returned to the caller (which persists it to
  the keychain and zeroes it), and SHALL NOT linger in the model after teardown

### Requirement: Clean Teardown And Interrupt

On success, error, or interrupt (SIGINT/SIGTERM/Ctrl-C), the TUI SHALL exit
cleanly and restore the terminal. The run's real error and the caller's success
line SHALL never be swallowed by the TUI. An interrupted or failed auth SHALL
leave no active or half-written mailbox (SPEC-0007 "Aborted auth leaves no active
mailbox").

#### Scenario: Success line survives the TUI

- **WHEN** an interactive auth completes successfully
- **THEN** the program SHALL tear down, the terminal SHALL be restored, and the
  caller's `Added mailbox` / `Re-authenticated mailbox` line SHALL print on the
  restored terminal exactly as the non-TUI path prints it

#### Scenario: Interrupt restores the terminal and rolls back

- **WHEN** the operator interrupts an interactive auth mid-flow
- **THEN** the TUI SHALL tear down without corrupting the terminal, the process
  SHALL stop, and any partially-added mailbox SHALL be cleaned up so no active or
  orphaned mailbox remains

### Requirement: Benign-Scope Notice

During `reduit auth refresh`, the expected scope-downgrade diagnostic emitted by
the cheap-resume probe — a `403` with Proton code `9101` on the salts endpoint,
which is the normal signal that the flow will escalate to interactive re-login —
SHALL be presented as an informational notice, not an error. A genuine auth
failure SHALL still be presented as an error. The reclassification SHALL be
scoped to the interactive auth commands and SHALL NOT affect the sync engine's
logging, and SHALL hold regardless of the configured log format.

#### Scenario: Expected scope diagnostic is a notice

- **WHEN** an interactive `auth refresh` cheap-resume probe hits the salts-scope
  `403 / 9101`
- **THEN** it SHALL render as a notice (not a red error), explaining that the
  stored session is being re-authenticated

#### Scenario: A real auth error is still an error

- **WHEN** an interactive auth encounters a genuine failure (e.g. a wrong
  password) that is not the benign salts-scope diagnostic
- **THEN** it SHALL render as an error, not a notice

#### Scenario: Notice reclassification does not touch sync

- **WHEN** the sync engine emits proton-client diagnostics
- **THEN** they SHALL be unaffected by the auth notice handler — only the
  interactive auth commands install it
