# SPEC-0012: Sync Progress UI

## Overview

`reduit sync` gains a live progress bar for interactive runs: a
charmbracelet/bubbles progress component, rendered by a Bubble Tea program,
**pinned at the top of the terminal** while the run's log lines scroll below
it. Non-interactive runs (cron, CI, pipes) are entirely unaffected — they keep
today's plain structured-log output. The sync engine remains
presentation-agnostic: progress is surfaced through a typed event seam on the
engine's dependencies, and the CLI owns all rendering.

Decided in ADR-0023 (sync progress bar via charmbracelet/bubbles). Builds on
ADR-0022 (charmbracelet/log as the slog backend — the log stream the bar must
coexist with), ADR-0006 (pure-Go posture, which bubbletea/bubbles preserve),
and SPEC-0002 (sync & local cache — the counts and phases the bar renders).

Governing: ADR-0023, ADR-0022, ADR-0006, SPEC-0002.

## Requirements

### Requirement: Bubbles Progress Bar

In an interactive terminal, `reduit sync` SHALL render a progress bar
implemented with charmbracelet/bubbles inside a Bubble Tea program. The bar
SHALL remain pinned at the top of the terminal for the duration of the sync
while log lines scroll below it.

#### Scenario: Bar visible during backfill

- **WHEN** a sync's backfill phase runs in an interactive terminal
- **THEN** a bubbles progress bar SHALL be visible, pinned at the top of the
  terminal, showing determinate progress (messages applied / total enumerated)

#### Scenario: Logs scroll below the pinned bar

- **WHEN** the engine emits log records while the progress bar is active
- **THEN** the records SHALL render in the region below the bar, scrolling as
  they accumulate, and SHALL NOT tear, overwrite, or displace the bar

#### Scenario: Multi-mailbox progress

- **WHEN** `reduit sync` runs more than one active mailbox in one invocation
- **THEN** the pinned region SHALL reflect per-mailbox progress (the mailbox
  currently syncing and its phase), so concurrent mailboxes do not render a
  misleading single aggregate

### Requirement: TTY Gate And Non-Interactive Fallback

When the output is not an interactive terminal (cron, CI, a pipe, a
redirect), `reduit sync` SHALL NOT start the TUI and SHALL emit exactly the
plain structured-log output it emits today, containing no ANSI escape
sequences introduced by the progress UI. The progress bar is a progressive
enhancement, never a requirement.

#### Scenario: Piped run stays byte-clean

- **WHEN** `reduit sync` runs with stderr attached to a pipe or file
- **THEN** no Bubble Tea program SHALL start, the output SHALL be the plain
  charmbracelet/log stream, and it SHALL contain no progress-UI escape
  sequences

#### Scenario: Watch mode composes with both modes

- **WHEN** `reduit sync --watch <interval>` runs interactively or
  non-interactively
- **THEN** each iteration SHALL apply the same gate: TUI on a terminal, plain
  logs otherwise, with the signal-stop behavior of SPEC-0002 "Triggered
  Execution" unchanged

### Requirement: Engine Presentation Isolation

The sync engine (`internal/sync`) SHALL NOT import bubbletea, bubbles, or any
other terminal-UI library. Progress SHALL be surfaced through a typed
progress-event seam on the engine's dependencies; a nil reporter SHALL be a
no-op. The CLI layer owns all presentation.

#### Scenario: Engine builds without TUI dependencies

- **WHEN** the engine package's imports are inspected
- **THEN** no terminal-UI library SHALL appear; the progress seam is typed
  events only

#### Scenario: Nil reporter is a no-op

- **WHEN** the engine runs with no progress reporter configured
- **THEN** the sync SHALL behave identically to a run before this capability
  existed — same writes, same logs, same summary, no panics

#### Scenario: Events carry the run's shape

- **WHEN** a sync run progresses
- **THEN** the seam SHALL emit typed events sufficient to drive the bar:
  backfill enumerated (total), message applied (done/total), tail batch
  applied, and mailbox complete (summary counts)

### Requirement: Determinate Backfill, Indeterminate Tail

The backfill phase SHALL render a determinate bar driven by the enumerated
message total; the tail phase, which has no meaningful total, SHALL render an
indeterminate indicator fed by batch events.

#### Scenario: Backfill has a denominator

- **WHEN** the backfill applies message M of N enumerated
- **THEN** the bar SHALL show determinate progress M/N (percent complete)

#### Scenario: Tail has no denominator

- **WHEN** the run is in the tail phase applying event batches
- **THEN** the pinned region SHALL show an indeterminate indicator (activity,
  not a fabricated percent)

### Requirement: Clean Teardown

On completion, interrupt (SIGINT/SIGTERM), or error, the TUI SHALL exit
cleanly and restore the terminal. The run's error and the final per-mailbox
summary table SHALL never be swallowed by the TUI, and the exit-code contract
of SPEC-0002 "Triggered Execution" SHALL be unchanged.

#### Scenario: Summary survives the TUI

- **WHEN** a sync run finishes while the TUI is active
- **THEN** the TUI SHALL exit, the terminal SHALL be restored, and the final
  summary table SHALL print exactly as it does without the TUI

#### Scenario: Interrupt restores the terminal

- **WHEN** the operator sends SIGINT/SIGTERM mid-run
- **THEN** the TUI SHALL tear down without corrupting the terminal, and the
  process SHALL stop with the same behavior the non-TUI path has

#### Scenario: Errors keep their exit code

- **WHEN** any mailbox's run records a fatal cause
- **THEN** the process SHALL exit non-zero with the cause printed, identically
  to the non-TUI path

### Requirement: Concurrency Safety

All concurrent operations between the engine and the progress UI MUST follow
safe concurrency patterns:

- Context propagation MUST be used for cancellation across the engine, the
  progress seam, and the UI event loop — a cancelled run MUST stop the UI and
  a closed UI MUST NOT block the engine.
- The UI event loop's lifecycle MUST be explicitly managed: started before the
  run's first progress event is emitted, and shut down deterministically when
  the run ends (no leaked event-loop workers).
- Race safety MUST be ensured — progress events crossing from engine workers
  to the UI MUST use a safe hand-off (message passing); shared mutable state
  between them MUST NOT exist. A full or slow UI consumer MUST NOT stall the
  sync engine.
- Concurrent tests MUST run with race detection enabled.

#### Scenario: Slow consumer does not stall sync

- **WHEN** the UI consumes progress events more slowly than the engine emits
  them
- **THEN** the engine SHALL NOT block on the seam (events MAY be dropped or
  coalesced for display); the sync's throughput and correctness are unaffected

#### Scenario: Cancellation crosses the seam

- **WHEN** the run's context is cancelled while the TUI is active
- **THEN** the engine SHALL stop per SPEC-0002 and the UI SHALL shut down
  cleanly, with neither side deadlocking on the other
