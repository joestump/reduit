# Design: Interactive Auth UI (SPEC-0013)

## Context

Interactive `reduit auth add` / `auth refresh` today read secrets with bare
`term.ReadPassword` prompts (`internal/cli/prompt.go`) while go-proton-api logs
raw diagnostics around them. The product now has a Bubble Tea design language
(ADR-0025) and a pinned-bar-over-scrolling-logs sync UI (ADR-0023); the auth
prompts are the last inconsistent surface, and on refresh the benign
cheap-resume `403 / 9101` reads as a scary red error before the flow escalates to
re-login as designed.

Unlike sync — where the engine runs to completion and the UI only observes —
auth is **request/response**: the UI collects a field, hands it to a network
call, and the call's result decides the next field. `interactiveAuth`
(`internal/cli/auth.go`) is a straight-line function that *blocks* on
`p.secret(...)` / `p.line(...)` between `client.Login`, `client.SubmitTOTP`, and
`client.Unlock`. Bubble Tea forbids blocking in `Update`, so the sequence must be
re-expressed as an async state machine while keeping the network logic — and its
security invariants (SPEC-0007) — exactly as-is.

## Goals / Non-Goals

### Goals

- A TTY-gated Bubble Tea presentation for interactive `auth add`/`auth refresh`:
  masked input fields, a spinner during network calls, streaming logs below a
  pinned header, in the ADR-0025 design language.
- Single-source the auth network sequence so the plain and TUI paths cannot
  drift (SPEC-0007 invariants hold on both).
- Byte-for-byte-identical non-interactive/piped auth; unchanged scripted-prompter
  tests.
- The benign refresh `403 / 9101` rendered as a notice; genuine errors still red.

### Non-Goals

- Changing any auth semantics (SRP, 2FA, resume/escalation, keychain layout,
  cleanup-on-abort) — SPEC-0007 is untouched.
- A TUI for non-interactive contexts, or for MCP (auth is a CLI verb).
- Solving human-verification / CAPTCHA in-app (ADR-0021 stands; the login step
  maps the HV error to an actionable message).

## Decisions

### Shared network steps, not a forked state machine

Extract the three network calls out of `interactiveAuth` into pure, prompt-free
functions — `loginStep` (wraps `client.Login` + the HV-required → app-version
error mapping + the `TwoFAUnsupported` rejection), `submitTOTPStep`, `unlockStep`.
`interactiveAuth` keeps its exact signature and composes them for the plain path
(so `scriptPrompter` tests pass unchanged). The TUI model calls the *same* steps
from inside `tea.Cmd`s. This is the direct analog of ADR-0023's "engine seam, not
engine dependency": the network sequence is the shared core; presentation is
layered on top and swapped by the TTY gate.

### Model: an async field↔network state machine

One `authModel` (new `internal/cli/authui.go`) with an `authPhase` enum:
`password → loggingIn → totp → submitTOTP → passphrase → unlocking →
done/failed`. Each network step runs off the UI goroutine as a `tea.Cmd`
returning a typed result message (`loginResultMsg{status, err}`,
`totpResultMsg{err}`, `unlockResultMsg{err}`). `Update` folds a result to pick
the next phase — e.g. `loginResultMsg` with `status.TwoFA == TOTP` → `totp`, else
→ `passphrase`. One `bubbles/textinput` is reconfigured per phase:
`EchoPassword` (`•`) for password/passphrase, `EchoNormal` for the TOTP. The
spinner ticks during the `*ing` network phases. `View()` returns `""` once done,
so nothing stays pinned after teardown (mirrors `syncModel`).

### Refresh cheap-resume runs first, non-interactively

`tryCheapResume` (`auth.go`) is a non-interactive network sequence (Resume →
Labels probe → verify-unlock). Rather than model it as an interactive phase, the
refresh TUI runs it *first* on a background goroutine under the notice log writer,
surfacing its `403 / 9101` as a notice; only on fall-through (`done == false`)
does the interactive input model start. This keeps `phaseResume` out of the model
and the model purely about the re-login field↔network loop.

### TTY gate + teardown: the TUI is a display, never the owner of results

A single gate `runAuthGated` (new `internal/cli/authui_run.go`, mirroring
`runSyncGated`, reusing the `isTerminal` seam) chooses once: non-TTY → today's
`interactiveAuth(ctx, client, plainPrompter, ...)` verbatim; TTY → `runAuthTUI`.
`authAdd`/`authRefresh` call the gate instead of `interactiveAuth` directly.

Teardown is load-bearing and inherits the Phase-1 sync lesson (bind the program
to the run's ctx; bubbletea `Println` has no ctx guard, so the log writer drops
once dead):

1. Build the notice log writer over the program *before* any network call, so no
   proton diagnostic escapes to bare stderr and tears the header.
2. Run the model; it captures either `m.passphrase` (success) or `m.err`.
3. On `prog.Run()` return: cancel the program context, close/flush the log
   writer, read `m.passphrase` / `m.err` out of the final model.
4. Return `(passphrase, err)` to the caller, which owns `defer zero(passphrase)`,
   the keychain writes, and the success line — all unchanged.

Password/TOTP are zeroed inside their `tea.Cmd`s. The passphrase crosses teardown
only as the return value. An interrupt cancels ctx (cancelling in-flight network
calls and quitting the program) and the caller's existing cleanup rolls back a
partially-added mailbox.

### Benign-scope notice: a reclassifying slog.Handler, scoped to auth

A `noticeHandler` (new `internal/cli/authnotice.go`) wraps the real slog handler
and is installed *only* on the logger passed to `protonConfig` for the auth
commands. It inspects records *before* formatting (so it is independent of
`logger.format`, per SPEC-0007): a `≥ERROR` record whose message carries the
salts-scope signature (`403` + code `9101` / "sufficient scope") is downgraded to
a notice level and tagged so the writer renders it gold; everything else passes
through. Working on the pre-format record (not formatted bytes) is why a
log-writer string filter was rejected. The message text comes from the
`slogLogger` shim (`internal/proton/logger.go`), which already guarantees no
secret is formatted into it. The sync engine's `protonConfig` is untouched.

## Architecture

```mermaid
sequenceDiagram
    participant U as operator
    participant M as authModel (Bubble Tea)
    participant S as shared steps
    participant C as proton.Client
    U->>M: types password (masked)
    M->>S: loginStep (tea.Cmd, off UI goroutine)
    S->>C: Login
    C-->>M: loginResultMsg{status,err}
    alt TwoFA == TOTP
        U->>M: types TOTP (echoed)
        M->>S: submitTOTPStep
        S->>C: SubmitTOTP
        C-->>M: totpResultMsg
    end
    U->>M: types passphrase (masked)
    M->>S: unlockStep
    S->>C: Unlock
    C-->>M: unlockResultMsg
    M-->>U: phaseDone; teardown → caller reads passphrase, writes keychain, prints success
```

Reused verbatim from the sync UI: the `program` interface, `syncLogWriter`
(streaming logs below the header), `buildLoggerTo`, `isTerminal`, and
`styles.New()` / `glyphs` (`❯ ✓ ✗`, cyan/mint/gold/coral).

## Risks / Trade-offs

- **Inverting a blocking sequence into an async model** is the main complexity;
  mitigated by unit-testing the model via synthetic result messages (no live
  client/terminal) and by keeping the network logic in the shared steps.
- **Secret handling across a UI** is sensitive; mitigated by masking on input,
  zeroing in the commands, and letting only the passphrase cross teardown as the
  caller-owned return value — the same lifecycle as today.
- **Notice over-matching** could paint a real error gold; mitigated by matching
  the narrow salts-scope `9101` signature only and leaving all other records as
  errors.
- **Two front-ends for one sequence** risks drift; mitigated structurally — there
  is one implementation of the steps, and the plain path's tests are the
  regression guard.

## Migration Plan

1. Extract `loginStep`/`submitTOTPStep`/`unlockStep`; refactor `interactiveAuth`
   to compose them (behavior unchanged, existing tests green).
2. Add `authnotice.go` (the scoped handler) with unit tests over the
   `capturingProgram` double.
3. Add `authui.go` (model) + `authui_run.go` (gate, teardown, `newAuthProgram`);
   route `authAdd`/`authRefresh` through `runAuthGated`.
4. Add model/gate/notice tests; run `make test` (race) + `make lint`; manual TTY
   walk-through of `auth refresh` (notice shows, masked fields, success line).

## Open Questions

- Whether to also style `auth list` / `auth remove` output (currently plain
  tables) for consistency — out of scope here; low value, tracked separately if
  wanted.
- Whether the notice should also cover other known-benign proton diagnostics
  beyond the salts-scope `9101` — start narrow; widen only with evidence.
