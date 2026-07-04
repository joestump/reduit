# SPEC-0005: Local TUI

## Overview

The Reduit **local TUI** is the human-facing surface: a full-screen
terminal application built on Bubble Tea, styled as a loving homage to
`mutt` — mutt as *design language* (dense index rows, a pager, a status
line, keyboard-first single-key bindings, a help footer), not a
feature-for-feature clone. It renders what the cache holds and derives:
keyword search over messages with a results index and pager, extracted
attachments, per-contact facts with citations, metadata coverage, and
sync/embedding statistics. It is read-only over the same `store` methods
the MCP uses (ADR-0017), runs entirely locally with no listener, and
works offline.

> **Scope note.** This spec has carried three scopes: a full HTMX
> browse/search web UI (withdrawn), a web insights UI (ADR-0024,
> superseded), and now the TUI (ADR-0025, 2026-07-03). There is no web
> surface: no HTTP, no HTML, no CSP. `reduit serve` is reserved for
> non-UI futures (ADR-0025) and is not specified here.

Governing: ADR-0025 (TUI decision + design language), ADR-0023 (Bubble
Tea in-tree; TTY + teardown discipline), ADR-0022 (charm ecosystem),
ADR-0017 (shared store, MCP primary), ADR-0012 (single-user local-first),
ADR-0006 (SQLite cache).

## Requirements

### Requirement: Bubble Tea Application, Mutt Design Language

The TUI MUST be implemented with charmbracelet/bubbletea (+ bubbles/
lipgloss) and MUST follow the mutt-inspired design language defined in
the design document's style reference: a dense index (list) view, a
full-height pager for reading a selected item, a persistent status line,
and a help footer. Interaction MUST be keyboard-first with mutt-familiar
single-key bindings (e.g. `j/k` movement, `/` search, `q` back/quit,
`?` help).

#### Scenario: Core layout

- **WHEN** the TUI opens a view
- **THEN** it SHALL render an index or pager with a persistent status
  line and key-hint footer, per the design system

#### Scenario: Keyboard-first

- **WHEN** the operator presses a bound key in any view
- **THEN** the action SHALL execute without requiring a pointer; every
  view SHALL be fully operable from the keyboard

### Requirement: Keyword Search With Index And Pager

The TUI SHALL provide keyword/FTS search over cached messages (the
store's FTS index), presented mutt-style: `/` opens a search prompt,
results render as a message index (sender, date, subject, folder), and
selecting a hit opens a read-only pager of the cached plaintext body
with its metadata. Semantic/hybrid search is OUT of v1 scope (joins when
SPEC-0008 ships).

#### Scenario: Search to pager

- **WHEN** the operator searches a term that matches cached messages
- **THEN** matching messages SHALL render as an index, and selecting one
  SHALL open its cached body and metadata in the pager

#### Scenario: No matches

- **WHEN** a search matches nothing
- **THEN** the TUI SHALL say so in the status line and remain usable

### Requirement: Insights Views

The TUI SHALL provide the derived-data views: attachments (filename,
MIME type, size, owning message, and extracted text), per-contact facts
with citations (read-only; mutations stay CLI/MCP per SPEC-0011),
metadata coverage (per-mailbox counts, date ranges, folders), and stats
(sync run history from `sync_runs`, extraction/embedding coverage, store
size).

> **Attachment open-in-app is deferred.** The store caches attachment
> metadata + extracted text, not raw bytes (ADR-0016), and the TUI is
> read-only and offline (REQ "Read-Only Shared-Store Access"), so it
> cannot fetch bytes to hand to the OS opener. The open-in-default-app
> hand-off returns when an attachment-blob capability exists — tracked
> in #174. Until then the attachments view surfaces the extracted text
> (the RAG-relevant content), which is what the cache holds.

#### Scenario: Attachment view shows metadata and extracted text

- **WHEN** the operator opens an attachment from the attachments index
- **THEN** the TUI SHALL show its metadata and extracted text (or an
  empty state when no text has been extracted). Open-in-default-app
  hand-off is out of scope until the store caches raw attachment bytes
  (#174); in-terminal image rendering remains a v2 possibility per
  ADR-0025.

#### Scenario: Facts are read-only

- **WHEN** a contact's facts are displayed
- **THEN** each fact SHALL show its citation and the view SHALL offer no
  mutation

### Requirement: Read-Only Shared-Store Access

Every TUI view MUST read through the same `store` methods the MCP tools
use, MUST NOT write to the store, and MUST NOT call Proton or trigger
sync/extract work. The TUI SHALL render fully offline from whatever the
cache holds (SPEC-0002 offline behavior), with empty states rather than
errors on a cold cache.

#### Scenario: No writes, no network

- **WHEN** any TUI interaction is handled
- **THEN** it SHALL perform no store writes and no Proton API calls

#### Scenario: Offline and cold-cache

- **WHEN** the machine is offline or the cache is empty
- **THEN** every view SHALL render (empty states permitted); nothing
  SHALL error on account of the network

### Requirement: Terminal Discipline

The TUI MUST require an interactive terminal (refusing with a clear
message otherwise), MUST restore the terminal completely on exit,
suspend (`ctrl-z`), and signal (SIGINT/SIGTERM), and MUST NOT corrupt
the scrollback. Untrusted strings (subjects, sender names, filenames,
fact text — all attacker-influenced) MUST be sanitized of terminal
control/escape sequences before rendering, so a crafted message cannot
inject escapes through the TUI.

#### Scenario: Non-TTY refused

- **WHEN** the TUI command runs without an interactive terminal
- **THEN** it SHALL exit with a clear message and non-zero status, not
  render ANSI into the pipe

#### Scenario: Hostile strings are inert

- **WHEN** a cached subject or filename contains terminal escape
  sequences
- **THEN** the TUI SHALL render them stripped/escaped, not emit them raw

### Requirement: No Web Surface

The TUI feature MUST NOT introduce an HTTP listener, HTML rendering, or
any web asset. `reduit serve` remains a stub reserved for non-UI futures
(ADR-0025); adding UI behavior to it requires a superseding ADR.

#### Scenario: No listener

- **WHEN** the TUI runs
- **THEN** no network listener SHALL be opened
