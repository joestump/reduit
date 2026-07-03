// Package syncengine — the progress-reporting seam.
//
// This file is the engine's ONLY progress surface: a typed-event interface the
// engine calls as a run advances, so a presentation layer (the `reduit sync`
// TUI — SPEC-0012) can render a live bar without the engine importing any
// terminal-UI library. The engine stays presentation-agnostic (ADR-0023
// "Engine seam, not engine dependency"): it emits typed events; the CLI owns
// rendering. A nil reporter is a no-op, so a run without a consumer behaves
// exactly as it did before this seam existed.
//
// Governing: ADR-0023 (sync progress bar via charmbracelet/bubbles),
// SPEC-0012 (Sync Progress UI — "Engine Presentation Isolation",
// "Concurrency Safety").
package syncengine

// ProgressReporter receives typed progress events as a sync run advances. It is
// the engine's presentation seam: the engine emits events; a consumer (the CLI
// TUI) renders them. The zero value the engine uses when none is configured is
// nil, guarded at every emit, so a nil reporter is a no-op (SPEC-0012 "Nil
// reporter is a no-op").
//
// NON-BLOCKING CONTRACT: the engine calls these methods SYNCHRONOUSLY from its
// sync goroutines — potentially the per-message backfill hot loop. An
// implementation MUST NOT block: a slow or full consumer MUST drop or coalesce
// rather than stall the caller, or it will throttle decryption itself
// (SPEC-0012 "Concurrency Safety": "A full or slow UI consumer MUST NOT stall
// the sync engine"). Display is lossy by design; the authoritative counts live
// in RunSummary / sync_runs, not in these events.
//
// Every event carries MailboxID so a multi-mailbox run (SyncAll fans out with
// bounded concurrency) can be rendered per-mailbox without the events from
// concurrent mailboxes being conflated (SPEC-0012 "Multi-mailbox progress").
type ProgressReporter interface {
	// BackfillEnumerated fires once per mailbox, after BackfillMessageIDs
	// returns, carrying the message total that makes the backfill bar
	// determinate (SPEC-0012 "Backfill has a denominator").
	BackfillEnumerated(ev BackfillEnumerated)
	// MessageApplied fires after each backfilled message is applied, carrying
	// the running done/total. The engine emits one per message; the consumer
	// coalesces (SPEC-0012 "Slow consumer does not stall sync").
	MessageApplied(ev MessageApplied)
	// TailBatchApplied fires after each committed tail batch. The tail has no
	// meaningful total, so this drives the INDETERMINATE tail indicator
	// (SPEC-0012 "Tail has no denominator").
	TailBatchApplied(ev TailBatchApplied)
	// MailboxDone fires once at the end of a mailbox's run, carrying the final
	// summary (SPEC-0012 "Events carry the run's shape").
	MailboxDone(ev MailboxDone)
}

// BackfillEnumerated reports the enumerated backfill total for a mailbox: the
// denominator the determinate bar divides by.
type BackfillEnumerated struct {
	MailboxID string
	Address   string
	Total     int
}

// MessageApplied reports a backfill message applied: Done of Total for this
// mailbox. Total matches the preceding BackfillEnumerated.
type MessageApplied struct {
	MailboxID string
	Done      int
	Total     int
}

// TailBatchApplied reports one committed tail batch for a mailbox. Events is the
// batch's event count — activity for the indeterminate tail indicator, not a
// fraction of any total.
type TailBatchApplied struct {
	MailboxID string
	Events    int
}

// MailboxDone reports a mailbox's run finished, carrying its final summary. The
// consumer marks that mailbox complete.
type MailboxDone struct {
	MailboxID string
	Summary   RunSummary
}

// reportBackfillEnumerated and the emit* helpers below are the engine's guarded
// emit points: each is a no-op when the reporter is nil, so the engine's sync
// paths call them unconditionally without a nil check at every call site.
func (e *Engine) emitBackfillEnumerated(ev BackfillEnumerated) {
	if e.progress != nil {
		e.progress.BackfillEnumerated(ev)
	}
}

func (e *Engine) emitMessageApplied(ev MessageApplied) {
	if e.progress != nil {
		e.progress.MessageApplied(ev)
	}
}

func (e *Engine) emitTailBatchApplied(ev TailBatchApplied) {
	if e.progress != nil {
		e.progress.TailBatchApplied(ev)
	}
}

func (e *Engine) emitMailboxDone(ev MailboxDone) {
	if e.progress != nil {
		e.progress.MailboxDone(ev)
	}
}
