// MOVE Phase-3 reconciliation.
//
// The IMAP MOVE handler (internal/imapserver) labels a message into the
// destination mailbox on Proton (Phase 2) and then unlabels it from the
// source (Phase 3). When Phase 3 fails, the message ends up carrying BOTH
// the source and destination Proton labels — so it lives in two IMAP
// mailboxes — and the handler records a `pending_unlabels` row capturing
// the "this label should be gone" intent it could not durably apply.
//
// This file drains those rows: for each recorded (message, label) intent
// it retries UnlabelMessages against Proton. A successful retry deletes
// the row (the two-mailbox state is now resolved on Proton; the next sync
// event drops the local source link). A failed retry bumps the attempt
// counter and leaves the row for a later pass — but only up to
// maxReconcileAttempts: a permanently-failing unlabel (label deleted
// server-side, message deleted, non-transient 422) is "parked" once it
// crosses the ceiling (filtered out of future passes, not deleted) so it
// stops costing a Proton round-trip every tick while staying visible to
// an operator.
//
// Governing: SPEC-0003 REQ "Moving between system folders changes Proton
// system flag", SPEC-0003 REQ "Moving between Labels/ folders adjusts
// labels additively".

package sync

import (
	"context"
	"log/slog"

	"github.com/joestump/reduit/internal/mailbox"
	"github.com/joestump/reduit/internal/proton"
)

// PendingUnlabelStore is the slice of mailbox.Service the reconciler
// needs. Declaring it locally (rather than importing the whole
// mailbox.Service) keeps the reconciler testable with a tiny stub and
// documents exactly which mailbox operations the reconciliation path
// touches.
//
// Governing: SPEC-0003 REQ "Moving between system folders changes Proton
// system flag".
type PendingUnlabelStore interface {
	ListPendingUnlabels(ctx context.Context, accountID string, limit, maxAttempts int) ([]*mailbox.PendingUnlabel, error)
	ResolvePendingUnlabel(ctx context.Context, accountID string, id int64) error
	FailPendingUnlabel(ctx context.Context, accountID string, id int64) error
}

// reconcileBatchLimit bounds how many pending-unlabel rows a single
// reconciliation pass drains, so a large backlog cannot monopolise a
// worker tick (each row is a Proton round-trip). Remaining rows are
// picked up on the next tick. 50 matches Proton's per-call event
// coalescing ceiling — a comfortable per-tick budget without starving
// the event-poll path that shares the worker's Proton slot.
const reconcileBatchLimit = 50

// maxReconcileAttempts is the ceiling on how many times the reconciler
// retries a single unlabel before parking it. Without this, a
// permanently-failing unlabel (label deleted server-side, message
// deleted, a non-transient 422) would be retried on EVERY tick forever —
// one Proton round-trip per stuck row per tick per account, indefinitely.
// Once a row's attempts reach this value it is filtered out of
// ListPendingUnlabels (parked, not deleted) so it stops consuming Proton
// calls while staying visible to an operator for manual reconciliation.
const maxReconcileAttempts = 10

// MoveReconciler retries the source-unlabel that an IMAP MOVE failed to
// apply, converging messages stuck in two mailboxes back to the single
// mailbox the client asked for. One instance is shared across workers;
// each call is scoped to a single account.
type MoveReconciler struct {
	store  PendingUnlabelStore
	logger *slog.Logger
}

// NewMoveReconciler constructs a reconciler over the given store. A nil
// logger falls back to slog.Default(). A nil store makes Reconcile a
// no-op (so a composition root that has not wired the mailbox service
// can leave the reconciler unset without crashing the worker).
func NewMoveReconciler(store PendingUnlabelStore, logger *slog.Logger) *MoveReconciler {
	if logger == nil {
		logger = slog.Default()
	}
	return &MoveReconciler{store: store, logger: logger}
}

// Reconcile drains up to reconcileBatchLimit pending-unlabel intents for
// accountID, retrying each against `client`. It returns the number of
// intents successfully resolved (for logging/metrics) and the first
// store error encountered, if any. A failed Proton retry is NOT a
// returned error — the intent is left for the next pass — so a flaky
// Proton does not abort the worker tick.
//
// The contract intentionally tolerates a nil receiver / nil store so the
// worker can call it unconditionally.
func (rc *MoveReconciler) Reconcile(ctx context.Context, accountID string, client proton.Client) (int, error) {
	if rc == nil || rc.store == nil || client == nil {
		return 0, nil
	}
	// Only list rows below the retry ceiling; parked rows (attempts >=
	// maxReconcileAttempts) are skipped so they stop consuming a Proton
	// round-trip per tick. They remain in the table for operator
	// visibility.
	pending, err := rc.store.ListPendingUnlabels(ctx, accountID, reconcileBatchLimit, maxReconcileAttempts)
	if err != nil {
		return 0, err
	}
	resolved := 0
	for _, p := range pending {
		if ctx.Err() != nil {
			// Worker is draining; stop issuing Proton calls. Remaining
			// rows survive for the next active worker.
			break
		}
		if err := client.UnlabelMessages(ctx, []string{p.ProtonMessageID}, p.ProtonLabelID); err != nil {
			rc.logger.LogAttrs(ctx, slog.LevelWarn,
				"sync: move reconciliation unlabel retry failed; leaving for next pass",
				slog.String("account_id", accountID),
				slog.String("proton_message_id", p.ProtonMessageID),
				slog.String("proton_label_id", p.ProtonLabelID),
				slog.Int("attempts", p.Attempts),
				slog.String("err", err.Error()))
			if ferr := rc.store.FailPendingUnlabel(ctx, accountID, p.ID); ferr != nil {
				rc.logger.LogAttrs(ctx, slog.LevelWarn,
					"sync: failed to bump pending-unlabel attempts",
					slog.String("account_id", accountID),
					slog.Int64("id", p.ID),
					slog.String("err", ferr.Error()))
			} else if p.Attempts+1 >= maxReconcileAttempts {
				// This failure pushed the row to (or past) the ceiling: it
				// will be filtered out of subsequent ListPendingUnlabels
				// calls. Log exactly ONCE here — the row is now parked and
				// won't be retried, so we won't reach this branch for it
				// again — so the operator sees a single actionable warning
				// rather than a per-tick stream.
				rc.logger.LogAttrs(ctx, slog.LevelWarn,
					"sync: parking pending unlabel after max attempts; manual reconcile may be needed",
					slog.String("account_id", accountID),
					slog.Int64("id", p.ID),
					slog.String("proton_message_id", p.ProtonMessageID),
					slog.String("proton_label_id", p.ProtonLabelID),
					slog.Int("attempts", p.Attempts+1),
					slog.Int("max_attempts", maxReconcileAttempts))
			}
			continue
		}
		if err := rc.store.ResolvePendingUnlabel(ctx, accountID, p.ID); err != nil {
			// Proton has been corrected but we could not delete the row.
			// Leaving it means a future pass re-issues an idempotent
			// UnlabelMessages (a no-op on Proton's additive-label model)
			// and tries the delete again. Log so a persistently-stuck row
			// is visible, but do not abort the rest of the batch.
			rc.logger.LogAttrs(ctx, slog.LevelWarn,
				"sync: move reconciliation succeeded on Proton but row delete failed; will retry idempotently",
				slog.String("account_id", accountID),
				slog.Int64("id", p.ID),
				slog.String("err", err.Error()))
			continue
		}
		resolved++
		rc.logger.LogAttrs(ctx, slog.LevelInfo,
			"sync: move reconciliation cleared stuck source label",
			slog.String("account_id", accountID),
			slog.String("proton_message_id", p.ProtonMessageID),
			slog.String("proton_label_id", p.ProtonLabelID))
	}
	return resolved, nil
}
