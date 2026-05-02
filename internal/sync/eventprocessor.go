// Governing: ADR-0001 (go-proton-api as Proton client),
//             SPEC-0002 REQ "Event Cursor Persistence",
//             SPEC-0002 REQ "Concurrency Limits".

package sync

import (
	"context"
	"errors"
	"log/slog"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/proton"
)

// eventProcessor owns one worker's interaction with Proton's event
// stream. It is constructed by worker.start() (synchronously, before
// the goroutine spins up) — a previous version did the bootstrap
// lazily inside tick(), but PR #41's hostile review pointed out that
// the lazy path only retried until proc became non-nil and offered
// no recovery story for steady-state Proton failures. Moving
// bootstrap to start() trades the (questionable) "transient
// ClientFactory error survives the first tick" benefit for loud
// failure at activation time, which is what an operator can act on.
//
// Refresh-token rotations are handled INSIDE go-proton-api's auth
// handler (see internal/proton/client.go installRefreshHandler) —
// they are NOT a function of when newEventProcessor runs. Re-running
// ClientFactory between ticks would not pick up a token rotation
// any faster than the upstream auth handler already does.
//
// Steady-state Proton failure (refresh token revoked server-side,
// account blocked, etc.) is deferred to story #17, which will add
// classification + state transition; for #16 the worker logs at
// ERROR each tick and the next tick retries the same dead processor.
//
// The processor caches the current cursor in-process so the per-tick
// path is one Proton round-trip plus one DB write, not a Proton
// round-trip plus two DB writes. The persisted cursor is the source
// of truth on restart; the in-process copy is a hot-path
// optimisation.
//
// Governing: SPEC-0002 REQ "Event Cursor Persistence".
type eventProcessor struct {
	accountID string
	svc       account.Service
	client    proton.Client
	logger    *slog.Logger

	// cursor is the cached event ID to pass to the next GetEvent call.
	// Mutation is single-goroutine (only the worker.run loop calls
	// processOnce), so no lock is required.
	cursor string
}

// newEventProcessor bootstraps a processor for the supplied account.
// The bootstrap reads the persisted cursor from sync_state; if no row
// exists yet it falls back to proton.Client.GetLatestEventID so the
// first-ever poll picks up "now" instead of replaying historical
// events.
//
// The bootstrap intentionally does NOT persist the bootstrap cursor —
// we want the first successful processOnce call to be what creates
// the sync_state row, so a worker that bootstraps and then exits
// before any successful poll does not leave an "I synced everything
// up to T0" lie behind.
//
// Governing: SPEC-0002 REQ "Event Cursor Persistence" (Resume on
// startup uses persisted cursor).
func newEventProcessor(ctx context.Context, accountID string, svc account.Service, client proton.Client, logger *slog.Logger) (*eventProcessor, error) {
	state, err := svc.GetSyncState(ctx, accountID)
	switch {
	case err == nil:
		logger.LogAttrs(ctx, slog.LevelDebug,
			"sync: resuming from persisted cursor",
			slog.String("cursor", state.LastEventID),
		)
		return &eventProcessor{
			accountID: accountID,
			svc:       svc,
			client:    client,
			logger:    logger,
			cursor:    state.LastEventID,
		}, nil
	case errors.Is(err, account.ErrNoSyncState):
		// First-ever boot: ask Proton for the "now" cursor so we
		// don't replay historical events. SPEC-0002 "Out of Scope"
		// explicitly notes that v0.1 starts from the current Proton
		// event cursor and only materialises new messages from that
		// point forward; this is where that policy lives in code.
		latest, lerr := client.GetLatestEventID(ctx)
		if lerr != nil {
			return nil, lerr
		}
		logger.LogAttrs(ctx, slog.LevelInfo,
			"sync: no persisted cursor; bootstrapping from latest",
			slog.String("cursor", latest),
		)
		return &eventProcessor{
			accountID: accountID,
			svc:       svc,
			client:    client,
			logger:    logger,
			cursor:    latest,
		}, nil
	default:
		return nil, err
	}
}

// processOnce fetches one event batch and, on success, persists the
// new cursor atomically. Returns (more, error) where `more` is the
// upstream's "there is at least one more batch waiting right now"
// signal — the worker uses this to decide whether to chain another
// processOnce immediately (drain the backlog) vs. wait for the next
// ticker fire.
//
// Governing: SPEC-0002 REQ "Event Cursor Persistence". For #16's
// plumbing stage the only state change derived from a batch is the
// cursor itself; #19 will pass a non-nil SyncStateTxWork to
// SetSyncState so its mailbox/UID writes commit alongside the cursor.
//
// On an empty batch (Proton returned the same cursor we asked with —
// `more` will be false and the returned slice will be empty or carry
// only the no-op event) we still upsert the cursor so the
// last_synced_at column ticks forward and the admin UI's "last sync"
// indicator stays current. The cursor value itself is unchanged in
// that case, so this is idempotent: two consecutive empty polls leave
// the cursor at the same string but bump last_synced_at twice.
func (p *eventProcessor) processOnce(ctx context.Context) (bool, error) {
	events, more, err := p.client.GetEvent(ctx, p.cursor)
	if err != nil {
		return false, err
	}

	// SPEC-0002 REQ "Event Cursor Persistence" — derive the new
	// cursor from the LAST event in the batch. Proton's event API is
	// monotonic and the upstream client returns events in delivery
	// order; the last event's ID is the cursor that names "I have
	// applied everything up to and including this point". When the
	// batch is empty (nothing new since the previous cursor) we keep
	// the old cursor — the SetSyncState call still runs to bump
	// last_synced_at for observability.
	nextCursor := p.cursor
	if n := len(events); n > 0 {
		nextCursor = events[n-1].EventID
	}

	for _, e := range events {
		// #16 plumbing-only: log what we got. #19 will replace this
		// with mailbox/message materialisation, and the writes will
		// move into a SyncStateTxWork callback so they commit in the
		// same transaction as the cursor advance.
		//
		// Unknown event types are not a separate code path here —
		// gpa.Event is a typed struct, so anything we don't recognise
		// is simply absent from the struct's fields. The acceptance
		// criteria's "Unknown event types: log at ERROR" only applies
		// once #19 starts pattern-matching on event sub-types; for
		// the plumbing pass, every event reaches this Debug log and
		// the cursor advances regardless.
		p.logger.LogAttrs(ctx, slog.LevelDebug,
			"sync: event received",
			slog.String("event_id", e.EventID),
			slog.Int("messages", len(e.Messages)),
			slog.Int("labels", len(e.Labels)),
			slog.Int("addresses", len(e.Addresses)),
		)
	}

	// Atomic cursor commit. txWork is omitted (the variadic accepts
	// zero callbacks) so SetSyncState writes only the cursor row;
	// #19 will pass a non-nil callback that materialises mailbox/UID
	// state in the same transaction.
	//
	// Governing: SPEC-0002 REQ "Event Cursor Persistence" — atomic
	// commit of cursor and state changes derived from the same batch.
	if err := p.svc.SetSyncState(ctx, p.accountID, nextCursor); err != nil {
		return false, err
	}
	p.cursor = nextCursor
	return more, nil
}
