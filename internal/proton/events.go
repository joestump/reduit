package proton

import (
	"context"

	gpa "github.com/ProtonMail/go-proton-api"
)

// eventFetcher is the slice of go-proton-api the cursor logic needs. *gpa.Client
// satisfies it directly; tests supply a fake so collectEvents — the cursor and
// translation logic that is the wrapper's own — is exercised without a live
// account.
type eventFetcher interface {
	GetEvent(ctx context.Context, eventID string) ([]gpa.Event, bool, error)
}

// collectEvents fetches the events after sinceEventID and translates them into
// a reduit EventBatch (ADR-0014 "advance the persisted Proton event cursor and
// apply the delta").
//
// Cursor invariant: NextCursor starts at the requested cursor and only advances
// to the id of an event actually returned, so an empty fetch leaves the caller
// pointed at the same place (never backward, never skipping) — the resumable,
// idempotent property ADR-0014 requires. The upstream `more` flag is surfaced
// as EventBatch.More so a caller draining the backlog loops until it clears.
func collectEvents(ctx context.Context, f eventFetcher, sinceEventID string) (EventBatch, error) {
	raw, more, err := f.GetEvent(ctx, sinceEventID)
	if err != nil {
		return EventBatch{}, classifyError(err)
	}

	batch := EventBatch{
		NextCursor: sinceEventID,
		More:       more,
		Events:     make([]Event, 0, len(raw)),
	}
	for _, e := range raw {
		batch.NextCursor = e.EventID
		batch.Events = append(batch.Events, convertEvent(e))
	}
	return batch, nil
}

// convertEvent maps one go-proton-api event onto reduit's domain type, keeping
// only what the sync layer consumes: the cursor id, the full-resync flag, and
// the message-level deltas.
func convertEvent(e gpa.Event) Event {
	out := Event{
		EventID: e.EventID,
		// Any non-zero refresh flag means the local view is stale and must be
		// re-bootstrapped rather than delta-applied (ADR-0014).
		Refresh: e.Refresh != 0,
	}
	if len(e.Messages) > 0 {
		out.Messages = make([]MessageEvent, 0, len(e.Messages))
		for _, m := range e.Messages {
			out.Messages = append(out.Messages, MessageEvent{
				Action:    convertAction(m.Action),
				MessageID: m.ID,
			})
		}
	}
	return out
}

// convertAction collapses go-proton-api's four event actions onto reduit's
// three: a flags-only update is, for cache purposes, an update.
func convertAction(a gpa.EventAction) EventAction {
	switch a {
	case gpa.EventCreate:
		return EventCreate
	case gpa.EventDelete:
		return EventDelete
	case gpa.EventUpdate, gpa.EventUpdateFlags:
		return EventUpdate
	default:
		return EventUpdate
	}
}
