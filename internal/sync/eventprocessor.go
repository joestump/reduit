// Governing: ADR-0001 (go-proton-api as Proton client),
//             SPEC-0002 REQ "Event Cursor Persistence",
//             SPEC-0002 REQ "Concurrency Limits",
//             SPEC-0002 REQ "Backoff on Failure" (refresh-token-revoked
//             permanent-failure path),
//             SPEC-0002 REQ "IMAP Update Notification".

package sync

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/pubsub"
)

// Publisher is the slice of pubsub.Bus the event processor needs:
// publish an Update under a string key. The Bus implements this
// interface naturally; tests can pass a recording stub that captures
// every (key, update) pair without standing up a real bus.
//
// Governing: SPEC-0002 REQ "IMAP Update Notification".
type Publisher interface {
	Publish(key string, u pubsub.Update)
}

// nopPublisher is the zero-value publisher: every Publish call is
// silently dropped. Used when the supervisor was constructed without a
// Publisher (e.g. a unit test that doesn't care about IDLE notifications)
// so the eventprocessor can call Publish unconditionally without nil
// checks at every call site.
type nopPublisher struct{}

func (nopPublisher) Publish(string, pubsub.Update) {}

// errRefreshTokenRevoked is the sentinel returned by processOnce after
// the worker has handled a permanent auth failure: the account has
// been transitioned back to pending_proton_setup and the worker MUST
// exit without walking the backoff curve. The worker's tick loop uses
// errors.Is on this sentinel to take the silent-exit branch.
//
// Governing: SPEC-0002 REQ "Backoff on Failure" — "Permanent errors do
// not retry indefinitely".
var errRefreshTokenRevoked = errors.New("sync: refresh token revoked; account returned to pending_proton_setup")

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

	// publisher receives one Update per MessageEvent in a successfully-
	// committed batch. nil is replaced with nopPublisher at construction
	// so processOnce can call Publish unconditionally.
	//
	// Governing: SPEC-0002 REQ "IMAP Update Notification".
	publisher Publisher

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
func newEventProcessor(ctx context.Context, accountID string, svc account.Service, client proton.Client, logger *slog.Logger, publisher Publisher) (*eventProcessor, error) {
	if publisher == nil {
		publisher = nopPublisher{}
	}
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
			publisher: publisher,
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
			publisher: publisher,
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
//
// Stale-cursor recovery: Proton retains events for ~24h. If the
// worker resumes from a cursor older than that, GetEvent returns a
// 422 + Code=InvalidValue. Rather than spinning forever on the dead
// cursor, we transparently fall back to GetLatestEventID and resume
// from "now" — the cost is a one-time gap (events between the dead
// cursor and now are unrecoverable anyway, since Proton has purged
// them) and the recovery is logged at WARN so operators can correlate
// the gap with the cursor reset.
func (p *eventProcessor) processOnce(ctx context.Context) (bool, error) {
	events, more, err := p.client.GetEvent(ctx, p.cursor)
	if err != nil {
		// Permanent auth failure: refresh token revoked server-side.
		// Transition the account back to pending_proton_setup so the
		// wizard prompts for re-login, then return the sentinel so the
		// worker's tick loop exits without walking the backoff curve.
		//
		// Governing: SPEC-0002 REQ "Backoff on Failure" — "Permanent
		// errors do not retry indefinitely".
		if isRefreshTokenRevokedError(err) {
			// The Transition fires the supervisor's OnTransition
			// callback synchronously, which dispatches to stopWorker
			// on the active->pending edge. stopWorker.waitDone blocks
			// on the worker's run goroutine — and we ARE that goroutine.
			// Running Transition inline would therefore deadlock.
			//
			// We spin Transition into a fresh goroutine so the
			// supervisor's stopWorker can wait on us draining via
			// ctx.Done. The worker's tick() consumes the sentinel by
			// cancelling its own context, so the run loop exits, the
			// done channel closes, and stopWorker.waitDone returns.
			//
			// Governing: SPEC-0002 REQ "Backoff on Failure".
			go func(svc account.Service, id string) {
				if _, terr := svc.Transition(context.Background(), id, account.StatePendingProtonSetup); terr != nil {
					p.logger.LogAttrs(context.Background(), slog.LevelError,
						"sync: refresh token revoked but transition to pending failed",
						slog.Any("err", terr),
					)
				}
			}(p.svc, p.accountID)
			p.logger.LogAttrs(ctx, slog.LevelWarn,
				"sync: refresh token revoked; account returned to pending_proton_setup, worker exiting",
				slog.Any("err", err),
			)
			return false, errRefreshTokenRevoked
		}
		// Stale-cursor recovery. The bookmark we have is older than
		// Proton's retention window; the only correct response is to
		// reset to "now" and let #19's mailbox/UID materialisation
		// reconcile against the gap. Returning the GetLatestEventID
		// failure (if any) bubbles a real network error up to the
		// worker for retry on the next tick.
		if isStaleCursorError(err) {
			latest, lerr := p.client.GetLatestEventID(ctx)
			if lerr != nil {
				return false, lerr
			}
			p.logger.LogAttrs(ctx, slog.LevelWarn,
				"sync: stale cursor reset; events between previous and now are lost (Proton retention)",
				slog.String("stale_cursor", p.cursor),
				slog.String("new_cursor", latest),
			)
			// Persist the recovery cursor immediately so a subsequent
			// crash doesn't replay the same dead cursor on restart.
			if err := p.svc.SetSyncState(ctx, p.accountID, latest, nil); err != nil {
				return false, err
			}
			p.cursor = latest
			// Yield to the next tick so the operator sees the recovery
			// log before the next GetEvent. There is no backlog to
			// drain here by definition (we just reset to "now").
			return false, nil
		}
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
	//
	// Empty-EventID defense: if the last event's ID is the empty
	// string, persisting it would make the next GetEvent call ask
	// Proton for "everything" (the upstream API treats "" specially).
	// We treat this as a malformed batch: keep the old cursor, log at
	// ERROR, and let the next tick retry from the same place.
	nextCursor := p.cursor
	if n := len(events); n > 0 {
		last := events[n-1].EventID
		if last == "" {
			p.logger.LogAttrs(ctx, slog.LevelError,
				"sync: dropping batch with empty trailing EventID; cursor unchanged",
				slog.Int("batch_size", n),
				slog.String("retained_cursor", p.cursor),
			)
			return false, nil
		}
		nextCursor = last
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

	// Atomic cursor commit. The strict-arity SetSyncState API takes a
	// single nilable txWork callback; #16 plumbing has no derived state
	// so we pass nil. #19 will replace this with a non-nil callback
	// that materialises mailbox/UID state in the same transaction.
	//
	// Governing: SPEC-0002 REQ "Event Cursor Persistence" — atomic
	// commit of cursor and state changes derived from the same batch.
	if err := p.svc.SetSyncState(ctx, p.accountID, nextCursor, nil); err != nil {
		return false, err
	}
	p.cursor = nextCursor

	// Publish IDLE notifications AFTER the cursor commit so a
	// subscriber that observes a Publish can rely on the underlying
	// state having committed. Publishing pre-commit would let an IDLE
	// session see "MessageAdded" for a message that the next FETCH
	// can't find if the commit then fails. SPEC-0002 design pins
	// notification AFTER state changes have committed.
	//
	// Governing: SPEC-0002 REQ "IMAP Update Notification".
	p.publishMessageEvents(events)
	return more, nil
}

// publishMessageEvents fans the per-MessageEvent kind onto the pubsub
// bus. Each MessageEvent carries one Action and at least one
// LabelID — Proton uses LabelIDs as its per-mailbox routing key, and
// IMAP IDLE consumers subscribe under the same `<account_id>:<label_id>`
// shape so the worker does not need to resolve LabelIDs to local
// mailbox row IDs at notification time.
//
// EventAction mapping (from go-proton-api):
//
//	EventCreate      → MessageAdded       (new message in a label)
//	EventDelete      → MessageRemoved     (message removed from labels)
//	EventUpdate      → MessageFlagChanged (full update)
//	EventUpdateFlags → MessageFlagChanged (flags-only update)
//
// EventDelete events have no Message body, so we cannot enumerate the
// labels the message was in. The IMAP IDLE consumer's RESYNC-on-
// reconnect contract handles this gap: a delete fans an account-wide
// notification (mailbox_id=""), and any IDLE session for that account
// re-checks its selected mailbox. SPEC-0002 design's drop-oldest
// policy makes this acceptable — the spec already accepts lossy
// notifications behind a RESYNC fallback.
//
// Governing: SPEC-0002 REQ "IMAP Update Notification".
func (p *eventProcessor) publishMessageEvents(events []proton.Event) {
	for _, e := range events {
		for _, m := range e.Messages {
			kind := messageEventKind(m.Action)
			if kind == pubsub.KindUnknown {
				continue
			}
			update := pubsub.Update{Kind: kind, MessageID: m.ID}
			// Most MessageEvent payloads carry the message metadata
			// (which includes LabelIDs); EventDelete leaves the
			// Message field zero, so LabelIDs is empty and we fall
			// back to the account-wide key. The IMAP IDLE session's
			// re-check on a wildcard notification covers the gap.
			labels := m.Message.LabelIDs
			if len(labels) == 0 {
				p.publisher.Publish(notifyKey(p.accountID, ""), update)
				continue
			}
			for _, label := range labels {
				p.publisher.Publish(notifyKey(p.accountID, label), update)
			}
		}
	}
}

// messageEventKind maps a Proton EventAction to the pubsub Kind the
// IDLE session emits. Returns KindUnknown for actions the IDLE side
// has no representation for; the caller skips those.
func messageEventKind(a gpa.EventAction) pubsub.Kind {
	switch a {
	case gpa.EventCreate:
		return pubsub.MessageAdded
	case gpa.EventDelete:
		return pubsub.MessageRemoved
	case gpa.EventUpdate, gpa.EventUpdateFlags:
		return pubsub.MessageFlagChanged
	default:
		return pubsub.KindUnknown
	}
}

// notifyKey is the canonical pubsub key shape for IMAP IDLE
// notifications: `<account_id>:<mailbox_id>`. mailbox_id may be the
// empty string for account-wide events (e.g. EventDelete with no
// Message body); IDLE sessions subscribed to a specific mailbox key
// will not see those, so the IMAP server will need to also subscribe
// to the account-wide key as a RESYNC trigger when SPEC-0003 IDLE
// support lands.
//
// The shape matches `internal/pubsub/doc.go` ("opaque string, expected
// shape <account_id>:<mailbox_id>").
//
// Governing: SPEC-0002 REQ "IMAP Update Notification".
func notifyKey(accountID, mailboxID string) string {
	return accountID + ":" + mailboxID
}

// isRefreshTokenRevokedError reports whether err is the upstream
// signal that the refresh token has been revoked — the permanent-
// failure case SPEC-0002 REQ "Backoff on Failure" calls out
// explicitly. We match on Code=AuthRefreshTokenInvalid (10013) primary
// because the upstream issues that on /auth/v4/refresh failure with a
// 4xx; we also accept HTTP 401 as a defensive fallback because some
// proxies strip the body and we'd rather kick the account to pending
// than spin on a credential that has clearly stopped working.
//
// Governing: SPEC-0002 REQ "Backoff on Failure".
func isRefreshTokenRevokedError(err error) bool {
	var apiErr *gpa.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.Code == gpa.AuthRefreshTokenInvalid {
		return true
	}
	// HTTP 401 from /auth/v4/refresh is the "your refresh token is
	// rejected" surface in the rare cases the upstream omits the
	// typed code. 401 from any other endpoint is normally retried by
	// go-proton-api's transport layer, but those go via a refresh
	// round-trip that itself surfaces 10013 if the refresh fails —
	// so a 401 reaching us here strongly implies the refresh path
	// has already given up.
	return apiErr.Status == http.StatusUnauthorized
}

// isStaleCursorError reports whether err indicates the cursor we
// passed to GetEvent has aged past Proton's event retention window
// (~24h). Proton signals this with HTTP 422 + Code=InvalidValue (the
// generic "request param is no longer accepted" code). Other 422s
// (e.g. malformed UID) also surface as InvalidValue, but those are
// programmer bugs that retrying-from-latest cannot harm — falling
// back to GetLatestEventID still produces a valid cursor and the
// real bug surfaces in the gap analysis.
//
// We deliberately do NOT match by HTTP status alone: a transient 422
// from a hostile proxy without a real APIError body would otherwise
// trigger a destructive cursor reset. Requiring both Status==422 and
// Code==InvalidValue scopes the recovery to the actual upstream
// signal.
func isStaleCursorError(err error) bool {
	var apiErr *gpa.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.Status == http.StatusUnprocessableEntity && apiErr.Code == gpa.InvalidValue
}
