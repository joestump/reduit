// Server-Sent Events handler for the admin UI's live sync-status
// stream.
//
//	GET /sse/accounts/{id}/status -- emits Server-Sent Events on
//	account lifecycle state changes (and, when the sync worker grows
//	them, sync-progress / error events).
//
// The dashboard's per-account status card subscribes to this endpoint
// via the HTMX SSE extension (per ADR-0005) and swaps its status badge
// on each `status` event without a full-page reload.
//
// Ownership is enforced by the same requireOwnedAccount gate the
// per-account action handlers use: a session that neither owns the
// account nor is admin gets 403 before any stream is opened. The
// response carries the SSE headers SPEC-0005 requires
// (text/event-stream, no-cache, X-Accel-Buffering: no) so an
// intervening reverse proxy does not buffer or close the stream, and a
// comment-only heartbeat every 15s keeps idle proxies from timing the
// connection out. The handler flushes after every write and tears down
// cleanly on client disconnect (r.Context() cancellation) -- the
// pubsub subscription is always unsubscribed on return, so neither the
// goroutine nor the bus subscription leaks.
//
// Governing: SPEC-0005 REQ "Sync Status via SSE", ADR-0005 (HTMX +
// SSE); issue #16.

package server

import (
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/pubsub"
)

// sseHeartbeatInterval is the cadence of comment-only keepalive frames.
// SPEC-0005 REQ "Sync Status via SSE" Scenario "SSE is proxy-buffer-
// tolerant" fixes this at 15 seconds: long enough to be near-free,
// short enough to keep a default-configured nginx/Caddy proxy_read
// timeout (typically 60s) from closing an idle stream.
//
// Governing: SPEC-0005 REQ "Sync Status via SSE".
const sseHeartbeatInterval = 15 * time.Second

// handleAccountStatusSSE streams account status updates as
// Server-Sent Events.
//
// Lifecycle:
//
//  1. requireOwnedAccount resolves {id} and enforces ownership/admin
//     (403 on failure). It writes the error response itself, so we
//     just return.
//  2. We assert http.Flusher support. Every exit path so far returns a
//     clean error status -- the 200 + SSE headers are committed only
//     once we are definitely going to stream.
//  3. We subscribe to the per-account status topic on the bus (if a
//     bus is wired) BEFORE reading the current state for the snapshot,
//     so a transition racing the subscription is delivered live rather
//     than lost.
//  4. We commit the 200 + SSE headers, clear the http.Server
//     WriteTimeout (an absolute deadline that would otherwise kill the
//     stream after WriteTimeout seconds), emit the snapshot, then loop,
//     forwarding each Update as a `status` event and emitting a
//     heartbeat every sseHeartbeatInterval.
//  5. The loop exits when the client disconnects (r.Context() is
//     cancelled) -- the deferred unsubscribe then removes the bus
//     subscription and closes the channel, so the goroutine and the
//     subscription are both reclaimed. No leak on disconnect.
func (s *Server) handleAccountStatusSSE(w http.ResponseWriter, r *http.Request) {
	if s.deps.SessionManager == nil || s.deps.AccountService == nil {
		s.deps.Logger.Error("sse status handler called without required deps")
		http.Error(w, "sse not configured", http.StatusInternalServerError)
		return
	}

	// Ownership gate -- identical to the per-account action handlers.
	// Governing: SPEC-0005 REQ "Sync Status via SSE" Scenario "SSE
	// access control" (403 for non-owner / non-admin).
	acct, _, ok := s.requireOwnedAccount(w, r)
	if !ok {
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		// No streaming support behind this ResponseWriter -- can't
		// hold an SSE stream open. Fail loud rather than buffer the
		// whole response (which would defeat the point). Nothing has
		// been written yet, so http.Error returns a clean 500.
		s.deps.Logger.Error("sse status: ResponseWriter does not support flushing",
			slog.String("account_id", acct.ID))
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Subscribe to the per-account status topic BEFORE reading the
	// current state for the initial snapshot. Ordering matters: the
	// ownership gate above already read the row once, and a transition
	// can commit in the window between that read and our subscription.
	// Subscribing first guarantees any such gap-transition is delivered
	// over the live stream rather than silently lost -- which would
	// otherwise leave the badge permanently stale if the gap-transition
	// was terminal (e.g. -> suspended). A nil bus (test fixtures /
	// sync-not-wired deployments) yields no channel; the handler then
	// runs heartbeat-only so the stream is still opened and stays
	// proxy-tolerant.
	//
	// Governing: SPEC-0005 REQ "Sync Status via SSE" (no lost updates).
	var (
		updates <-chan pubsub.Update
		unsub   = func() {}
	)
	if s.deps.StatusBus != nil {
		updates, unsub = s.deps.StatusBus.Subscribe(pubsub.StatusKey(acct.ID), 0)
	}
	defer unsub()

	// Re-read the current state for the snapshot AFTER subscribing so it
	// reflects (or is superseded by) any transition that raced the
	// subscription. A read failure is non-fatal: fall back to the state
	// the ownership gate already loaded rather than abort the stream.
	snapshotState := acct.State
	if fresh, err := s.deps.AccountService.GetByID(r.Context(), acct.ID); err == nil {
		snapshotState = fresh.State
	} else {
		s.deps.Logger.Warn("sse status: snapshot re-read failed; using gate-read state",
			slog.String("account_id", acct.ID),
			slog.String("error", err.Error()))
	}

	// SSE + proxy-tolerance headers per SPEC-0005 REQ "Sync Status via
	// SSE" Scenario "SSE is proxy-buffer-tolerant". Set before the first
	// write/flush so they ride on the 200. We commit the 200 only here,
	// once we are definitely going to stream -- every early-exit path
	// above returns a clean error status instead.
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// Clear the http.Server WriteTimeout for this connection. That
	// timeout is an ABSOLUTE deadline over the whole response write, so
	// in production (WriteTimeout: 60s on the admin listener) it would
	// force-kill every SSE stream 60s after it opened -- the next Flush
	// errors, the handler returns, and the browser's EventSource
	// reconnects every 60s, re-running the ownership lookup + snapshot
	// each cycle. Clearing the deadline lets the stream live until the
	// client disconnects or the bus closes. SetWriteDeadline(zero)
	// removes the deadline; ErrNotSupported (some test ResponseWriters)
	// is logged and tolerated -- those writers have no deadline to clear.
	//
	// Governing: SPEC-0005 REQ "Sync Status via SSE" ("connection SHALL
	// remain open until client disconnect").
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.deps.Logger.Warn("sse status: clear write deadline failed",
			slog.String("account_id", acct.ID),
			slog.String("error", err.Error()))
	}

	// Emit an initial snapshot so a freshly-connected card reflects the
	// current state immediately rather than waiting for the next
	// transition. Equivalent to the server-rendered badge, just over the
	// stream.
	if err := s.writeStatusEvent(w, snapshotState); err != nil {
		return
	}
	flusher.Flush()

	ctx := r.Context()
	ticker := time.NewTicker(sseHeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Client disconnected (or server shutting down). Deferred
			// unsub reclaims the subscription; nothing else to do.
			return
		case <-ticker.C:
			// Comment-only heartbeat. An SSE comment line begins with a
			// colon and is ignored by the EventSource parser; it exists
			// solely to keep proxies from closing the idle connection.
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case u, chOpen := <-updates:
			if !chOpen {
				// Bus closed (process shutdown). End the stream.
				return
			}
			// We only render state-change updates today; ignore any
			// message-mutation kinds that might share the topic in the
			// future so the badge swap stays well-formed.
			if u.Kind != pubsub.StateChanged {
				continue
			}
			if err := s.writeStatusEvent(w, account.State(u.To)); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// writeStatusEvent serializes the status badge for state as a named SSE
// `status` event whose data is the badge HTML. The HTMX SSE extension
// swaps the data into the subscribed element (the dashboard card's
// badge), so the payload is exactly the markup the server-rendered
// badge would carry.
//
// Each data line is prefixed with `data: ` per the SSE wire format; the
// badge is single-line so one data line suffices, terminated by the
// blank line that closes the event.
//
// Governing: SPEC-0005 REQ "Sync Status via SSE", ADR-0005.
func (s *Server) writeStatusEvent(w http.ResponseWriter, state account.State) error {
	label, badgeClass := stateBadge(state)
	// stateBadge labels and classes are from a fixed internal set, but
	// run them through html/template escaping anyway so a future
	// dynamic label can never break out of the badge markup.
	payload := fmt.Sprintf(`<span class="badge %s">%s</span>`,
		template.HTMLEscapeString(badgeClass),
		template.HTMLEscapeString(label))
	if _, err := fmt.Fprintf(w, "event: status\ndata: %s\n\n", payload); err != nil {
		return err
	}
	return nil
}
