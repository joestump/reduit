// Package syncengine — the per-mailbox bootstrap-then-tail routine.
//
// This file is the heart of one mailbox's sync: resume its authenticated Proton
// client from stored secrets, then either backfill a bounded window of history
// (first sync) or tail the event stream and apply the delta (every run after).
// Cache writes and the event-cursor advance commit in one transaction per batch
// so a crash never leaves the cursor ahead of the data it points past
// (SPEC-0002 "Crash-Safety And Resumability").
//
// Governing: SPEC-0002 (Sync & Local Cache), ADR-0014 (sync-and-cache),
// ADR-0013 (secrets in OS keychain).
package syncengine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/joestump/reduit/internal/keychain"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/store"
)

// Retry policy for transient Proton failures. These are package vars, not
// constants, so tests can tighten them; production leaves them as-is and relies
// on go-proton-api's transport to honor Retry-After beneath these attempts
// (SPEC-0002 "Backoff on transient failure").
var (
	maxAttempts = 3
	backoffBase = 500 * time.Millisecond
)

// syncMailbox resumes the mailbox's client and runs one bootstrap-or-tail pass,
// recording the fatal cause (if any) on summary. It never returns an error: a
// failure is the mailbox's own (summary.Err) so a caller syncing many mailboxes
// is not derailed by one (SPEC-0002 "Per-Mailbox Sync Isolation").
func (e *Engine) syncMailbox(ctx context.Context, m store.Mailbox, summary *RunSummary) {
	client, seed, reauth, err := e.resumeClient(ctx, m)
	if err != nil {
		// An auth failure isolates to this mailbox: mark it needs_reauth only
		// when the credentials are genuinely bad/absent (not a transient network
		// blip), record the cause, and leave siblings untouched (SPEC-0002
		// "Auth failure isolates to its mailbox").
		if reauth {
			if serr := e.store.SetMailboxState(ctx, m.ID, store.MailboxStateNeedsReauth); serr != nil {
				e.log.Error("mark needs_reauth failed", "mailbox_id", m.ID, "error", serr)
			}
		}
		e.log.Error("mailbox sync could not authenticate",
			"mailbox_id", m.ID, "address", m.Address, "needs_reauth", reauth, "error", err)
		summary.Err = err
		return
	}
	defer client.Close()
	// Resume REUSES the cached session (no network), so tokens rotate only lazily
	// when the access token expires mid-run — on Unlock or a later API call. The
	// auth handler tracks the rotated values on the client; persist them once here
	// AFTER all operations, so the next resume matches (SPEC-0007 "Cross-Process
	// Session Resume"). Runs before client.Close (defer LIFO) so the client's
	// tokens are still readable.
	defer e.persistRotatedSession(ctx, m.ID, client, seed, summary)

	// Labels are fetched once per run and indexed for folder resolution, so each
	// message map is a cheap lookup rather than a per-message API call.
	var labels []proton.Label
	if err := e.retry(ctx, "labels", func() error {
		l, er := client.Labels(ctx)
		labels = l
		return er
	}); err != nil {
		summary.Err = fmt.Errorf("fetch labels: %w", err)
		return
	}
	folders := newFolderResolver(labels)

	ss, err := e.store.GetSyncState(ctx, m.ID)
	if err != nil {
		summary.Err = fmt.Errorf("read sync state: %w", err)
		return
	}

	// No persisted cursor → first sync → bootstrap. Otherwise tail the delta.
	if ss.EventCursor == nil {
		summary.Err = e.bootstrap(ctx, client, m, folders, summary)
		return
	}
	summary.Err = e.tail(ctx, client, m, *ss.EventCursor, folders, summary)
}

// resumeSeed holds the session values a resume started from, so the rotated
// values observed after operations can be diffed and persisted (SPEC-0007
// "Cross-Process Session Resume").
type resumeSeed struct {
	accessToken  string
	refreshToken string
	sessionUID   string
}

// resumeClient reconstructs an authenticated, unlocked Proton client for the
// mailbox from its stored secrets, mirroring how `reduit labels` resumes:
// keychain access + refresh token + stored session UID → Dialer.Resume (session
// REUSE, no network) → Unlock with the keychain passphrase. Reusing the cached
// access token preserves the 2FA-elevated scope key/salt access needs; an eager
// refresh would reduce it and fail Unlock's GetSalts with 403 code 9101. It
// returns the seed values so the caller can persist any tokens a lazy refresh
// rotates during the run, and reports whether the failure warrants flipping the
// mailbox to needs_reauth (bad/absent credentials) versus a transient failure
// retried next run. Nothing is persisted here: Resume makes no network call, so
// no rotation has happened yet.
func (e *Engine) resumeClient(ctx context.Context, m store.Mailbox) (client proton.Client, seed resumeSeed, reauth bool, err error) {
	if m.ProtonUserID == nil {
		return nil, seed, true, errors.New("mailbox has never authenticated")
	}

	refreshToken, err := e.keychain.Get(m.ID, keychain.RefreshToken)
	if err != nil {
		// A missing secret is a re-auth condition; an unavailable/locked keyring
		// is an environmental failure the operator must resolve, not a re-auth.
		return nil, seed, errors.Is(err, keychain.ErrNotFound), fmt.Errorf("read refresh token: %w", err)
	}
	if m.SessionUID == nil || *m.SessionUID == "" {
		return nil, seed, true, errors.New("mailbox predates session-uid tracking; re-auth required")
	}
	storedUID := *m.SessionUID
	accessToken, err := e.keychain.Get(m.ID, keychain.AccessToken)
	if err != nil {
		// A pre-fix row has a refresh token but no access token. Resuming without
		// it would force an eager refresh that reduces the scope and later 9101s on
		// key/salt access, so treat its absence as a re-auth condition: the
		// operator must re-authenticate (`reduit auth refresh`) to store one.
		if errors.Is(err, keychain.ErrNotFound) {
			return nil, seed, true, errors.New("mailbox predates full-scope resume (no stored access token); re-authenticate it with 'reduit auth refresh'")
		}
		return nil, seed, false, fmt.Errorf("read access token: %w", err)
	}
	seed = resumeSeed{accessToken: accessToken, refreshToken: refreshToken, sessionUID: storedUID}

	// Resume reuses the cached session (NewClient) and makes no network call, so
	// it cannot itself fail transiently; the first real call (Unlock below)
	// surfaces an invalid session. Proton refresh tokens are one-time-use, so this
	// layer never retries a resume.
	client, err = e.dialer.Resume(ctx, *m.ProtonUserID, storedUID, accessToken, refreshToken)
	if err != nil {
		// A rejected/invalid refresh token is a re-auth condition; a network
		// error is transient and must NOT flip the mailbox's state.
		return nil, seed, errors.Is(err, proton.ErrRefreshTokenInvalid), fmt.Errorf("resume session: %w", err)
	}

	passphrase, err := e.keychain.Get(m.ID, keychain.MailboxPassphrase)
	if err != nil {
		client.Close()
		return nil, seed, errors.Is(err, keychain.ErrNotFound), fmt.Errorf("read passphrase: %w", err)
	}
	pb := []byte(passphrase)
	defer zeroBytes(pb)
	if err := client.Unlock(ctx, pb); err != nil {
		client.Close()
		// A rejected passphrase means the stored secret no longer unlocks the
		// keys — a re-auth condition.
		return nil, seed, true, fmt.Errorf("unlock mailbox: %w", err)
	}
	return client, seed, false, nil
}

// persistRotatedSession writes back any session value a lazy refresh rotated
// during the run — the access token and refresh token (keychain secrets) and the
// session UID (non-secret store state) — comparing the client's current values
// against the seed the run started from. It runs as a deferred step after all
// operations. A failed refresh-token write is a re-auth condition: Proton refresh
// tokens are one-time-use, so once a lazy refresh spent the old token, a mailbox
// whose new token could not be stored cannot resume next run — flip it to
// needs_reauth and, if the run had not already failed, surface the cause. A
// failed access-token or UID write is recoverable (the persisted refresh token
// still drives the next resume's lazy refresh), so it is logged, not fatal.
func (e *Engine) persistRotatedSession(ctx context.Context, mailboxID string, client proton.Client, seed resumeSeed, summary *RunSummary) {
	if err := e.persistRotatedAccessToken(mailboxID, seed.accessToken, client.AccessToken()); err != nil {
		e.log.Error("store rotated access token failed", "mailbox_id", mailboxID, "error", err)
	}
	if err := e.persistRotatedToken(mailboxID, seed.refreshToken, client.RefreshToken()); err != nil {
		if serr := e.store.SetMailboxState(ctx, mailboxID, store.MailboxStateNeedsReauth); serr != nil {
			e.log.Error("mark needs_reauth failed", "mailbox_id", mailboxID, "error", serr)
		}
		e.log.Error("store rotated token failed", "mailbox_id", mailboxID, "error", err)
		if summary.Err == nil {
			summary.Err = fmt.Errorf("store rotated token: %w", err)
		}
	}
	if err := e.persistRotatedSessionUID(ctx, mailboxID, seed.sessionUID, client.SessionUID()); err != nil {
		e.log.Error("store rotated session uid failed", "mailbox_id", mailboxID, "error", err)
	}
}

// persistRotatedToken writes the new refresh token to the keychain only when it
// actually changed, avoiding a needless keychain write (and prompt on some
// platforms) when the token was not rotated.
func (e *Engine) persistRotatedToken(mailboxID, old, current string) error {
	if current == "" || current == old {
		return nil
	}
	return e.keychain.Set(mailboxID, keychain.RefreshToken, current)
}

// persistRotatedAccessToken writes the new access token to the keychain only
// when a lazy refresh actually rotated it. An empty current value is ignored so a
// run that produced none never clobbers the stored one.
func (e *Engine) persistRotatedAccessToken(mailboxID, old, current string) error {
	if current == "" || current == old {
		return nil
	}
	return e.keychain.Set(mailboxID, keychain.AccessToken, current)
}

// persistRotatedSessionUID writes the rotated session UID to the mailbox row
// only when a resume actually changed it. An empty current value is ignored so a
// resume that did not surface a UID never clobbers the stored one.
func (e *Engine) persistRotatedSessionUID(ctx context.Context, mailboxID, old, current string) error {
	if current == "" || current == old {
		return nil
	}
	return e.store.SetSessionUID(ctx, mailboxID, current)
}

// bootstrap performs a mailbox's first sync (SPEC-0002 "Bootstrap Then Tail").
// It captures the current event-stream head FIRST, then backfills the bounded
// window of history and, only after the backfill completes, persists that
// pre-backfill cursor as the resume point — so the subsequent tail starts from
// before the backfill and misses no event created while it ran. An interrupted
// backfill re-runs idempotently (messages converge on their stable hash), which
// is acceptable per the idempotency guarantees. It is also the re-bootstrap path
// a tail takes when Proton signals a stale view (Event.Refresh).
func (e *Engine) bootstrap(ctx context.Context, client proton.Client, m store.Mailbox, folders folderResolver, summary *RunSummary) error {
	var startCursor string
	if err := e.retry(ctx, "latest_event_id", func() error {
		c, er := client.LatestEventID(ctx)
		startCursor = c
		return er
	}); err != nil {
		return fmt.Errorf("latest event id: %w", err)
	}

	// A zero backfill window means "no time bound" — the full mailbox.
	var since time.Time
	if e.cfg.BackfillWindow > 0 {
		since = e.now().Add(-e.cfg.BackfillWindow)
	}

	var ids []string
	if err := e.retry(ctx, "backfill_ids", func() error {
		x, er := client.BackfillMessageIDs(ctx, since)
		ids = x
		return er
	}); err != nil {
		return fmt.Errorf("backfill message ids: %w", err)
	}

	// Ids arrive oldest-first, so each is applied in its own transaction: a
	// crash resumes forward without re-walking already-committed messages, and a
	// TERMINAL decrypt failure skips one message without poisoning the run.
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		dm, err := e.decrypt(ctx, client, id)
		if err != nil {
			// A TRANSIENT decrypt failure (network, retries exhausted) must NOT
			// be skipped: doing so would persist startCursor past this history
			// message, and since it predates that cursor the tail would never
			// re-fetch it — silent, permanent data loss. Abort the bootstrap
			// BEFORE the cursor is persisted so sync_state stays nil and the next
			// run re-bootstraps and recovers this message. Only genuinely
			// terminal failures (not found, crypto) skip-and-continue.
			if isTransient(err) {
				return fmt.Errorf("transient decrypt of %s aborted backfill: %w", id, err)
			}
			e.log.Warn("decrypt failed during backfill; skipping message",
				"mailbox_id", m.ID, "proton_id", id, "error", err)
			summary.Errors++
			continue
		}
		w := mapMessage(m.ID, dm, folders)
		res, err := e.store.ApplyMessage(ctx, w)
		if err != nil {
			return fmt.Errorf("apply backfilled message %s: %w", id, err)
		}
		applyCounts(summary, res, w)
	}

	if err := e.store.UpsertSyncState(ctx, m.ID, startCursor, e.now().UTC()); err != nil {
		return fmt.Errorf("persist bootstrap cursor: %w", err)
	}
	return nil
}

// tail applies the delta since the persisted cursor (SPEC-0002 "Subsequent sync
// tails the event stream"). It drains the event stream one batch at a time; each
// batch's message applies/deletes AND the advanced cursor commit in a single
// transaction, so a partial batch is never observable and an interrupted run
// resumes from the last committed cursor. A batch carrying Proton's Refresh flag
// aborts the tail and re-bootstraps, because Proton has declared the local view
// stale.
func (e *Engine) tail(ctx context.Context, client proton.Client, m store.Mailbox, cursor string, folders folderResolver, summary *RunSummary) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var batch proton.EventBatch
		if err := e.retry(ctx, "get_events", func() error {
			b, er := client.GetEvents(ctx, cursor)
			batch = b
			return er
		}); err != nil {
			return fmt.Errorf("get events: %w", err)
		}

		// Proton says the view is stale: discard the delta and re-bootstrap this
		// mailbox from a fresh head (SPEC-0002 "Full rescan on demand" path).
		if batch.Refresh() {
			e.log.Info("proton signaled a stale view; re-bootstrapping mailbox",
				"mailbox_id", m.ID, "address", m.Address)
			return e.bootstrap(ctx, client, m, folders, summary)
		}

		// No events → nothing to apply and the cursor cannot advance; the stream
		// is drained (SPEC-0002 incremental-by-default: no re-fetch of history).
		if len(batch.Events) == 0 {
			return nil
		}

		writes, deletes, err := e.prepareBatch(ctx, client, m.ID, batch, folders, summary)
		if err != nil {
			// A transient decrypt failure aborted the batch: leave the cursor
			// un-advanced so the next run retries this whole batch and misses no
			// message (see prepareBatch).
			return fmt.Errorf("prepare event batch: %w", err)
		}
		if err := e.commitBatch(ctx, m.ID, writes, deletes, batch.NextCursor, summary); err != nil {
			return fmt.Errorf("commit event batch: %w", err)
		}
		cursor = batch.NextCursor

		if !batch.More {
			return nil
		}
	}
}

// prepareBatch decrypts every create/update in the batch OUTSIDE the write
// transaction and collects the resulting writes plus the set of deletes. Doing
// the decrypts here means a TERMINAL decrypt failure skips just that message
// (errors++), never aborting the batch's transaction (SPEC-0002 "Decrypt
// failure does not poison the cache"). Multiple events touching one message
// within the batch collapse to that message's FINAL action, so a create+delete
// in the same batch decrypts nothing and simply deletes, and a create+update
// decrypts the current state once.
//
// A TRANSIENT decrypt failure (network, retries exhausted) is NOT skipped: it
// returns an error so tail aborts the batch BEFORE commitBatch advances the
// cursor. Skipping it would let the cursor move past the message's create event
// and the next run — tailing from the advanced cursor — would never re-fetch it,
// silently and permanently dropping it from the cache. Aborting instead leaves
// the cursor un-advanced so the whole batch is retried cleanly next run.
func (e *Engine) prepareBatch(ctx context.Context, client proton.Client, mailboxID string, batch proton.EventBatch, folders folderResolver, summary *RunSummary) (writes []store.MessageWrite, deletes []string, err error) {
	order := make([]string, 0)
	final := make(map[string]proton.EventAction)
	for _, ev := range batch.Events {
		for _, me := range ev.Messages {
			if _, seen := final[me.MessageID]; !seen {
				order = append(order, me.MessageID)
			}
			final[me.MessageID] = me.Action
		}
	}

	for _, id := range order {
		if final[id] == proton.EventDelete {
			deletes = append(deletes, id)
			continue
		}
		// EventCreate / EventUpdate: fetch and decrypt the current message.
		dm, derr := e.decrypt(ctx, client, id)
		if derr != nil {
			if isTransient(derr) {
				return nil, nil, fmt.Errorf("transient decrypt of %s aborted batch: %w", id, derr)
			}
			e.log.Warn("decrypt failed during tail; skipping message",
				"mailbox_id", mailboxID, "proton_id", id, "error", derr)
			summary.Errors++
			continue
		}
		writes = append(writes, mapMessage(mailboxID, dm, folders))
	}
	return writes, deletes, nil
}

// commitBatch applies a batch's writes and deletes and advances the cursor in
// ONE transaction, so the cursor never moves ahead of the data it points past
// and a failure rolls the whole batch back (SPEC-0002 "Cursor advances
// atomically with the delta"). Run counts are folded into the summary only after
// the transaction commits, so a rolled-back batch contributes nothing.
func (e *Engine) commitBatch(ctx context.Context, mailboxID string, writes []store.MessageWrite, deletes []string, cursor string, summary *RunSummary) error {
	var added, updated, deleted, attachments int
	err := e.store.WithTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		for _, w := range writes {
			res, err := tx.ApplyMessage(ctx, w)
			if err != nil {
				return err
			}
			if res.Inserted {
				added++
			} else {
				updated++
			}
			attachments += len(w.Attachments)
		}
		for _, pid := range deletes {
			ok, err := tx.DeleteMessageByProtonID(ctx, mailboxID, pid)
			if err != nil {
				return err
			}
			if ok {
				deleted++
			}
		}
		return tx.UpsertSyncState(ctx, mailboxID, cursor, e.now().UTC())
	})
	if err != nil {
		return err
	}
	summary.Added += added
	summary.Updated += updated
	summary.Deleted += deleted
	summary.Attachments += attachments
	return nil
}

// decrypt fetches and decrypts one message, retrying only transient (network)
// failures. A genuine decrypt failure returns immediately so the caller skips
// that one message rather than retrying a doomed decrypt.
func (e *Engine) decrypt(ctx context.Context, client proton.Client, id string) (proton.DecryptedMessage, error) {
	var dm proton.DecryptedMessage
	err := e.retry(ctx, "decrypt", func() error {
		d, er := client.DecryptMessage(ctx, id)
		dm = d
		return er
	})
	return dm, err
}

// applyCounts folds one applied message into the run summary: an inserted row is
// an add, an existing row an update, plus its attachment count.
func applyCounts(summary *RunSummary, res store.UpsertResult, w store.MessageWrite) {
	if res.Inserted {
		summary.Added++
	} else {
		summary.Updated++
	}
	summary.Attachments += len(w.Attachments)
}

// retry runs fn, retrying transient Proton errors with exponential backoff up to
// maxAttempts. Non-transient errors (auth, decrypt, not-found) return
// immediately; a cancelled context stops the loop. It never busy-loops — each
// retry waits backoffBase·2^(n-1), and go-proton-api's transport honors any
// Retry-After beneath it (SPEC-0002 "Rate-Limit Respect").
func (e *Engine) retry(ctx context.Context, op string, fn func() error) error {
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err = fn(); err == nil {
			return nil
		}
		if !isTransient(err) || attempt == maxAttempts {
			return err
		}
		backoff := backoffBase * time.Duration(1<<(attempt-1))
		e.log.Warn("transient sync error; backing off before retry",
			"op", op, "attempt", attempt, "backoff", backoff, "error", err)
		e.sleep(ctx, backoff)
	}
	return err
}

// isTransient reports whether err is a retryable network/rate-limit failure. The
// proton layer maps connection failures and 5xx/429 to ErrNetwork; everything
// else (auth, decrypt, not-found) is terminal for this attempt.
func isTransient(err error) bool {
	return errors.Is(err, proton.ErrNetwork)
}

// zeroBytes wipes a byte buffer holding secret material after use.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
