// Post-authentication Session methods. These were stubs at #18; #19
// fills in List / Select / Status / Fetch / Move with real per-account
// state from internal/mailbox.
//
// All branches that need account context read s.snapshotAccountID() so
// an unauthenticated caller (which cannot exist in the upstream library
// — emersion's state machine refuses post-auth commands without a
// successful Login — but we defend in depth) hits the same byte-
// identical "Mailbox does not exist" response a non-owned mailbox
// produces.
//
// Mutation methods (Create / Delete / Rename / Subscribe / Unsubscribe)
// are intentionally left as the SPEC-0003 "not supported" stub: Reduit
// does not let an IMAP client manipulate Proton's folder topology.
// Operators create labels through Proton or through the (future) MCP
// surface, and Reduit's sync worker materialises them as IMAP mailboxes.
//
// Governing: SPEC-0003 REQs "UID Stability", "Folder Hierarchy and
// Mapping", "Account Isolation in IMAP Operations", "Concurrent
// Sessions Per Account".

package imapserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"

	"github.com/joestump/reduit/internal/mailbox"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/pubsub"
)

// imapHierarchyDelim is the IMAP folder hierarchy separator. We expose
// only `/` because Proton's label paths use it natively (e.g.
// `Family/Tax`) and translating to a different IMAP delimiter (`.`,
// `\`) would force every Move/Copy/Status path to round-trip names
// through a re-encoder. Keeping `/` end-to-end means the resolver in
// internal/mailbox is the only place names are touched.
const imapHierarchyDelim rune = '/'

// errMailboxNotFound is the response the empty-backend stub returns
// for every named-mailbox operation. Identical text + code to a
// future not-found case so a malicious client cannot distinguish the
// two through black-box probing.
//
// Governing: SPEC-0003 REQ "SELECT of a non-owned mailbox fails as
// not-found".
var errMailboxNotFound = &imap.Error{
	Type: imap.StatusResponseTypeNo,
	Text: "Mailbox does not exist",
}

// errMailboxReadOnly is the response Create/Delete/Rename/Subscribe
// return: Reduit does not let IMAP clients manipulate Proton's label
// topology. Distinct text from errMailboxNotFound so a well-behaved
// client can show a meaningful error in its UI; the lack of an info
// leak is preserved because the response does not vary with whether
// the named mailbox actually exists.
var errMailboxReadOnly = &imap.Error{
	Type: imap.StatusResponseTypeNo,
	Text: "Reduit does not allow client-side mailbox modification",
}

// snapshotAccountID returns the session's authenticated account ID
// under the per-session lock. Empty string means unauthenticated; the
// caller MUST treat that as "no mailboxes match" without leaking the
// fact that the session is unauthenticated through a different error.
func (s *session) snapshotAccountID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accountID
}

// sessionState holds the post-Select per-session state. Per SPEC-0003
// REQ "Per-session state is isolated" each session gets its own copy;
// `selected` and `pendingDeletes` are NOT shared across sessions.
// Concurrent reads of `selected` go through the per-session mutex so a
// racing UNSELECT cannot tear the read.
//
// selectedMailboxID is the int64 primary-key ID of the selected
// mailbox; it is set alongside `selected` during Select and used by
// Idle to derive the pubsub key `"<accountID>:<mailboxID>"`.
//
// Governing: SPEC-0003 REQ "IDLE Support With Live Updates".
type sessionState struct {
	mu                sync.Mutex
	selected          *mailbox.Mailbox
	selectedMailboxID int64               // mirrors selected.ID; zero when no mailbox is selected
	pendingDeletes    map[uint32]struct{} // UIDs flagged \Deleted, awaiting EXPUNGE
}

// state lazily initialises the per-session state. Called from every
// post-Select handler; the first call after Login allocates, every
// subsequent call returns the same struct.
func (s *session) state() *sessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.selectedState == nil {
		s.selectedState = &sessionState{
			pendingDeletes: make(map[uint32]struct{}),
		}
	}
	return s.selectedState
}

// Select implements emersion/go-imap's Session.Select. Looks up the
// mailbox by (account_id, name); on miss returns the byte-identical
// "Mailbox does not exist" so a session for account A cannot probe the
// existence of account B's folders by SELECT timing/text.
//
// Governing: SPEC-0003 REQ "SELECT of a non-owned mailbox fails as
// not-found".
func (s *session) Select(name string, _ *imap.SelectOptions) (*imap.SelectData, error) {
	if s.backend.mailboxes == nil {
		return nil, errMailboxNotFound
	}
	acctID := s.snapshotAccountID()
	if acctID == "" {
		return nil, errMailboxNotFound
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mbox, err := s.backend.mailboxes.GetMailboxByName(ctx, acctID, name)
	if err != nil {
		// Both ErrMailboxNotFound (clean miss) and any other error map
		// to the same response. Other-error logging happens here so an
		// operator can correlate a SELECT failure with an underlying DB
		// issue.
		if !errors.Is(err, mailbox.ErrMailboxNotFound) {
			s.logger.LogAttrs(ctx, slog.LevelWarn, "imap select error",
				slog.String("account_id", acctID),
				slog.String("mailbox", name),
				slog.String("err", err.Error()))
		}
		return nil, errMailboxNotFound
	}

	count, err := s.backend.mailboxes.CountMessagesInMailbox(ctx, acctID, mbox.ID)
	if err != nil {
		s.logger.LogAttrs(ctx, slog.LevelWarn, "imap select count error",
			slog.String("account_id", acctID),
			slog.String("mailbox", name),
			slog.String("err", err.Error()))
		return nil, errMailboxNotFound
	}

	st := s.state()
	st.mu.Lock()
	st.selected = mbox
	st.selectedMailboxID = mbox.ID
	st.pendingDeletes = make(map[uint32]struct{})
	st.mu.Unlock()

	return &imap.SelectData{
		// We do not yet track per-mailbox flag inventories; advertise
		// the standard system flags so clients (Apple Mail, Thunderbird)
		// can display them. The wildcard in PermanentFlags signals
		// keyword support for future work.
		Flags: []imap.Flag{
			imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged,
			imap.FlagDeleted, imap.FlagDraft,
		},
		PermanentFlags: []imap.Flag{
			imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged,
			imap.FlagDeleted, imap.FlagDraft, imap.FlagWildcard,
		},
		NumMessages: count,
		UIDNext:     imap.UID(mbox.UIDNext),
		UIDValidity: mbox.UIDValidity,
	}, nil
}

func (s *session) Create(_ string, _ *imap.CreateOptions) error {
	return errMailboxReadOnly
}

func (s *session) Delete(_ string) error {
	return errMailboxReadOnly
}

func (s *session) Rename(_, _ string, _ *imap.RenameOptions) error {
	return errMailboxReadOnly
}

func (s *session) Subscribe(_ string) error {
	// Subscriptions are not persisted; pretend success so clients that
	// auto-subscribe on first SELECT (Apple Mail does this) do not
	// surface a confusing error.
	//
	// TODO(#44): when APPEND lands, persist subscriptions so a client's
	// "show only subscribed folders" view round-trips across sessions.
	return nil
}

func (s *session) Unsubscribe(_ string) error {
	return nil
}

// List walks the per-account mailbox set and writes one ListData per
// match. Accounts only see their own mailboxes; an unauthenticated
// session sees nothing (per the upstream library's state machine that
// branch should be unreachable, but we defend anyway).
//
// Governing: SPEC-0003 REQ "LIST shows only own folders".
func (s *session) List(w *imapserver.ListWriter, ref string, patterns []string, _ *imap.ListOptions) error {
	if s.backend.mailboxes == nil {
		return nil
	}
	acctID := s.snapshotAccountID()
	if acctID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mboxes, err := s.backend.mailboxes.ListMailboxes(ctx, acctID)
	if err != nil {
		s.logger.LogAttrs(ctx, slog.LevelWarn, "imap list error",
			slog.String("account_id", acctID),
			slog.String("err", err.Error()))
		// Returning an error here would propagate as a tagged BAD; an
		// empty result is a closer match to the spec ("LIST shows only
		// own folders") and avoids leaking back-end state.
		return nil
	}

	// Empty patterns is the LIST-extensions sentinel for "return the
	// hierarchy delimiter alone", which clients use to discover the
	// separator. emersion's imapmemserver does the same.
	if len(patterns) == 0 {
		return w.WriteList(&imap.ListData{
			Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect},
			Delim: imapHierarchyDelim,
		})
	}

	for _, mb := range mboxes {
		match := false
		for _, pattern := range patterns {
			if imapserver.MatchList(mb.Name, imapHierarchyDelim, ref, pattern) {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		data := &imap.ListData{
			Mailbox: mb.Name,
			Delim:   imapHierarchyDelim,
		}
		// Attach the special-use attribute for system folders so a
		// well-behaved client (Apple Mail, Thunderbird) can auto-route
		// Sent / Drafts / Trash / Archive correctly without the user
		// configuring it manually.
		//
		// Governing: SPEC-0003 REQ "System folders map to standard
		// names".
		if mb.Kind == mailbox.KindSystem {
			if attr := specialUseAttrFor(mb.Name); attr != "" {
				data.Attrs = append(data.Attrs, attr)
			}
		}
		if err := w.WriteList(data); err != nil {
			return err
		}
	}
	return nil
}

// specialUseAttrFor returns the IMAP special-use attribute for a
// system mailbox name, or "" if none applies. Mirrors the map in
// internal/mailbox.systemFolders so updates go in two places — kept
// duplicated rather than imported because the imap.MailboxAttr type
// lives in the emersion library and we do not want to expose that
// type on internal/mailbox's public surface.
func specialUseAttrFor(name string) imap.MailboxAttr {
	switch name {
	case "Sent":
		return imap.MailboxAttrSent
	case "Drafts":
		return imap.MailboxAttrDrafts
	case "Trash":
		return imap.MailboxAttrTrash
	case "Spam":
		return imap.MailboxAttrJunk
	case "Archive":
		return imap.MailboxAttrArchive
	case "All Mail":
		return imap.MailboxAttrAll
	}
	return ""
}

// Status returns the requested STATUS items for the named mailbox. Same
// account-scoping enforcement as Select; on miss returns the byte-
// identical "Mailbox does not exist".
//
// Governing: SPEC-0003 REQ "Account Isolation in IMAP Operations".
func (s *session) Status(name string, options *imap.StatusOptions) (*imap.StatusData, error) {
	if s.backend.mailboxes == nil {
		return nil, errMailboxNotFound
	}
	acctID := s.snapshotAccountID()
	if acctID == "" {
		return nil, errMailboxNotFound
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mbox, err := s.backend.mailboxes.GetMailboxByName(ctx, acctID, name)
	if err != nil {
		return nil, errMailboxNotFound
	}
	data := &imap.StatusData{Mailbox: name}
	if options.UIDValidity {
		data.UIDValidity = mbox.UIDValidity
	}
	if options.UIDNext {
		data.UIDNext = imap.UID(mbox.UIDNext)
	}
	if options.NumMessages {
		count, err := s.backend.mailboxes.CountMessagesInMailbox(ctx, acctID, mbox.ID)
		if err != nil {
			return nil, errMailboxNotFound
		}
		data.NumMessages = &count
	}
	if options.NumRecent {
		// We do not track \Recent (deprecated in IMAP4rev2 anyway);
		// always return 0 so clients that ask have a stable answer.
		zero := uint32(0)
		data.NumRecent = &zero
	}
	if options.NumUnseen {
		// Compute the real unseen (no `\Seen` flag) count via a per-flag
		// SQL accounting rather than surfacing the total. On error we
		// fail the whole STATUS with the byte-identical not-found
		// response so a back-end hiccup never leaks a distinguishable
		// error shape.
		//
		// Governing: SPEC-0003 REQ "Account Isolation in IMAP
		// Operations".
		unseen, err := s.backend.mailboxes.CountUnseenInMailbox(ctx, acctID, mbox.ID)
		if err != nil {
			s.logger.LogAttrs(ctx, slog.LevelWarn, "imap status unseen count error",
				slog.String("account_id", acctID),
				slog.String("mailbox", name),
				slog.String("err", err.Error()))
			return nil, errMailboxNotFound
		}
		data.NumUnseen = &unseen
	}
	return data, nil
}

// appendMaxLiteralBytes caps the size of an APPEND literal Reduit will
// buffer in memory before encrypt + import. Proton's import endpoint
// rejects messages over ~50 MiB (proton.MaxImportSize accounts for the
// ~33% base64 overhead on top); we reject earlier at the raw-byte
// boundary so a hostile client cannot make us buffer an unbounded
// literal before the upstream size check fires. 50 MiB of raw bytes is
// already past what Proton accepts post-encoding, so this is a generous
// ceiling, not a new restriction.
const appendMaxLiteralBytes = 50 * 1024 * 1024

// AppendLimit implements emersion's optional SessionAppendLimit
// interface. Returning a non-zero limit makes the server advertise
// `APPENDLIMIT=<n>` in CAPABILITY (RFC 7889) AND makes emersion reject an
// oversized APPEND literal with `[TOOBIG]` BEFORE the client streams the
// body — so a client learns the ceiling up front and gets an early
// rejection instead of uploading up to 50 MiB only to be refused.
//
// The value is the same appendMaxLiteralBytes the Append handler enforces
// as a defense-in-depth second check (a hostile LiteralReader could
// under-report Size()). appendMaxLiteralBytes fits in a uint32 (50 MiB ≪
// 4 GiB), so the conversion is lossless.
//
// Governing: SPEC-0003 REQ "Folder Hierarchy and Mapping".
func (s *session) AppendLimit() uint32 {
	return uint32(appendMaxLiteralBytes)
}

// Append implements the IMAP APPEND verb: a client uploads a full
// RFC822 message into the named mailbox. Reduit translates this into a
// Proton import under the destination mailbox's label, then materialises
// the imported message into local mailbox state so the new UID is
// returned in the APPENDUID response (RFC 4315) and the message is
// immediately visible to a subsequent SELECT/FETCH.
//
// Clients use APPEND for save-to-Drafts (Apple Mail), restore-from-
// backup (imapsync / offlineimap), and drag-to-folder. It is the inbound
// counterpart to SMTP submission (the outbound path) and is independent
// of it.
//
// Order of operations (import-before-materialise, mirroring MOVE/COPY's
// "Proton authoritative, local mirror follows"):
//  1. Resolve the destination mailbox (account-scoped). A non-owned or
//     unknown name returns the byte-identical not-found response.
//  2. Read the literal into memory (bounded by appendMaxLiteralBytes).
//  3. ImportMessage at Proton under the mailbox's label. On failure,
//     nothing has touched local state, so we surface a transient NO and
//     the client retries the whole APPEND.
//  4. Upsert the message row + AssignUID in the destination mailbox.
//     The assigned UID is the APPENDUID.
//
// Deferred (reported precisely): APPEND does not yet round-trip the
// supplied \Answered / \Flagged / \Draft flags or the client InternalDate
// onto Proton beyond the unread (\Seen) bit and the import's own receive
// time — Proton's import metadata models neither IMAP keywords nor a
// caller-chosen internal date. The flags the client sent ARE persisted
// on the local message row so a same-session FETCH reflects them; they
// are reconciled to Proton's authoritative view on the next sync.
//
// Governing: SPEC-0003 REQ "Folder Hierarchy and Mapping" — the appended
// message lands in exactly the destination mailbox's Proton label, the
// same translation MOVE/COPY use; SPEC-0003 REQ "Account Isolation in
// IMAP Operations" — an APPEND to a non-owned mailbox is indistinguishable
// from a genuine not-found.
func (s *session) Append(mailboxName string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	if s.backend.mailboxes == nil || s.backend.proton == nil {
		// Without both the mailbox store and the Proton client there is
		// no path to durably accept the message; refuse rather than
		// silently dropping the upload.
		return nil, errMailboxReadOnly
	}
	acctID := s.snapshotAccountID()
	if acctID == "" {
		return nil, errMailboxNotFound
	}

	// Resolve the destination FIRST so a non-owned / unknown mailbox is
	// rejected before we buffer the (potentially large) literal. The
	// literal still has to be drained for the protocol to stay in sync,
	// but emersion drains any unread literal bytes when the handler
	// returns an error, so an early return here is safe.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	destMbox, err := s.backend.mailboxes.GetMailboxByName(ctx, acctID, mailboxName)
	if err != nil {
		return nil, errMailboxNotFound
	}

	if r.Size() > appendMaxLiteralBytes {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeTooBig,
			Text: "Message too large",
		}
	}

	raw, err := readLiteral(r, appendMaxLiteralBytes)
	if err != nil {
		s.logger.LogAttrs(ctx, slog.LevelWarn, "imap append literal read failed",
			slog.String("account_id", acctID),
			slog.String("mailbox", mailboxName),
			slog.String("err", err.Error()))
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Could not read appended message",
		}
	}

	// \Seen in the supplied flags ⇒ the message is already read ⇒ import
	// as NOT unread. Absent \Seen, import unread (the default for newly-
	// delivered mail).
	unread := !appendFlagsHaveSeen(options)

	cli, err := s.protonClient(ctx, acctID)
	if err != nil {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Cannot reach Proton; try again",
		}
	}

	protonID, err := cli.ImportMessage(ctx, raw, destMbox.ProtonLabelID, unread)
	if err != nil {
		s.logger.LogAttrs(ctx, slog.LevelWarn, "imap append proton import failed",
			slog.String("account_id", acctID),
			slog.String("mailbox", mailboxName),
			slog.String("dest_label", destMbox.ProtonLabelID),
			slog.String("err", err.Error()))
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Proton import failed",
		}
	}

	// Materialise locally. Proton is now the source of truth (the message
	// exists there); a failure to mirror it locally is logged but does
	// NOT fail the APPEND — the next sync round will materialise the row
	// and assign a UID. We only lose the APPENDUID optimisation in that
	// case, which RFC 4315 permits the server to omit.
	internalDate := time.Now().UTC()
	if options != nil && !options.Time.IsZero() {
		internalDate = options.Time.UTC()
	}
	mid, err := s.backend.mailboxes.UpsertMessage(ctx, &mailbox.Message{
		AccountID:       acctID,
		ProtonMessageID: protonID,
		RFC822Size:      int64(len(raw)),
		Flags:           encodeFlags(appendFlags(options)),
		InternalDate:    internalDate,
	})
	if err != nil {
		s.logger.LogAttrs(ctx, slog.LevelWarn, "imap append local upsert failed; relying on next sync",
			slog.String("account_id", acctID),
			slog.String("proton_message_id", protonID),
			slog.String("err", err.Error()))
		return &imap.AppendData{UIDValidity: destMbox.UIDValidity}, nil
	}
	uid, err := s.backend.mailboxes.AssignUID(ctx, acctID, destMbox.ID, mid)
	if err != nil {
		// The most common cause here is a DUPLICATE APPEND: the same
		// message imported (or re-imported, e.g. an idempotent client
		// retry) is already linked to this mailbox, so the
		// (mailbox_id, message_id) UNIQUE index refuses a second UID. In
		// that case the message is already fully materialised at its
		// existing UID — there is nothing for sync to fix; we simply omit
		// the APPENDUID (RFC 4315 makes APPENDUID optional) and return a
		// bare OK. A genuinely transient AssignUID failure (UID exhaustion,
		// DB hiccup) lands here too and is equally safe: the message row
		// exists and the next sync round will link it. Either way APPEND
		// succeeds; only the APPENDUID optimisation is lost.
		s.logger.LogAttrs(ctx, slog.LevelWarn, "imap append uid assign skipped; message already present or transient error, omitting APPENDUID",
			slog.String("account_id", acctID),
			slog.Int64("dest_mailbox_id", destMbox.ID),
			slog.Int64("message_id", mid),
			slog.String("err", err.Error()))
		return &imap.AppendData{UIDValidity: destMbox.UIDValidity}, nil
	}

	return &imap.AppendData{
		UID:         imap.UID(uid),
		UIDValidity: destMbox.UIDValidity,
	}, nil
}

// readLiteral reads up to limit+1 bytes from r and returns an error if
// the stream exceeds limit. The +1 read lets us distinguish "exactly
// limit bytes" (accepted) from "more than limit" (rejected) without a
// second Size() check, since a hostile LiteralReader could under-report
// Size().
func readLiteral(r imap.LiteralReader, limit int64) ([]byte, error) {
	buf := make([]byte, 0, clampCap(r.Size(), limit))
	tmp := make([]byte, 32*1024)
	var total int64
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			total += int64(n)
			if total > limit {
				return nil, errors.New("imapserver: append literal exceeds size limit")
			}
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return buf, nil
			}
			return nil, err
		}
	}
}

// clampCap returns a sane initial capacity for the literal buffer:
// the reported size when it is positive and within the limit, else a
// small default so an under/over-reported Size() does not let a client
// trick us into a giant up-front allocation.
func clampCap(size, limit int64) int {
	if size <= 0 || size > limit {
		return 64 * 1024
	}
	return int(size)
}

// appendFlags returns the flags the client supplied with APPEND, or nil.
func appendFlags(options *imap.AppendOptions) []imap.Flag {
	if options == nil {
		return nil
	}
	return options.Flags
}

// appendFlagsHaveSeen reports whether the APPEND flag set includes
// \Seen.
func appendFlagsHaveSeen(options *imap.AppendOptions) bool {
	for _, f := range appendFlags(options) {
		if f == imap.FlagSeen {
			return true
		}
	}
	return false
}

// encodeFlags serialises a flag slice into the comma-separated form the
// messages.flags column stores. It is the inverse of decodeFlags.
func encodeFlags(flags []imap.Flag) string {
	if len(flags) == 0 {
		return ""
	}
	parts := make([]string, 0, len(flags))
	for _, f := range flags {
		s := strings.TrimSpace(string(f))
		if s == "" {
			continue
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ",")
}

// idleTimeout is the IDLE session duration before the server emits
// `* BYE Idle timeout` and closes the connection. RFC 2177 mandates
// that clients re-issue IDLE at least every 29 minutes; we enforce
// the limit at exactly 29 minutes so a client that never sends DONE
// is disconnected before it expects.
//
// Governing: SPEC-0003 REQ "IDLE Support With Live Updates" (RFC 2177
// idle timeout of 29 minutes).
const idleTimeout = 29 * time.Minute

// idlePubSubKey returns the pubsub bus key for the given account and
// mailbox ID. The format `<accountID>:<mailboxID>` matches the design
// in SPEC-0003 § "Pubsub for IMAP IDLE".
//
// Governing: SPEC-0003 REQ "IDLE Support With Live Updates",
//
//	SPEC-0003 REQ "Concurrent Sessions Per Account".
func idlePubSubKey(accountID string, mailboxID int64) string {
	return fmt.Sprintf("%s:%d", accountID, mailboxID)
}

// Poll runs after every authenticated command. When the bus is wired
// it drains any pubsub events that arrived since the last command and
// emits the corresponding unilateral updates. When the bus is nil (or
// no mailbox is selected) it is a no-op that returns nil so the
// upstream library's command loop continues without interruption.
//
// Governing: SPEC-0003 REQ "IDLE Support With Live Updates".
func (s *session) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	if s.backend.bus == nil {
		return nil
	}
	acctID := s.snapshotAccountID()
	if acctID == "" {
		return nil
	}
	st := s.state()
	st.mu.Lock()
	mboxID := st.selectedMailboxID
	st.mu.Unlock()
	if mboxID == 0 {
		return nil
	}
	// We do not maintain a persistent subscription for Poll (that would
	// require per-session goroutine infrastructure beyond what this PR
	// targets). Poll is best-effort: the critical path for live updates
	// is Idle, which holds a real subscription.
	return nil
}

// Idle subscribes to the in-process pubsub bus for the selected
// mailbox and translates each Update into the appropriate IMAP
// unilateral response:
//
//   - MessageAdded  → WriteNumMessages (EXISTS) with the new count
//   - MessageRemoved → WriteExpunge with sequence number 1 (exact
//     seqnum determination requires a full mailbox scan; the client
//     resynchronises via NOOP/STATUS on reconnect anyway per RFC 2177)
//   - MessageFlagChanged → WriteMessageFlags (FETCH FLAGS)
//
// Idle returns nil on clean DONE, or an error if the connection
// fails mid-IDLE.
//
// Governing: SPEC-0003 REQ "IDLE Support With Live Updates",
//
//	SPEC-0003 REQ "Concurrent Sessions Per Account".
func (s *session) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	// Delegate to the testable loop with the production timeout and
	// an updateWriterAdapter that bridges idleWriter → *UpdateWriter.
	var writer idleWriter
	if w != nil {
		writer = &updateWriterAdapter{w: w}
	}
	return idleLoopWithWriter(s, writer, stop, idleTimeout)
}

// idleWriter is the minimal interface needed by the IDLE emit path.
// The production path satisfies it via *imapserver.UpdateWriter; the
// test path satisfies it via trackingWriter in idle_test.go.
//
// The interface is package-private so it does not appear in the public
// API of this package.
//
// Governing: SPEC-0003 REQ "IDLE Support With Live Updates".
type idleWriter interface {
	writeNumMessages(uint32) error
	writeExpunge(uint32) error
	writeMessageFlags(seqNum uint32, uid uint32, flags []string) error
}

// updateWriterAdapter wraps *imapserver.UpdateWriter so it satisfies
// idleWriter. This is the production bridge; tests inject a trackingWriter
// directly.
type updateWriterAdapter struct {
	w *imapserver.UpdateWriter
}

func (a *updateWriterAdapter) writeNumMessages(n uint32) error { return a.w.WriteNumMessages(n) }
func (a *updateWriterAdapter) writeExpunge(seq uint32) error   { return a.w.WriteExpunge(seq) }
func (a *updateWriterAdapter) writeMessageFlags(seqNum, _ uint32, flags []string) error {
	imapFlags := make([]imap.Flag, 0, len(flags))
	for _, f := range flags {
		imapFlags = append(imapFlags, imap.Flag(f))
	}
	return a.w.WriteMessageFlags(seqNum, 0, imapFlags)
}

// runIdleLoop is the testable core of the Idle event loop. It accepts
// a timeout override and a nil UpdateWriter (used in goroutine-lifecycle
// tests that do not need to emit wire bytes). When w is nil the loop
// still subscribes to pubsub and honours stop/timeout, but skips the
// emit step.
//
// Governing: SPEC-0003 REQ "IDLE Support With Live Updates".
func runIdleLoop(s *session, stop <-chan struct{}, timeout time.Duration) error {
	return idleLoopWithWriter(s, nil, stop, timeout)
}

// idleLoopWithWriter is the fully parameterised IDLE loop. Both
// production (via Idle → updateWriterAdapter) and tests (via nil or
// trackingWriter) flow through this.
//
// Governing: SPEC-0003 REQ "IDLE Support With Live Updates",
//
//	SPEC-0003 REQ "Concurrent Sessions Per Account".
func idleLoopWithWriter(s *session, w idleWriter, stop <-chan struct{}, timeout time.Duration) error {
	acctID := s.snapshotAccountID()
	if acctID == "" || s.backend.bus == nil {
		select {
		case <-stop:
			return nil
		case <-time.After(timeout):
			return &imap.Error{Type: imap.StatusResponseTypeBye, Text: "Idle timeout"}
		}
	}

	st := s.state()
	st.mu.Lock()
	mboxID := st.selectedMailboxID
	st.mu.Unlock()

	if mboxID == 0 {
		select {
		case <-stop:
			return nil
		case <-time.After(timeout):
			return &imap.Error{Type: imap.StatusResponseTypeBye, Text: "Idle timeout"}
		}
	}

	// Governing: SPEC-0003 REQ "IDLE Support With Live Updates" —
	// subscribe to pubsub keyed by (account_id, mailbox_id).
	// Governing: SPEC-0003 REQ "Concurrent Sessions Per Account" —
	// multiple sessions for the same account subscribe independently;
	// Bus.Publish fans out to all of them simultaneously.
	key := idlePubSubKey(acctID, mboxID)
	updates, unsub := s.backend.bus.Subscribe(key, 0)
	defer unsub()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-stop:
			return nil
		case <-timer.C:
			return &imap.Error{Type: imap.StatusResponseTypeBye, Text: "Idle timeout"}
		case u, ok := <-updates:
			if !ok {
				// Bus closed (server shutdown); exit cleanly.
				return nil
			}
			if w != nil {
				if err := s.emitIdleUpdateTo(w, u); err != nil {
					return err
				}
			}
		}
	}
}

// emitIdleUpdateTo is the testable core of the update emission path. It writes
// to an idleWriter instead of *imapserver.UpdateWriter so tests can
// inject a trackingWriter without a live TCP connection.
//
// Governing: SPEC-0003 REQ "IDLE Support With Live Updates".
func (s *session) emitIdleUpdateTo(w idleWriter, u pubsub.Update) error {
	ctx := context.Background()
	acctID := s.snapshotAccountID()

	switch u.Kind {
	case pubsub.MessageAdded:
		// Emit EXISTS with the updated message count. We re-query the
		// mailbox count so the number is accurate; on error we skip the
		// update rather than emitting a stale EXISTS, which would confuse
		// clients into thinking more messages exist than actually do.
		if s.backend.mailboxes == nil {
			return nil
		}
		st := s.state()
		st.mu.Lock()
		mboxID := st.selectedMailboxID
		st.mu.Unlock()
		if mboxID == 0 {
			return nil
		}
		qCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		count, err := s.backend.mailboxes.CountMessagesInMailbox(qCtx, acctID, mboxID)
		if err != nil {
			s.logger.LogAttrs(ctx, slog.LevelWarn, "idle: count failed; skipping EXISTS",
				slog.String("account_id", acctID),
				slog.Int64("mailbox_id", mboxID),
				slog.String("err", err.Error()))
			return nil
		}
		return w.writeNumMessages(count)

	case pubsub.MessageRemoved:
		// Emit EXPUNGE. We do not know the exact sequence number from
		// the pubsub payload (that would require a full mailbox scan
		// which is expensive mid-IDLE), so we emit seqnum 1 as a
		// conservative signal. The client MUST RESYNC after seeing an
		// EXPUNGE it cannot place; RFC 7162 (CONDSTORE) is the long-
		// term fix, deferred to a later story.
		return w.writeExpunge(1)

	case pubsub.MessageFlagChanged:
		// Emit FETCH with the new flags. seqnum 1 and uid 0 are safe
		// placeholders — the emersion WriteMessageFlags helper writes
		// `* 1 FETCH (FLAGS (...))` which tells the client flags
		// changed; it resynchronises as needed. The UID is omitted
		// (zero) because we do not carry it in the pubsub payload.
		return w.writeMessageFlags(1, 0, u.Flags)

	default:
		// Unknown kind — log and skip. Do NOT return an error; a
		// future pubsub.Kind added by another story should not kill
		// existing IDLE sessions.
		s.logger.LogAttrs(ctx, slog.LevelWarn, "idle: unknown update kind; skipping",
			slog.String("account_id", acctID),
			slog.Int("kind", int(u.Kind)))
		return nil
	}
}

// Unselect clears the per-session selected mailbox state. Per SPEC-0003
// REQ "Per-session state is isolated" this only affects THIS session.
func (s *session) Unselect() error {
	st := s.state()
	st.mu.Lock()
	st.selected = nil
	st.selectedMailboxID = 0
	st.pendingDeletes = make(map[uint32]struct{})
	st.mu.Unlock()
	return nil
}

// Expunge removes every message in the selected mailbox that the
// caller has marked \Deleted (via STORE) and that falls in the
// optional UID set. Per SPEC-0003 REQ "Reused message ID does not get
// a reused UID" the expunge deletes ONLY the (mailbox, message) link;
// the underlying message row is preserved so a future re-add gets a
// fresh UID, never the prior one.
func (s *session) Expunge(_ *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	if s.backend.mailboxes == nil {
		return errMailboxNotFound
	}
	acctID := s.snapshotAccountID()
	if acctID == "" {
		return errMailboxNotFound
	}
	st := s.state()
	st.mu.Lock()
	mbox := st.selected
	pending := st.pendingDeletes
	st.mu.Unlock()
	if mbox == nil {
		return errMailboxNotFound
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Snapshot the current mailbox contents so we can map UIDs back to
	// message IDs without holding the per-session lock across DB calls.
	msgs, err := s.backend.mailboxes.ListMessagesInMailbox(ctx, acctID, mbox.ID)
	if err != nil {
		return errMailboxNotFound
	}

	for _, m := range msgs {
		if _, deleted := pending[m.UID]; !deleted {
			continue
		}
		if uids != nil && !uids.Contains(imap.UID(m.UID)) {
			continue
		}
		if _, err := s.backend.mailboxes.RemoveMessageFromMailbox(ctx, acctID, mbox.ID, m.MessageID); err != nil {
			s.logger.LogAttrs(ctx, slog.LevelWarn, "imap expunge remove failed",
				slog.String("account_id", acctID),
				slog.Int64("mailbox_id", mbox.ID),
				slog.Int64("message_id", m.MessageID),
				slog.String("err", err.Error()))
		}
	}

	// Clear the pending-delete set; whatever the EXPUNGE did or did not
	// touch is now committed.
	st.mu.Lock()
	st.pendingDeletes = make(map[uint32]struct{})
	st.mu.Unlock()
	return nil
}

func (s *session) Search(_ imapserver.NumKind, _ *imap.SearchCriteria, _ *imap.SearchOptions) (*imap.SearchData, error) {
	// SEARCH delegates to Proton's full-text search; not yet wired.
	// Per the spec's "Out of scope" section in SPEC-0003 we may return
	// an empty result set rather than refuse outright. emersion's
	// SearchData has no UID-only flag at this version; an empty All
	// set is the conformant "no matches" response.
	return &imap.SearchData{}, nil
}

// Fetch writes FETCH responses for every message in numSet matching the
// requested options. Metadata items (UID / Flags / InternalDate /
// RFC822.SIZE) come straight from the local `messages` row. Body items
// (BODY[], the obsolete RFC822* family, BODY[HEADER], BODY[TEXT], and
// their <partial> ranges) require the real message content, which Reduit
// does NOT store locally — it is fetched from Proton and decrypted on
// demand via GetMessageRFC822.
//
// The Proton fetch happens at most once per message per Fetch call: the
// full RFC822 is materialised lazily the first time any body section for
// that message is requested, then every section (full / header / text /
// partial) is sliced from those bytes.
//
// Governing: SPEC-0003 design "FETCH BODY[] on big messages" — full
// fetch + decrypt, bodies not stored locally.
func (s *session) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	if s.backend.mailboxes == nil {
		return errMailboxNotFound
	}
	acctID := s.snapshotAccountID()
	if acctID == "" {
		return errMailboxNotFound
	}
	st := s.state()
	st.mu.Lock()
	mbox := st.selected
	st.mu.Unlock()
	if mbox == nil {
		return errMailboxNotFound
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	msgs, err := s.backend.mailboxes.ListMessagesInMailbox(ctx, acctID, mbox.ID)
	if err != nil {
		return errMailboxNotFound
	}

	for i, m := range msgs {
		seqNum := uint32(i + 1)
		if !numSetContains(numSet, seqNum, m.UID) {
			continue
		}
		rw := w.CreateMessage(seqNum)
		if options.UID {
			rw.WriteUID(imap.UID(m.UID))
		}
		if options.Flags {
			rw.WriteFlags(decodeFlags(m.Flags))
		}
		if options.InternalDate {
			rw.WriteInternalDate(m.InternalDate)
		}
		if options.RFC822Size {
			rw.WriteRFC822Size(m.RFC822Size)
		}
		if len(options.BodySection) > 0 {
			if err := s.writeBodySections(ctx, rw, acctID, m, options.BodySection); err != nil {
				// A body-fetch failure (Proton unreachable, mailbox still
				// locked, decrypt failure) must not poison the whole FETCH
				// response: we have already written this message's opening
				// paren and any metadata items. Close the message and
				// surface the error so emersion emits a tagged NO; the
				// client retries.
				_ = rw.Close()
				return err
			}
		}
		if err := rw.Close(); err != nil {
			return err
		}
	}
	return nil
}

// writeBodySections materialises the message's RFC822 once and writes
// each requested section as a BODY[...] literal. Supported sections:
//
//   - BODY[] / RFC822 — the full message.
//   - BODY[HEADER] / RFC822.HEADER — the MIME header block (through the
//     blank line that separates header from body, inclusive).
//   - BODY[TEXT] / RFC822.TEXT — the body after that blank line.
//   - any of the above with a <offset.size> Partial range.
//
// Specific MIME part addressing (BODY[1.2], BODY[1.MIME]) is NOT yet
// supported; an unsupported specifier yields an empty literal rather
// than an error so a client requesting a mix of sections still gets the
// ones we can serve. Full-message BODY[] — the headline client need —
// is always served.
//
// Governing: SPEC-0003 design "FETCH BODY[] on big messages".
func (s *session) writeBodySections(ctx context.Context, rw *imapserver.FetchResponseWriter, acctID string, m *mailbox.MessageInMailbox, sections []*imap.FetchItemBodySection) error {
	payloads, err := s.bodySectionsForMessage(ctx, acctID, m, sections)
	if err != nil {
		return err
	}
	for i, section := range sections {
		payload := payloads[i]
		wc := rw.WriteBodySection(section, int64(len(payload)))
		_, werr := wc.Write(payload)
		cerr := wc.Close()
		if werr != nil {
			return werr
		}
		if cerr != nil {
			return cerr
		}
	}
	return nil
}

// bodySectionsForMessage fetches + decrypts the message's RFC822 once,
// then slices it into the bytes each requested section asks for. It is
// the testable core of the BODY[] path — it touches Proton and the
// section logic but never the (unconstructable-in-tests) FetchWriter, so
// unit tests can assert the lazy-fetch + slicing behaviour without a
// live TCP connection. The returned slice is index-aligned with
// `sections`.
//
// Governing: SPEC-0003 design "FETCH BODY[] on big messages".
func (s *session) bodySectionsForMessage(ctx context.Context, acctID string, m *mailbox.MessageInMailbox, sections []*imap.FetchItemBodySection) ([][]byte, error) {
	cli, err := s.protonClient(ctx, acctID)
	if err != nil {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Cannot reach Proton; try again",
		}
	}
	raw, err := cli.GetMessageRFC822(ctx, m.ProtonMessageID)
	if err != nil {
		s.logger.LogAttrs(ctx, slog.LevelWarn, "imap fetch body retrieval failed",
			slog.String("account_id", acctID),
			slog.String("proton_message_id", m.ProtonMessageID),
			slog.String("err", err.Error()))
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Message body temporarily unavailable",
		}
	}

	out := make([][]byte, len(sections))
	for i, section := range sections {
		out[i] = bodySectionBytes(raw, section)
	}
	return out, nil
}

// bodySectionBytes slices the full RFC822 message into the bytes a
// single BODY[...] section asks for, applying the Specifier (full /
// header / text), the HEADER.FIELDS / HEADER.FIELDS.NOT field filters,
// and any <offset.size> Partial range. An unsupported specifier (a
// specific MIME part) returns an empty slice.
func bodySectionBytes(raw []byte, section *imap.FetchItemBodySection) []byte {
	var out []byte
	switch {
	case len(section.Part) > 0:
		// Specific MIME-part addressing is not implemented; emit empty.
		out = nil
	case section.Specifier == imap.PartSpecifierHeader:
		switch {
		case len(section.HeaderFields) > 0:
			// BODY[HEADER.FIELDS (...)] — only the named header lines.
			out = filterHeaderFields(rfc822Header(raw), section.HeaderFields, false)
		case len(section.HeaderFieldsNot) > 0:
			// BODY[HEADER.FIELDS.NOT (...)] — every header line EXCEPT
			// the named ones.
			out = filterHeaderFields(rfc822Header(raw), section.HeaderFieldsNot, true)
		default:
			// BODY[HEADER] — the whole header block.
			out = rfc822Header(raw)
		}
	case section.Specifier == imap.PartSpecifierText:
		out = rfc822Text(raw)
	default:
		// PartSpecifierNone (BODY[] / RFC822) — the whole message.
		out = raw
	}
	return applyPartial(out, section.Partial)
}

// filterHeaderFields returns the subset of a raw RFC822 header block
// selected by `fields`. When exclude is false it keeps ONLY the named
// fields (HEADER.FIELDS); when true it keeps every field EXCEPT the
// named ones (HEADER.FIELDS.NOT). Field-name matching is case-
// insensitive per RFC 5322. Folded continuation lines (lines beginning
// with SP or TAB) stay attached to the header line they continue, so a
// multi-line Subject or Received is emitted whole.
//
// The output is terminated with a trailing CRLF (the blank line that
// closes a header block) so clients see a well-formed, parseable header
// section — matching what BODY[HEADER] returns.
func filterHeaderFields(header []byte, fields []string, exclude bool) []byte {
	want := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		want[strings.ToLower(strings.TrimSpace(f))] = struct{}{}
	}

	var out []byte
	keep := false // whether the current (possibly folded) header is being kept
	for _, line := range splitHeaderLines(header) {
		// A continuation line (folded value) begins with SP or HTAB; it
		// inherits the keep decision of the header line it continues.
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if keep {
				out = append(out, line...)
			}
			continue
		}
		// A blank line terminates the header block; do not carry it into
		// the per-field output (we append our own terminator below).
		trimmed := strings.TrimRight(string(line), "\r\n")
		if trimmed == "" {
			continue
		}
		name := trimmed
		if i := strings.IndexByte(trimmed, ':'); i >= 0 {
			name = trimmed[:i]
		}
		_, named := want[strings.ToLower(strings.TrimSpace(name))]
		keep = named != exclude // keep iff (named && !exclude) || (!named && exclude)
		if keep {
			out = append(out, line...)
		}
	}
	// Terminate with the blank line that closes a header block.
	out = append(out, '\r', '\n')
	return out
}

// splitHeaderLines splits a header block into individual lines, each
// retaining its trailing CRLF (or LF). Unlike strings.Split it keeps the
// line terminators so the reassembled output is byte-faithful to the
// source header.
func splitHeaderLines(header []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(header); i++ {
		if header[i] == '\n' {
			lines = append(lines, header[start:i+1])
			start = i + 1
		}
	}
	if start < len(header) {
		lines = append(lines, header[start:])
	}
	return lines
}

// rfc822HeaderText splits a raw RFC822 message at the blank line that
// separates the header block from the body. Returns the header (through
// and including the separating CRLF/LF) and the remaining body. If no
// separator is found the whole message is treated as header with an
// empty body — the conservative reading for a malformed message.
func rfc822HeaderText(raw []byte) (header, text []byte) {
	// RFC 5322 uses CRLF; tolerate bare LF for robustness against any
	// upstream normalisation. Prefer the CRLFCRLF boundary, fall back to
	// LFLF.
	if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
		return raw[:idx+4], raw[idx+4:]
	}
	if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		return raw[:idx+2], raw[idx+2:]
	}
	return raw, nil
}

func rfc822Header(raw []byte) []byte {
	h, _ := rfc822HeaderText(raw)
	return h
}

func rfc822Text(raw []byte) []byte {
	_, t := rfc822HeaderText(raw)
	return t
}

// applyPartial restricts data to the <offset.size> window an IMAP
// BODY[]<o.s> request specifies. An offset past the end yields an empty
// slice (RFC 3501 §6.4.5); a size that overruns the end is clamped.
//
// emersion parses the partial size as a signed int64 straight off the
// wire, so a hostile client can send a near-MaxInt64 size. The window
// is computed with overflow-safe SUBTRACTION (avail = len - offset, then
// clamp size to avail) rather than the additive `offset + size`, which
// would overflow to a negative end and panic on the slice expression.
func applyPartial(data []byte, p *imap.SectionPartial) []byte {
	if p == nil {
		return data
	}
	if p.Offset < 0 || p.Offset >= int64(len(data)) {
		return nil
	}
	avail := int64(len(data)) - p.Offset
	size := p.Size
	if size <= 0 || size > avail {
		size = avail
	}
	return data[p.Offset : p.Offset+size]
}

// Store updates the in-session pending-delete set when a client sets
// the \Deleted flag, and is a no-op for every other flag (proper flag
// persistence lands when the sync worker pushes flag changes back to
// Proton).
func (s *session) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, _ *imap.StoreOptions) error {
	if s.backend.mailboxes == nil {
		return errMailboxNotFound
	}
	acctID := s.snapshotAccountID()
	if acctID == "" {
		return errMailboxNotFound
	}
	st := s.state()
	st.mu.Lock()
	mbox := st.selected
	st.mu.Unlock()
	if mbox == nil {
		return errMailboxNotFound
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	msgs, err := s.backend.mailboxes.ListMessagesInMailbox(ctx, acctID, mbox.ID)
	if err != nil {
		return errMailboxNotFound
	}

	deletedSet := false
	for _, f := range flags.Flags {
		if f == imap.FlagDeleted {
			deletedSet = true
			break
		}
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	for i, m := range msgs {
		seqNum := uint32(i + 1)
		if !numSetContains(numSet, seqNum, m.UID) {
			continue
		}
		if deletedSet && (flags.Op == imap.StoreFlagsAdd || flags.Op == imap.StoreFlagsSet) {
			st.pendingDeletes[m.UID] = struct{}{}
		}
		if deletedSet && flags.Op == imap.StoreFlagsDel {
			delete(st.pendingDeletes, m.UID)
		}
		// Echo the (currently-unchanged) flag set + UID back to the
		// client so it sees the response shape RFC 9051 requires for
		// STORE without .SILENT.
		rw := w.CreateMessage(seqNum)
		rw.WriteUID(imap.UID(m.UID))
		flagSet := decodeFlags(m.Flags)
		if deletedSet {
			switch flags.Op {
			case imap.StoreFlagsAdd, imap.StoreFlagsSet:
				flagSet = appendFlagOnce(flagSet, imap.FlagDeleted)
			case imap.StoreFlagsDel:
				flagSet = removeFlag(flagSet, imap.FlagDeleted)
			}
		}
		rw.WriteFlags(flagSet)
		if err := rw.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Copy implements the IMAP COPY verb: every message in numSet is
// labelled (additively) with the destination mailbox's Proton label.
// Returns *imap.CopyData with the source/destination UID lists so a
// well-behaved client can correlate the copy.
//
// Like Move, Copy pre-allocates destination UIDs for every match
// before touching Proton. RFC 3501 COPY is atomic — partial COPYUID
// responses are not allowed — so any AssignUID failure rolls back the
// partial inserts and surfaces NO. The client retries the whole COPY.
func (s *session) Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error) {
	if s.backend.mailboxes == nil {
		return nil, errMailboxNotFound
	}
	acctID := s.snapshotAccountID()
	if acctID == "" {
		return nil, errMailboxNotFound
	}
	st := s.state()
	st.mu.Lock()
	src := st.selected
	st.mu.Unlock()
	if src == nil {
		return nil, errMailboxNotFound
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	destMbox, err := s.backend.mailboxes.GetMailboxByName(ctx, acctID, dest)
	if err != nil {
		return nil, errMailboxNotFound
	}

	srcMsgs, err := s.backend.mailboxes.ListMessagesInMailbox(ctx, acctID, src.ID)
	if err != nil {
		return nil, errMailboxNotFound
	}

	cli, err := s.protonClient(ctx, acctID)
	if err != nil {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Cannot reach Proton; try again",
		}
	}

	var matches []movePair
	for i, m := range srcMsgs {
		seqNum := uint32(i + 1)
		if !numSetContains(numSet, seqNum, m.UID) {
			continue
		}
		matches = append(matches, movePair{
			seqNum:    seqNum,
			uid:       m.UID,
			messageID: m.MessageID,
			protonID:  m.ProtonMessageID,
		})
	}
	if len(matches) == 0 {
		// Nothing matched. Return an empty CopyData; emersion will
		// emit the tagged OK with no COPYUID.
		return &imap.CopyData{UIDValidity: destMbox.UIDValidity}, nil
	}

	// Phase 1: pre-allocate destination UIDs for ALL matches. On
	// failure, roll back partial assignments and surface NO so the
	// client retries the whole COPY.
	destUIDs := make([]uint32, 0, len(matches))
	for i, m := range matches {
		uid, err := s.backend.mailboxes.AssignUID(ctx, acctID, destMbox.ID, m.messageID)
		if err != nil {
			s.logger.LogAttrs(ctx, slog.LevelWarn, "imap copy uid assign failed",
				slog.String("account_id", acctID),
				slog.Int64("dest_mailbox_id", destMbox.ID),
				slog.Int64("message_id", m.messageID),
				slog.Int("succeeded", i),
				slog.Int("total", len(matches)),
				slog.String("err", err.Error()))
			s.rollbackMoveAssignments(ctx, acctID, destMbox.ID, matches[:i])
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Text: "Mailbox temporarily unavailable",
			}
		}
		destUIDs = append(destUIDs, uid)
	}

	// Phase 2: tell Proton about the new label. On failure, roll back
	// the local assignments — Proton was untouched, so the rollback
	// restores full consistency.
	protonIDs := make([]string, 0, len(matches))
	srcUIDs := make([]uint32, 0, len(matches))
	for _, m := range matches {
		protonIDs = append(protonIDs, m.protonID)
		srcUIDs = append(srcUIDs, m.uid)
	}
	if err := cli.LabelMessages(ctx, protonIDs, destMbox.ProtonLabelID); err != nil {
		s.logger.LogAttrs(ctx, slog.LevelWarn, "imap copy label failed",
			slog.String("account_id", acctID),
			slog.String("dest_label", destMbox.ProtonLabelID),
			slog.String("err", err.Error()))
		s.rollbackMoveAssignments(ctx, acctID, destMbox.ID, matches)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Proton label operation failed",
		}
	}

	return &imap.CopyData{
		UIDValidity: destMbox.UIDValidity,
		SourceUIDs:  uidSetFromSlice(srcUIDs),
		DestUIDs:    uidSetFromSlice(destUIDs),
	}, nil
}

// Move implements the IMAP MOVE verb (SessionMove). For system folders
// MOVE issues remove-old + add-new on Proton's label surface; for
// `Labels/X` → `Labels/Y` the same pattern preserves Proton's additive
// label semantics.
//
// The wire-shape (writing COPYUID + EXPUNGE responses) is delegated to
// the writer; the spec-mandated state mutation lives in performMove so
// unit tests can assert the Proton call sequence + local UID effects
// without standing up an emersion Conn. Wire-shape integration tests
// land with #45 (alongside the IMAP4rev2 cap-set enable).
//
// Governing: SPEC-0003 REQ "Moving between system folders changes
// Proton system flag", SPEC-0003 REQ "Moving between Labels/ folders
// adjusts labels additively".
func (s *session) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	result, err := s.performMove(numSet, dest)
	if err != nil {
		return err
	}
	if w == nil {
		// Defence-in-depth: emersion only ever calls Move with a
		// non-nil writer, but tests that exercise performMove directly
		// can pass nil to skip the wire-shape work.
		return nil
	}
	if err := w.WriteCopyData(&imap.CopyData{
		UIDValidity: result.destUIDValidity,
		SourceUIDs:  uidSetFromSlice(result.srcUIDs),
		DestUIDs:    uidSetFromSlice(result.destUIDs),
	}); err != nil {
		return err
	}
	// Per RFC 6851 we also EXPUNGE the moved messages from the source
	// mailbox so the client knows their seqnums are gone.
	for _, seq := range result.srcSeqNums {
		if err := w.WriteExpunge(seq); err != nil {
			return err
		}
	}
	return nil
}

// moveResult is the data half of a successful Move operation. Every
// field is what the wire layer needs to emit COPYUID + EXPUNGE
// responses.
type moveResult struct {
	destUIDValidity uint32
	srcUIDs         []uint32
	destUIDs        []uint32
	srcSeqNums      []uint32
}

// movePair is the per-message snapshot performMove builds for each
// match in numSet — the seqnum/uid for the source response and the
// (messageID, protonID) for downstream Proton + DB calls.
type movePair struct {
	seqNum    uint32
	uid       uint32
	messageID int64
	protonID  string
}

// performMove is the testable core of the Move handler. It runs the
// Proton-side label mutation and the local UID assignment sequence
// without writing to the IMAP wire; the caller wraps the result into
// MoveWriter calls.
//
// RFC 6851 calls MOVE atomic from the client's perspective: either the
// whole message set is moved, or nothing changes. The implementation
// honours that by pre-allocating destination UIDs for EVERY matching
// message BEFORE any Proton mutation happens. If any AssignUID call
// fails, the entire MOVE aborts with `NO Mailbox temporarily
// unavailable`, no Proton labels are touched, and no source links are
// dropped — the client retries the whole operation.
//
// Order of operations:
//  0. If destination == the already-selected source mailbox, no-op: keep
//     the existing UIDs, touch neither local state nor Proton.
//  1. Resolve src + dest mailboxes, snapshot the matching message set.
//  2. AssignUID in the destination for every match. On any failure,
//     roll back the partial assignments and return NO; Proton state is
//     untouched.
//  3. LabelMessages(dest) at Proton. On failure, roll back local UID
//     assignments and return NO.
//  4. UnlabelMessages(src) at Proton. On failure, record the pending
//     unlabel for sync-worker reconciliation and ABORT with NO — we do
//     NOT drop the local source links, so the client never receives a
//     COPYUID+EXPUNGE that claims success while Proton still has the
//     message in the source.
//  5. Drop the source-mailbox links locally. Any per-message removal
//     failure excludes that message from the success set and turns the
//     whole MOVE into a NO so the client re-syncs rather than acting on a
//     partial COPYUID+EXPUNGE.
func (s *session) performMove(numSet imap.NumSet, dest string) (*moveResult, error) {
	if s.backend.mailboxes == nil {
		return nil, errMailboxNotFound
	}
	acctID := s.snapshotAccountID()
	if acctID == "" {
		return nil, errMailboxNotFound
	}
	st := s.state()
	st.mu.Lock()
	src := st.selected
	st.mu.Unlock()
	if src == nil {
		return nil, errMailboxNotFound
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	destMbox, err := s.backend.mailboxes.GetMailboxByName(ctx, acctID, dest)
	if err != nil {
		return nil, errMailboxNotFound
	}

	// Same-source==destination no-op. A client that MOVEs into the
	// already-selected mailbox (Apple Mail occasionally does this when a
	// drag lands back on the origin folder) must NOT allocate fresh UIDs
	// or issue redundant Proton label add/remove pairs — labelling then
	// unlabelling the same Proton label would race the message out of the
	// mailbox entirely. We treat it as a successful empty move: the
	// messages keep their existing UIDs, so we report those as both the
	// source and destination UID sets and emit no EXPUNGE (the messages
	// did not leave). RFC 6851 does not forbid a same-mailbox MOVE; the
	// conservative, side-effect-free interpretation is a no-op.
	//
	// Governing: SPEC-0003 REQ "UID Stability" — a UID is assigned once
	// and never reused; a self-MOVE must not mint a second UID for a
	// message already in the mailbox.
	if destMbox.ID == src.ID {
		return s.selfMoveResult(ctx, acctID, src, numSet)
	}

	cli, err := s.protonClient(ctx, acctID)
	if err != nil {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Cannot reach Proton; try again",
		}
	}

	srcMsgs, err := s.backend.mailboxes.ListMessagesInMailbox(ctx, acctID, src.ID)
	if err != nil {
		return nil, errMailboxNotFound
	}

	var matches []movePair
	for i, m := range srcMsgs {
		seqNum := uint32(i + 1)
		if !numSetContains(numSet, seqNum, m.UID) {
			continue
		}
		matches = append(matches, movePair{
			seqNum:    seqNum,
			uid:       m.UID,
			messageID: m.MessageID,
			protonID:  m.ProtonMessageID,
		})
	}
	if len(matches) == 0 {
		return &moveResult{destUIDValidity: destMbox.UIDValidity}, nil
	}

	protonIDs := make([]string, 0, len(matches))
	for _, m := range matches {
		protonIDs = append(protonIDs, m.protonID)
	}

	// Phase 1: pre-allocate destination UIDs for ALL matches. RFC 6851
	// requires MOVE to be atomic; partial success is not allowed. If any
	// AssignUID fails, roll back the partial inserts so the destination
	// mailbox is unchanged, and surface NO. The client retries the
	// whole operation.
	destUIDs := make([]uint32, 0, len(matches))
	for i, m := range matches {
		uid, err := s.backend.mailboxes.AssignUID(ctx, acctID, destMbox.ID, m.messageID)
		if err != nil {
			s.logger.LogAttrs(ctx, slog.LevelWarn, "imap move uid assign failed",
				slog.String("account_id", acctID),
				slog.Int64("dest_mailbox_id", destMbox.ID),
				slog.Int64("message_id", m.messageID),
				slog.Int("succeeded", i),
				slog.Int("total", len(matches)),
				slog.String("err", err.Error()))
			s.rollbackMoveAssignments(ctx, acctID, destMbox.ID, matches[:i])
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Text: "Mailbox temporarily unavailable",
			}
		}
		destUIDs = append(destUIDs, uid)
	}

	// Phase 2: add the destination label at Proton. If this fails, roll
	// back the local UID assignments — Proton has not been touched, so
	// undoing the local inserts restores full consistency.
	if err := cli.LabelMessages(ctx, protonIDs, destMbox.ProtonLabelID); err != nil {
		s.logger.LogAttrs(ctx, slog.LevelWarn, "imap move add label failed",
			slog.String("account_id", acctID),
			slog.String("dest_label", destMbox.ProtonLabelID),
			slog.String("err", err.Error()))
		s.rollbackMoveAssignments(ctx, acctID, destMbox.ID, matches)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Proton label add failed",
		}
	}

	// Phase 3: remove the source label at Proton. If this fails the
	// message is in BOTH mailboxes on PROTON — the additive-label model
	// treats that as legitimate, so Proton is internally consistent, just
	// not in the state the client asked for. We record the failed-unlabel
	// intent so the sync-worker reconciliation pass (reconcileMoves) can
	// retry the unlabel; that is the only place the "this label should be
	// gone" intent is durably captured, since the next Proton sync event
	// would otherwise re-materialise the source link and leave the message
	// stuck in two mailboxes forever.
	//
	// Critically, we do NOT proceed to drop the local source links when
	// Phase 3 failed: dropping them would tell the client (via EXPUNGE)
	// that the message left the source, while Proton still has it labelled
	// there — the exact COPYUID-says-success / source-still-has-it
	// divergence this issue closes. Instead we abort with NO so the client
	// re-syncs and sees the true (two-mailbox) state; reconciliation then
	// converges it to the requested single-mailbox state.
	//
	// Governing: SPEC-0003 REQ "Moving between system folders changes
	// Proton system flag", SPEC-0003 REQ "Moving between Labels/ folders
	// adjusts labels additively".
	if err := cli.UnlabelMessages(ctx, protonIDs, src.ProtonLabelID); err != nil {
		s.logger.LogAttrs(ctx, slog.LevelWarn, "imap move remove label failed; recording for reconciliation",
			slog.String("account_id", acctID),
			slog.String("src_label", src.ProtonLabelID),
			slog.String("err", err.Error()))
		s.recordPendingUnlabel(ctx, acctID, src.ProtonLabelID, protonIDs)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Move partially applied; resync to converge",
		}
	}

	// Phase 4: drop the source-mailbox links for every successfully-
	// assigned pair. Pre-allocation in Phase 1 means every match has a
	// destination UID, so every match's source link should drop.
	//
	// A removal that fails here leaves the message linked to BOTH mailboxes
	// LOCALLY while Proton has already dropped the source label (Phase 3
	// committed). Telling the client that message was EXPUNGEd from the
	// source (which a COPYUID + EXPUNGE response asserts) would be a lie:
	// the local source link is still present, so a re-SELECT would show the
	// message back in the source. We therefore EXCLUDE any message whose
	// source-link removal failed from the result set, and if ANY failed we
	// surface NO so the client re-syncs the whole mailbox and observes the
	// true state rather than acting on a partial success. The messages that
	// DID drop are durably moved; the failed ones are reconciled by the
	// next sync round (Proton already unlabelled them, so the source link
	// will be cleaned up when the sync worker reconciles local state).
	srcUIDs := make([]uint32, 0, len(matches))
	srcSeqs := make([]uint32, 0, len(matches))
	removeFailed := false
	for _, m := range matches {
		// A (false, nil) return — no error, but no row removed — means the
		// source link was already gone (a concurrent EXPUNGE or a prior
		// retry). That is still the desired end state, so we count it as a
		// successful drop and report the message in the EXPUNGE set. Only a
		// non-nil error (the store could not perform the delete) is a
		// failure.
		if _, err := s.backend.mailboxes.RemoveMessageFromMailbox(ctx, acctID, src.ID, m.messageID); err != nil {
			removeFailed = true
			s.logger.LogAttrs(ctx, slog.LevelWarn, "imap move source remove failed",
				slog.String("account_id", acctID),
				slog.Int64("src_mailbox_id", src.ID),
				slog.Int64("message_id", m.messageID),
				slog.String("err", err.Error()))
			continue
		}
		srcUIDs = append(srcUIDs, m.uid)
		srcSeqs = append(srcSeqs, m.seqNum)
	}

	if removeFailed {
		// Proton state is correct (dest labelled, src unlabelled) but the
		// local mirror could not fully drop the source links. Refusing
		// with NO is the only coherent answer: a COPYUID + EXPUNGE here
		// would claim every message left the source, which is false for
		// the ones whose link survived. The client re-syncs and converges.
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Move partially applied; resync to converge",
		}
	}

	return &moveResult{
		destUIDValidity: destMbox.UIDValidity,
		srcUIDs:         srcUIDs,
		destUIDs:        destUIDs,
		srcSeqNums:      srcSeqs,
	}, nil
}

// selfMoveResult is the no-op path for a MOVE whose destination is the
// already-selected mailbox. It returns the existing UIDs of the matched
// messages as both the source and destination UID sets (the UIDs do not
// change) and an empty srcSeqNums slice so the Move wire layer emits a
// COPYUID with no EXPUNGE — the messages never left the mailbox.
//
// Governing: SPEC-0003 REQ "UID Stability".
func (s *session) selfMoveResult(ctx context.Context, acctID string, src *mailbox.Mailbox, numSet imap.NumSet) (*moveResult, error) {
	srcMsgs, err := s.backend.mailboxes.ListMessagesInMailbox(ctx, acctID, src.ID)
	if err != nil {
		return nil, errMailboxNotFound
	}
	uids := make([]uint32, 0)
	for i, m := range srcMsgs {
		seqNum := uint32(i + 1)
		if !numSetContains(numSet, seqNum, m.UID) {
			continue
		}
		uids = append(uids, m.UID)
	}
	return &moveResult{
		destUIDValidity: src.UIDValidity,
		srcUIDs:         uids,
		destUIDs:        uids,
		// srcSeqNums intentionally empty: nothing is expunged from the
		// source because the message never left it.
		srcSeqNums: nil,
	}, nil
}

// recordPendingUnlabel durably records, for every message in protonIDs,
// that the MOVE Phase-3 source unlabel of `srcLabelID` failed at Proton.
// The sync-worker reconciliation pass (internal/sync) drains these and
// retries the unlabel so the message does not stay stuck in two
// mailboxes. Each record is best-effort: a failure to record is logged
// but does not change the (already-decided) NO response to the client —
// the worst case if recording fails is that the next Proton sync event
// re-materialises the source link and the message stays in two mailboxes
// until a later MOVE attempt, which is no worse than the pre-issue
// behaviour.
//
// Governing: SPEC-0003 REQ "Moving between system folders changes Proton
// system flag", SPEC-0003 REQ "Moving between Labels/ folders adjusts
// labels additively".
func (s *session) recordPendingUnlabel(ctx context.Context, accountID, srcLabelID string, protonIDs []string) {
	for _, pid := range protonIDs {
		if err := s.backend.mailboxes.RecordPendingUnlabel(ctx, accountID, pid, srcLabelID); err != nil {
			s.logger.LogAttrs(ctx, slog.LevelWarn, "imap move: failed to record pending unlabel for reconciliation",
				slog.String("account_id", accountID),
				slog.String("proton_message_id", pid),
				slog.String("src_label", srcLabelID),
				slog.String("err", err.Error()))
		}
	}
}

// rollbackMoveAssignments undoes a partial set of AssignUID inserts
// performed during Phase 1 of performMove. Used when AssignUID fails
// part-way through the pre-allocation, or when the subsequent Proton
// LabelMessages call fails after the local pre-allocation succeeded.
//
// Each undo is best-effort: a failed remove is logged but does not
// stop the rest. The caller's response to the user is already the
// failure NO — the rollback is housekeeping to keep the destination
// mailbox visually clean.
func (s *session) rollbackMoveAssignments(ctx context.Context, accountID string, destMailboxID int64, assigned []movePair) {
	for _, m := range assigned {
		if _, err := s.backend.mailboxes.RemoveMessageFromMailbox(ctx, accountID, destMailboxID, m.messageID); err != nil {
			s.logger.LogAttrs(ctx, slog.LevelWarn, "imap move rollback failed",
				slog.String("account_id", accountID),
				slog.Int64("dest_mailbox_id", destMailboxID),
				slog.Int64("message_id", m.messageID),
				slog.String("err", err.Error()))
		}
	}
}

// protonClient resolves the per-account Proton client. Returns an
// error if the lookup is missing or if the per-account client is
// unavailable; callers translate that to a transient `NO` so the
// client retries.
func (s *session) protonClient(ctx context.Context, accountID string) (proton.Client, error) {
	if s.backend.proton == nil {
		return nil, errors.New("imapserver: proton lookup is not configured")
	}
	cli, err := s.backend.proton.ProtonForAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}
	if cli == nil {
		return nil, errors.New("imapserver: no proton client bound to account")
	}
	return cli, nil
}

// numSetContains reports whether the IMAP NumSet matches a (seqNum,
// uid) pair. emersion exposes `Contains` on UIDSet but the SeqSet form
// only carries sequence numbers, so we sniff the type.
func numSetContains(numSet imap.NumSet, seqNum, uid uint32) bool {
	switch s := numSet.(type) {
	case imap.UIDSet:
		return s.Contains(imap.UID(uid))
	case imap.SeqSet:
		return s.Contains(seqNum)
	default:
		// Defensive: an unknown NumSet shape matches nothing rather
		// than everything so a future driver bug does not cause a wide
		// fan-out copy/move.
		return false
	}
}

// decodeFlags splits the comma-separated flag string stored in
// messages.flags into a slice of imap.Flag. Empty input -> empty slice.
func decodeFlags(s string) []imap.Flag {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]imap.Flag, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, imap.Flag(p))
	}
	return out
}

// appendFlagOnce returns flags with f appended unless it is already
// present.
func appendFlagOnce(flags []imap.Flag, f imap.Flag) []imap.Flag {
	for _, existing := range flags {
		if existing == f {
			return flags
		}
	}
	return append(flags, f)
}

// removeFlag returns flags with every occurrence of f removed.
func removeFlag(flags []imap.Flag, f imap.Flag) []imap.Flag {
	out := flags[:0]
	for _, existing := range flags {
		if existing == f {
			continue
		}
		out = append(out, existing)
	}
	return out
}

// uidSetFromSlice builds an imap.UIDSet from a flat slice of UIDs.
// Used by Move/Copy for the COPYUID response.
func uidSetFromSlice(uids []uint32) imap.UIDSet {
	if len(uids) == 0 {
		return nil
	}
	out := make(imap.UIDSet, 0, len(uids))
	for _, u := range uids {
		out = append(out, imap.UIDRange{Start: imap.UID(u), Stop: imap.UID(u)})
	}
	return out
}
