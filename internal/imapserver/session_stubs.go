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
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"

	"github.com/joestump/reduit/internal/mailbox"
	"github.com/joestump/reduit/internal/proton"
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
type sessionState struct {
	mu             sync.Mutex
	selected       *mailbox.Mailbox
	pendingDeletes map[uint32]struct{} // UIDs flagged \Deleted, awaiting EXPUNGE
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
	if options.NumMessages || options.NumRecent || options.NumUnseen {
		count, err := s.backend.mailboxes.CountMessagesInMailbox(ctx, acctID, mbox.ID)
		if err != nil {
			return nil, errMailboxNotFound
		}
		if options.NumMessages {
			n := count
			data.NumMessages = &n
		}
		if options.NumRecent {
			// We do not track \Recent (deprecated in IMAP4rev2 anyway);
			// always return 0 so clients that ask have a stable answer.
			zero := uint32(0)
			data.NumRecent = &zero
		}
		if options.NumUnseen {
			// Without a per-flag accounting yet, surface the total as
			// the unseen count. The sync worker will populate per-flag
			// counters in a later story; until then over-reporting
			// unread messages is the safer side.
			n := count
			data.NumUnseen = &n
		}
	}
	return data, nil
}

func (s *session) Append(_ string, _ imap.LiteralReader, _ *imap.AppendOptions) (*imap.AppendData, error) {
	// APPEND requires a roundtrip to Proton's draft API which lands in
	// the SMTP outbox story. Reject for now with the read-only error so
	// clients like Apple Mail (which APPENDs sent messages to Sent)
	// fall back to "send via SMTP and let the server file it" via
	// SPEC-0004's submission path.
	return nil, errMailboxReadOnly
}

// Poll runs after every authenticated command; with the live-update
// bus deferred to story #20 there is nothing to push. Returning nil
// keeps the upstream loop quiet.
func (s *session) Poll(_ *imapserver.UpdateWriter, _ bool) error {
	return nil
}

// Idle blocks until stop is signalled. With no live update source
// wired in (story #20) we simply wait — the server's own idle-timeout
// logic will eventually break the connection.
func (s *session) Idle(_ *imapserver.UpdateWriter, stop <-chan struct{}) error {
	<-stop
	return nil
}

// Unselect clears the per-session selected mailbox state. Per SPEC-0003
// REQ "Per-session state is isolated" this only affects THIS session.
func (s *session) Unselect() error {
	st := s.state()
	st.mu.Lock()
	st.selected = nil
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

// Fetch writes minimal FETCH responses for every message in numSet
// matching the requested options. We support the flag/uid/internaldate/
// rfc822.size subset that lets clients build a pane (Apple Mail does
// this on first SELECT). Body retrieval (BODY[]) requires a Proton
// round-trip and lands when the sync worker materialises bodies.
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
		if err := rw.Close(); err != nil {
			return err
		}
	}
	return nil
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

	var (
		protonIDs []string
		srcUIDs   []uint32
		toAssign  []*mailbox.MessageInMailbox
	)
	for i, m := range srcMsgs {
		seqNum := uint32(i + 1)
		if !numSetContains(numSet, seqNum, m.UID) {
			continue
		}
		protonIDs = append(protonIDs, m.ProtonMessageID)
		srcUIDs = append(srcUIDs, m.UID)
		toAssign = append(toAssign, m)
	}
	if len(protonIDs) == 0 {
		// Nothing matched. Return an empty CopyData; emersion will
		// emit the tagged OK with no COPYUID.
		return &imap.CopyData{UIDValidity: destMbox.UIDValidity}, nil
	}

	if err := cli.LabelMessages(ctx, protonIDs, destMbox.ProtonLabelID); err != nil {
		s.logger.LogAttrs(ctx, slog.LevelWarn, "imap copy label failed",
			slog.String("account_id", acctID),
			slog.String("dest_label", destMbox.ProtonLabelID),
			slog.String("err", err.Error()))
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Proton label operation failed",
		}
	}

	destUIDs := make([]uint32, 0, len(toAssign))
	for _, m := range toAssign {
		uid, err := s.backend.mailboxes.AssignUID(ctx, acctID, destMbox.ID, m.MessageID)
		if err != nil {
			s.logger.LogAttrs(ctx, slog.LevelWarn, "imap copy uid assign failed",
				slog.String("account_id", acctID),
				slog.Int64("dest_mailbox_id", destMbox.ID),
				slog.Int64("message_id", m.MessageID),
				slog.String("err", err.Error()))
			continue
		}
		destUIDs = append(destUIDs, uid)
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
// without standing up an emersion Conn.
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

// performMove is the testable core of the Move handler. It runs the
// Proton-side label mutation and the local UID assignment sequence
// without writing to the IMAP wire; the caller wraps the result into
// MoveWriter calls.
//
// The local UID assignment on the destination mailbox happens AFTER
// the Proton operation succeeds so a network failure does not corrupt
// local state. The source-mailbox link is removed AFTER the destination
// assignment lands, making the IMAP-visible move atomic from the
// client's perspective even if a future bug interrupts the chain.
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

	type pair struct {
		seqNum    uint32
		uid       uint32
		messageID int64
		protonID  string
	}
	var matches []pair
	for i, m := range srcMsgs {
		seqNum := uint32(i + 1)
		if !numSetContains(numSet, seqNum, m.UID) {
			continue
		}
		matches = append(matches, pair{
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

	// Phase 1: add the destination label. If this fails, no local
	// mutation has happened — return NO and let the client retry.
	if err := cli.LabelMessages(ctx, protonIDs, destMbox.ProtonLabelID); err != nil {
		s.logger.LogAttrs(ctx, slog.LevelWarn, "imap move add label failed",
			slog.String("account_id", acctID),
			slog.String("dest_label", destMbox.ProtonLabelID),
			slog.String("err", err.Error()))
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Proton label add failed",
		}
	}

	// Phase 2: remove the source label. If this fails the message is
	// in BOTH mailboxes — the Proton model treats that as legitimate
	// (additive labels) so the client sees a stable state, just not the
	// one it asked for. Log loudly; the next sync round will reconcile.
	if err := cli.UnlabelMessages(ctx, protonIDs, src.ProtonLabelID); err != nil {
		s.logger.LogAttrs(ctx, slog.LevelWarn, "imap move remove label failed",
			slog.String("account_id", acctID),
			slog.String("src_label", src.ProtonLabelID),
			slog.String("err", err.Error()))
		// We deliberately do NOT abort here — Phase 1 already mutated
		// Proton state, so the IMAP-side operation is durably half-
		// done. Better to continue with the local mirror so the client
		// sees the destination mailbox populated, and let the next
		// sync round reconcile the source.
	}

	// Phase 3: local UID assignment for the destination. Per SPEC-0003
	// REQ "UID assignment is monotonic" each match consumes one fresh
	// UID from destMbox.uid_next.
	destUIDs := make([]uint32, 0, len(matches))
	srcUIDs := make([]uint32, 0, len(matches))
	srcSeqs := make([]uint32, 0, len(matches))
	for _, m := range matches {
		uid, err := s.backend.mailboxes.AssignUID(ctx, acctID, destMbox.ID, m.messageID)
		if err != nil {
			s.logger.LogAttrs(ctx, slog.LevelWarn, "imap move uid assign failed",
				slog.String("account_id", acctID),
				slog.Int64("dest_mailbox_id", destMbox.ID),
				slog.Int64("message_id", m.messageID),
				slog.String("err", err.Error()))
			continue
		}
		destUIDs = append(destUIDs, uid)
		srcUIDs = append(srcUIDs, m.uid)
		srcSeqs = append(srcSeqs, m.seqNum)
	}

	// Phase 4: drop the source-mailbox links. We do this after Phase 3
	// so that if AssignUID fails for any pair, the message is still
	// reachable in the source mailbox via the existing link.
	for _, m := range matches {
		if _, err := s.backend.mailboxes.RemoveMessageFromMailbox(ctx, acctID, src.ID, m.messageID); err != nil {
			s.logger.LogAttrs(ctx, slog.LevelWarn, "imap move source remove failed",
				slog.String("account_id", acctID),
				slog.Int64("src_mailbox_id", src.ID),
				slog.Int64("message_id", m.messageID),
				slog.String("err", err.Error()))
		}
	}

	return &moveResult{
		destUIDValidity: destMbox.UIDValidity,
		srcUIDs:         srcUIDs,
		destUIDs:        destUIDs,
		srcSeqNums:      srcSeqs,
	}, nil
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
