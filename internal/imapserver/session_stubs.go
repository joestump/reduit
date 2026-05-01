// Stub implementations of the post-Login Session interface methods.
// At this milestone the IMAP server has no mailbox content; LIST is
// empty, every named mailbox does not exist, and IDLE / Poll never
// emit updates. Stories #19 (folder hierarchy + UID stability) and
// #20 (IDLE live updates) replace these stubs.
//
// Governing: SPEC-0003 (whole-spec; the requirements implemented in
// this story do not extend beyond auth + listener + per-session
// lifetime). The stubs deliberately return errors that exactly match
// the "mailbox does not exist" error a future implementation will
// also emit when a name is genuinely unknown — no information leak.

package imapserver

import (
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

// errMailboxNotFound is the response the empty-backend stub returns
// for every named-mailbox operation. Identical text + code to a
// future not-found case so a malicious client cannot distinguish the
// two through black-box probing.
var errMailboxNotFound = &imap.Error{
	Type: imap.StatusResponseTypeNo,
	Text: "Mailbox does not exist",
}

func (s *session) Select(mailbox string, options *imap.SelectOptions) (*imap.SelectData, error) {
	return nil, errMailboxNotFound
}

func (s *session) Create(mailbox string, options *imap.CreateOptions) error {
	return errMailboxNotFound
}

func (s *session) Delete(mailbox string) error {
	return errMailboxNotFound
}

func (s *session) Rename(mailbox, newName string, options *imap.RenameOptions) error {
	return errMailboxNotFound
}

func (s *session) Subscribe(mailbox string) error {
	return errMailboxNotFound
}

func (s *session) Unsubscribe(mailbox string) error {
	return errMailboxNotFound
}

// List with no mailboxes is a successful no-op: the writer is never
// called and the command completes with the standard OK from the
// emersion server core.
func (s *session) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	return nil
}

func (s *session) Status(mailbox string, options *imap.StatusOptions) (*imap.StatusData, error) {
	return nil, errMailboxNotFound
}

func (s *session) Append(mailbox string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	return nil, errMailboxNotFound
}

// Poll runs after every authenticated command; with no mailbox state
// there is nothing to push, so we no-op.
func (s *session) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	return nil
}

// Idle blocks until stop is signalled. With no live update source
// wired in (story #20) we simply wait — the server's own idle-timeout
// logic will eventually break the connection.
func (s *session) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	<-stop
	return nil
}

func (s *session) Unselect() error {
	return errMailboxNotFound
}

func (s *session) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	return errMailboxNotFound
}

func (s *session) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	return nil, errMailboxNotFound
}

func (s *session) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	return errMailboxNotFound
}

func (s *session) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	return errMailboxNotFound
}

func (s *session) Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error) {
	return nil, errMailboxNotFound
}
