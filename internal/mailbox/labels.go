// IMAP ↔ Proton folder/label name mapping.
//
// The IMAP wire form is operator/client-facing (INBOX, Sent, Drafts,
// Trash, Spam, Archive, All Mail, Labels/<path>). Proton's label model
// is a flat list of system labels (numeric IDs `0`-`12` per
// go-proton-api's label_types.go) plus user-created labels with
// hierarchical path strings. A single resolver in this file is the only
// place the two namespaces meet, so a future change to either side
// (e.g., a new Proton system label, a different user-namespace prefix)
// touches one function instead of being scattered across the code base.
//
// Governing: SPEC-0003 REQ "Folder Hierarchy and Mapping",
// SPEC-0006 (MCP folder resolver shares this mapping).

package mailbox

import "strings"

// UserLabelNamespace is the IMAP-side prefix under which Proton user
// labels appear. Trailing `/` is the IMAP hierarchy separator emersion's
// MatchList uses; we keep it explicit so a label literally named
// "Labels" at Proton-level does not collide with the namespace root.
//
// Note: a Proton user label named e.g. `Sent` or `Inbox` is exposed as
// `Labels/Sent` (or `Labels/Inbox`) and does NOT collide with the
// reserved system folder names — they live in different IMAP paths and
// the (account_id, name) UNIQUE index treats them as distinct rows.
// The (account_id, proton_label_id) UNIQUE index further pins each
// label by its Proton ID, so the per-address Sent label and a user
// label named `Sent` cannot share a row.
const UserLabelNamespace = "Labels/"

// Kind is the distinction the schema records on every mailbox row:
// `system` is one of the seven Proton system folders, `user_label`
// is anything under `Labels/`. Kept here (next to the resolver) so
// callers do not have to remember which package owns the constant.
type Kind string

const (
	KindSystem    Kind = "system"
	KindUserLabel Kind = "user_label"
)

// Proton system label IDs, mirrored from go-proton-api's label_types.go.
// Hard-coded rather than imported as constants because the upstream
// library uses the same string-typed value and we want a single canonical
// translation table that does not change shape if the upstream constants
// rename. Verified against go-proton-api v0.4.x as of 2026-04.
//
// The IDs Reduit cares about are the seven mappable to standard IMAP
// folder names. Outbox, Starred, AllScheduled, AllDrafts, AllSent are
// intentionally NOT exposed to IMAP clients — they are Proton-specific
// virtual folders that map awkwardly to IMAP semantics. (`Drafts` and
// `Sent` here refer to the per-address Drafts/Sent labels, not the
// `AllDrafts`/`AllSent` virtual aggregates.)
const (
	ProtonInboxLabelID   = "0"
	ProtonTrashLabelID   = "3"
	ProtonSpamLabelID    = "4"
	ProtonAllMailLabelID = "5"
	ProtonArchiveLabelID = "6"
	ProtonSentLabelID    = "7"
	ProtonDraftsLabelID  = "8"
)

// systemFolders is the canonical IMAP-name → Proton-label-ID table.
// Order is preserved so iteration produces a deterministic LIST output
// in tests; callers that need a map should build one from the slice.
var systemFolders = []struct {
	IMAPName       string
	ProtonLabelID  string
	ProtonName     string
	SpecialUseAttr string // empty if no special-use attribute applies
}{
	{"INBOX", ProtonInboxLabelID, "Inbox", ""},
	{"Sent", ProtonSentLabelID, "Sent", "\\Sent"},
	{"Drafts", ProtonDraftsLabelID, "Drafts", "\\Drafts"},
	{"Trash", ProtonTrashLabelID, "Trash", "\\Trash"},
	{"Spam", ProtonSpamLabelID, "Spam", "\\Junk"},
	{"Archive", ProtonArchiveLabelID, "Archive", "\\Archive"},
	{"All Mail", ProtonAllMailLabelID, "All Mail", "\\All"},
}

// SystemFolder is the public projection of one row of `systemFolders`.
// Callers that need to enumerate the system mailboxes (e.g., the IMAP
// LIST handler when seeding a new account) walk SystemFolders().
type SystemFolder struct {
	IMAPName       string
	ProtonLabelID  string
	ProtonName     string
	SpecialUseAttr string
}

// SystemFolders returns the canonical IMAP-side system folder set in a
// stable order. The slice is a defensive copy so callers cannot mutate
// the package-level table.
func SystemFolders() []SystemFolder {
	out := make([]SystemFolder, len(systemFolders))
	for i, f := range systemFolders {
		out[i] = SystemFolder{
			IMAPName:       f.IMAPName,
			ProtonLabelID:  f.ProtonLabelID,
			ProtonName:     f.ProtonName,
			SpecialUseAttr: f.SpecialUseAttr,
		}
	}
	return out
}

// ResolveSystemFolderName returns the IMAP wire name for the given
// Proton label ID, or "" if the ID is not one of the seven Reduit
// exposes. Used by the sync worker when materialising a Proton message
// into a mailbox row.
func ResolveSystemFolderName(protonLabelID string) string {
	for _, f := range systemFolders {
		if f.ProtonLabelID == protonLabelID {
			return f.IMAPName
		}
	}
	return ""
}

// ResolveSystemFolderID is the inverse: IMAP wire name → Proton label ID.
// Returns "" if name is not a system folder. Caller checks for empty.
func ResolveSystemFolderID(imapName string) string {
	for _, f := range systemFolders {
		if f.IMAPName == imapName {
			return f.ProtonLabelID
		}
	}
	return ""
}

// IsSystemFolderName reports whether name is one of the seven IMAP
// standard mailbox names Reduit exposes. Callers that need the Kind
// classification should prefer ClassifyName which returns the kind +
// derived Proton path in one call.
func IsSystemFolderName(name string) bool {
	return ResolveSystemFolderID(name) != ""
}

// ParseUserLabelName strips the `Labels/` prefix and returns the bare
// Proton label path. Returns ok=false if name is not under the user
// namespace (or is the namespace root itself, which is non-selectable).
//
// Example:
//
//	ParseUserLabelName("Labels/Receipts")    -> ("Receipts", true)
//	ParseUserLabelName("Labels/Family/Tax")  -> ("Family/Tax", true)
//	ParseUserLabelName("INBOX")              -> ("", false)
//	ParseUserLabelName("Labels/")            -> ("", false)
//	ParseUserLabelName("Labels")             -> ("", false)
func ParseUserLabelName(imapName string) (protonLabelPath string, ok bool) {
	if !strings.HasPrefix(imapName, UserLabelNamespace) {
		return "", false
	}
	rest := imapName[len(UserLabelNamespace):]
	if rest == "" {
		// "Labels/" alone is the namespace root, not a selectable
		// mailbox.
		return "", false
	}
	return rest, true
}

// FormatUserLabelName is the inverse of ParseUserLabelName: it prepends
// the `Labels/` namespace prefix to a Proton label path. Used by the
// sync worker when materialising a user label into a mailbox row.
//
// TODO(follow-up): RFC 3501 §5.1.3 modified-UTF-7 encoding for non-ASCII
// label names + escaping for `"`, `(`, `)`, `[`, `]`, `\\`, control
// characters and CR/LF. Current pass-through works for ASCII labels but
// will mis-render Proton labels named e.g. `Café` or `Family"Tax\\` in
// LIST output. Either pre-encode here (using emersion's
// `go-imap/v2/internal/utf7` shim or x/text/encoding/unicode/utf7) OR
// reject names with the forbidden bytes at sync time. Track in the
// SPEC-0003 follow-up bucket alongside the IMAP4rev2 enable.
func FormatUserLabelName(protonLabelPath string) string {
	return UserLabelNamespace + protonLabelPath
}

// ClassifyName returns the Kind for an IMAP mailbox name plus the
// derived Proton-side identifier (a label ID for system folders, a
// label path for user labels). Returns ok=false for names that are
// neither a system folder nor under `Labels/`.
//
// Centralising this in one helper means Session.Move (and any future
// caller) does not have to hand-roll the dispatch.
func ClassifyName(imapName string) (kind Kind, protonRef string, ok bool) {
	if id := ResolveSystemFolderID(imapName); id != "" {
		return KindSystem, id, true
	}
	if path, isUser := ParseUserLabelName(imapName); isUser {
		return KindUserLabel, path, true
	}
	return "", "", false
}
