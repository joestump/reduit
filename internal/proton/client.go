package proton

import (
	"context"
	"time"
)

// Client is the operations one configured Proton mailbox needs, expressed in
// reduit domain types. The auth, sync, and send layers depend on this
// interface, not on go-proton-api; the concrete implementation is gpaClient
// (gpa_client.go) and the test double is Fake (fake.go).
//
// Lifecycle. A client moves through three states:
//
//	unauthenticated → Login (+ SubmitTOTP if 2FA) → authenticated
//	authenticated  → Unlock (mailbox passphrase) → unlocked
//
// Auth-only methods (Login, SubmitTOTP, ProtonUserID, RefreshToken) are
// usable once authenticated. The data methods (events, decrypt, send) require
// the keyring, so they need an Unlock first; they return ErrNotUnlocked
// otherwise. Refresh re-establishes the session from the stored refresh token
// and does not by itself restore the unlocked keyring.
//
// Governing: SPEC-0007 (auth flow), ADR-0014 (events/decrypt), ADR-0020 (send).
type Client interface {
	// Login performs SRP password authentication for the given address
	// (SPEC-0007 REQ "SRP and 2FA Handling"). go-proton-api runs the SRP
	// exchange; reduit never implements its own. The returned AuthStatus
	// reports the immutable proton_user_id and whether a 2FA challenge must
	// still be satisfied. password is the caller's buffer; this package does
	// not retain or log it.
	//
	// When Proton demands human verification (code 9001) Login returns an
	// *HVRequiredError. reduit does not solve it in-app (ADR-0021): it identifies
	// as a Proton Bridge client by default (DefaultAppVersion), which Proton waves
	// through with no challenge. Reaching an HV here means a non-Bridge app-version
	// is configured, and the CLI surfaces a clear app-version error.
	Login(ctx context.Context, address string, password []byte) (AuthStatus, error)

	// SubmitTOTP submits a TOTP code to complete a login that reported
	// TwoFATOTP (SPEC-0007 scenario "TOTP 2FA is required"). It is an error to
	// call this when no 2FA challenge is pending.
	SubmitTOTP(ctx context.Context, code string) error

	// Unlock decrypts the mailbox's OpenPGP private keys with the mailbox
	// passphrase (SPEC-0007 REQ "Mailbox Passphrase Capture and Key Unlock").
	// On success the per-address keyrings are held in memory for decrypt/send.
	// passphrase is the caller's buffer; it is not retained or logged.
	Unlock(ctx context.Context, passphrase []byte) error

	// ProtonUserID returns the account's immutable Proton user id, available
	// after a successful Login. It is "" before authentication. The auth layer
	// records it on the mailbox row on first auth and refuses to overwrite it
	// on re-auth (SPEC-0007 REQ "Re-Auth Flow", "Multi-Mailbox Add").
	ProtonUserID() string

	// RefreshToken returns the current Proton refresh token. Because Proton
	// rotates the refresh token on Login and Refresh, the caller must re-read
	// this after each and persist the new value to the keychain (ADR-0013).
	RefreshToken() string

	// SessionUID returns the go-proton-api session UID captured at Login and
	// re-read after Refresh/Resume. Proton's /auth/v4/refresh requires this UID
	// to identify the session; resuming without it yields 10013 "Invalid refresh
	// token". It is non-secret session state that the auth layer persists on the
	// mailbox row (ADR-0013) so a later cross-process Resume can supply it. Like
	// the refresh token it may rotate on Refresh, so the caller re-reads and
	// re-persists it after each resume. It is "" before authentication.
	SessionUID() string

	// Refresh rotates the session using the stored refresh token
	// (SPEC-0007 REQ "Secret Write, Read, and Delete" — secrets read
	// non-interactively at use time). RefreshToken reflects the rotated value
	// afterward. It does not restore the unlocked keyring; call Unlock again if
	// decrypt/send is needed.
	Refresh(ctx context.Context) error

	// Labels returns the account's labels, folders, and system mailboxes in
	// reduit domain types. It needs only an authenticated session — no mailbox
	// keyring Unlock — so it doubles as the live connection test the CLI runs
	// after `auth add` (SPEC-0007 "Re-Auth Flow" exercises the same Resume +
	// authenticated-call path). go-proton-api types do not cross this boundary.
	Labels(ctx context.Context) ([]Label, error)

	// LatestEventID returns the current head of the Proton event stream, used
	// to seed a mailbox's sync cursor on first sync (ADR-0014 "Bootstrap then
	// tail").
	LatestEventID(ctx context.Context) (string, error)

	// GetEvents fetches the batch of events after sinceEventID and reports the
	// cursor to persist next plus whether more events are immediately available
	// (ADR-0014 "advance the persisted Proton event cursor and apply the
	// delta"). A batch may carry a Refresh flag instructing a full re-sync.
	GetEvents(ctx context.Context, sinceEventID string) (EventBatch, error)

	// BackfillMessageIDs enumerates the message ids to import for a mailbox's
	// FIRST sync, bounded to messages whose Proton timestamp is at or after
	// since (SPEC-0002 REQ "Bootstrap Then Tail" — "First sync backfills a
	// bounded window"). GetEvents/DecryptMessage can tail and decrypt by id but
	// cannot enumerate history; this is that seam. Ids are returned oldest-first
	// so an interrupted backfill resumes forward without re-walking applied
	// messages. It pages Proton's metadata endpoint (bounded requests, never an
	// unbounded load) and needs only an authenticated session — no Unlock —
	// returning ErrNotAuthenticated otherwise.
	BackfillMessageIDs(ctx context.Context, since time.Time) ([]string, error)

	// DecryptMessage fetches and decrypts a single message with the unlocked
	// keyring (ADR-0014 "Decrypt in the pipeline"). Requires Unlock.
	DecryptMessage(ctx context.Context, messageID string) (DecryptedMessage, error)

	// DecryptAttachment fetches and decrypts one attachment of a message with
	// the unlocked keyring. The message id is required because the attachment's
	// session key is unwrapped against the message's address keyring. Requires
	// Unlock. Payload handling policy is ADR-0016.
	DecryptAttachment(ctx context.Context, messageID, attachmentID string) ([]byte, error)

	// Send submits a user-composed message (ADR-0020). The source mailbox
	// address is explicit (OutgoingMessage.FromAddressID); there is no implicit
	// default. This is the one mutating operation; callers (CLI and the MCP
	// send tool) gate it behind explicit confirmation (ADR-0020, SPEC-0010).
	// Requires Unlock.
	Send(ctx context.Context, msg OutgoingMessage) (SentMessage, error)

	// Close releases the underlying session/transport. It does not revoke the
	// Proton auth session.
	Close()
}

// Dialer constructs Clients. The auth flow (#86) calls NewClient and drives
// Login; sync/send (#88, ADR-0020) call Resume with a refresh token read from
// the keychain to obtain an already-authenticated client, then Unlock with the
// stored passphrase.
type Dialer interface {
	// NewClient returns a fresh, unauthenticated client for the interactive
	// Login flow.
	NewClient() Client

	// Resume reconstructs an authenticated client from a stored session UID and
	// refresh token (SPEC-0007 "Secrets read non-interactively at use time").
	// Both are required: Proton's /auth/v4/refresh identifies the session by its
	// UID, so resuming with an empty sessionUID yields 10013 "Invalid refresh
	// token". The refresh token (and possibly the UID) may be rotated by the
	// resume; read RefreshToken and SessionUID afterward and persist them. The
	// returned client is authenticated but not unlocked.
	Resume(ctx context.Context, protonUserID, sessionUID, refreshToken string) (Client, error)
}

// TwoFAState reports what, if anything, must happen after the password step of
// Login before the session is fully authenticated (SPEC-0007 REQ "SRP and 2FA
// Handling").
type TwoFAState int

const (
	// TwoFANone means the password step fully authenticated the session; no
	// second factor is required.
	TwoFANone TwoFAState = iota
	// TwoFATOTP means a TOTP code is required; call SubmitTOTP.
	TwoFATOTP
	// TwoFAUnsupported means the account requires a second factor reduit does
	// not support (e.g. FIDO2-only). SPEC-0007 scopes TOTP only; FIDO2 is left
	// to go-proton-api/upstream and is not a supported reduit auth path.
	TwoFAUnsupported
)

func (s TwoFAState) String() string {
	switch s {
	case TwoFANone:
		return "none"
	case TwoFATOTP:
		return "totp"
	case TwoFAUnsupported:
		return "unsupported"
	default:
		return "unknown"
	}
}

// AuthStatus is the outcome of the password step of Login.
type AuthStatus struct {
	// ProtonUserID is the account's immutable Proton user id.
	ProtonUserID string
	// TwoFA reports whether a second factor is still required.
	TwoFA TwoFAState
}

// Needs2FA reports whether the caller must satisfy a 2FA challenge before the
// session is usable.
func (a AuthStatus) Needs2FA() bool { return a.TwoFA == TwoFATOTP }

// Address is a mail participant (sender or recipient).
type Address struct {
	Name  string
	Email string
}

// Label is one of a mailbox's organizing entities — a user label, a user
// folder, or a built-in system mailbox (Inbox, Sent, …) — in reduit domain
// terms. It is the surface the `reduit labels` connection test prints; go-
// proton-api's label representation does not cross the Client boundary.
type Label struct {
	// ID is Proton's stable label id. System mailboxes have well-known numeric
	// ids ("0" = Inbox, "7" = Sent, …); user labels/folders have opaque ids.
	ID string
	// Name is the human-readable label name.
	Name string
	// Type is the label class: "label", "folder", or "system". An unrecognized
	// upstream type maps to "unknown" rather than leaking the numeric code.
	Type string
	// Color is the label's display color (hex like "#c44800"), empty for system
	// mailboxes that carry none.
	Color string
}

// Label type strings. These are the reduit-facing values of Label.Type; they
// are deliberately decoupled from go-proton-api's numeric LabelType so a change
// upstream does not ripple into reduit's domain or the CLI's output.
const (
	LabelTypeLabel   = "label"
	LabelTypeFolder  = "folder"
	LabelTypeSystem  = "system"
	LabelTypeUnknown = "unknown"
)

// EventAction is the kind of change an event item describes (ADR-0014
// "applying creates/updates/deletes idempotently").
type EventAction int

const (
	// EventCreate is a newly created item.
	EventCreate EventAction = iota
	// EventUpdate is a modified item (content or flags).
	EventUpdate
	// EventDelete is a removed item.
	EventDelete
)

func (a EventAction) String() string {
	switch a {
	case EventCreate:
		return "create"
	case EventUpdate:
		return "update"
	case EventDelete:
		return "delete"
	default:
		return "unknown"
	}
}

// MessageEvent is a single message-level change in an event.
type MessageEvent struct {
	Action    EventAction
	MessageID string
}

// Event is one Proton event in cursor order.
type Event struct {
	// EventID is this event's cursor position.
	EventID string
	// Refresh is set when Proton signals that the client's view is stale and a
	// full re-sync is required rather than a delta apply (ADR-0014). When true,
	// Messages should be ignored and the mailbox re-bootstrapped.
	Refresh bool
	// Messages are the message-level changes carried by this event.
	Messages []MessageEvent
}

// EventBatch is the result of one GetEvents call.
type EventBatch struct {
	// Events are the events after the requested cursor, in order.
	Events []Event
	// NextCursor is the event id to persist and pass to the next GetEvents
	// call. It equals the requested cursor when no events were returned, so a
	// caller that persists it never moves backward (ADR-0014 idempotent,
	// resumable sync).
	NextCursor string
	// More reports that additional events are immediately available beyond this
	// batch; a caller draining the stream loops until it is false.
	More bool
}

// Refresh reports whether any event in the batch carries the full-resync flag.
func (b EventBatch) Refresh() bool {
	for _, e := range b.Events {
		if e.Refresh {
			return true
		}
	}
	return false
}

// AttachmentMeta describes an attachment without its payload (ADR-0016).
type AttachmentMeta struct {
	ID       string
	Name     string
	MIMEType string
	Size     int64
}

// DecryptedMessage is a message whose body has been decrypted locally
// (ADR-0014). It is keyed by the stable Proton message id; the sync layer pairs
// that id with a content hash for idempotent caching (ADR-0014 "Idempotent
// keying").
type DecryptedMessage struct {
	MessageID   string
	AddressID   string
	Subject     string
	Sender      Address
	To          []Address
	CC          []Address
	BCC         []Address
	Date        time.Time
	MIMEType    string
	Body        []byte
	Unread      bool
	LabelIDs    []string
	Attachments []AttachmentMeta
}

// OutgoingAttachment is a file to attach to an outbound message (ADR-0020).
type OutgoingAttachment struct {
	Name     string
	MIMEType string
	Data     []byte
}

// OutgoingMessage is a user-composed message to submit (ADR-0020). The source
// mailbox address is explicit; recipients, subject, and body are required so an
// agent (via the MCP send tool) cannot fire an underspecified send.
type OutgoingMessage struct {
	// FromAddressID is the Proton address id to send from (ADR-0020 "Explicit
	// from-mailbox"). It must correspond to an unlocked address keyring.
	FromAddressID string
	To            []Address
	CC            []Address
	BCC           []Address
	Subject       string
	Body          string
	// MIMEType is the body content type ("text/plain" or "text/html"); empty
	// defaults to text/plain.
	MIMEType    string
	Attachments []OutgoingAttachment
}

// SentMessage is the result of a successful Send.
type SentMessage struct {
	// MessageID is the Proton id of the submitted message, used to reconcile
	// the local Sent record against the next sync (ADR-0020, ADR-0014).
	MessageID string
}
