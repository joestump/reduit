// Governing: ADR-0001 (go-proton-api as Proton client).

package proton

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// Re-exported upstream types form the public surface of the wrapper.
// Callers in the rest of Reduit reference these aliases instead of
// importing github.com/ProtonMail/go-proton-api directly. Keeping the
// shape identical (via type aliases, not new types) avoids needing a
// translation layer for every payload while still letting us swap the
// underlying library if ADR-0001 ever needs revisiting.
type (
	// AuthInfo is the SRP challenge returned by /auth/v4/info.
	AuthInfo = gpa.AuthInfo
	// AuthInfoReq is the request body for /auth/v4/info.
	AuthInfoReq = gpa.AuthInfoReq
	// Auth is the post-login session bundle (UID, access, refresh).
	Auth = gpa.Auth
	// Auth2FAReq is the request body for /auth/v4/2fa.
	Auth2FAReq = gpa.Auth2FAReq
	// FIDO2Req is the FIDO2 second-factor payload nested in Auth2FAReq.
	FIDO2Req = gpa.FIDO2Req
	// TwoFAStatus enumerates the 2FA modes Proton has enabled on an
	// account. The Auth.TwoFA.Enabled field is a bitfield; callers
	// branch on `enabled & HasTOTP != 0` style checks.
	TwoFAStatus = gpa.TwoFAStatus
	// TwoFAInfo is the nested `2FA` payload on Auth/AuthInfo.
	TwoFAInfo = gpa.TwoFAInfo
	// Salt is one entry from /core/v4/keys/salts.
	Salt = gpa.Salt
	// Salts is the slice form of Salt.
	Salts = gpa.Salts
	// Event is one event from /core/v4/events/{id}.
	Event = gpa.Event
	// Message is the full message payload.
	Message = gpa.Message
	// MessageMetadata is the listing-friendly subset of Message.
	MessageMetadata = gpa.MessageMetadata
	// MessageFilter is the filter passed to ListMessages.
	MessageFilter = gpa.MessageFilter
	// SendDraftReq is the request body for /mail/v4/messages/{id} send.
	SendDraftReq = gpa.SendDraftReq
	// User is the upstream user payload (used by Unlock).
	User = gpa.User
	// Address is one entry from /core/v4/addresses (used by Unlock).
	Address = gpa.Address
	// KeyRing aliases the gopenpgp KeyRing returned by Unlock.
	KeyRing = crypto.KeyRing
	// PublicKey is one entry from /core/v4/keys (used by the outbox
	// encryption-mode selector).
	PublicKey = gpa.PublicKey
	// PublicKeys is the slice form returned by GetPublicKeys.
	PublicKeys = gpa.PublicKeys
	// RecipientType discriminates Proton-internal vs external recipients
	// in /core/v4/keys responses.
	RecipientType = gpa.RecipientType
	// APIError is the typed error go-proton-api returns for non-2xx
	// HTTP responses. The outbox uses errors.As to map upstream HTTP
	// status codes onto SMTP reply codes.
	APIError = gpa.APIError
)

// RecipientType constants re-exported so callers do not need to import
// go-proton-api directly. The outbox encryption-mode selector branches
// on these values.
const (
	RecipientTypeInternal = gpa.RecipientTypeInternal
	RecipientTypeExternal = gpa.RecipientTypeExternal
)

// Key-state flag re-exports. PublicKey.Flags is a bitfield; the outbox
// checks `Flags & KeyStateActive != 0` to decide whether a key is
// usable for encryption.
const (
	KeyStateTrusted = gpa.KeyStateTrusted
	KeyStateActive  = gpa.KeyStateActive
)

// 2FA mode constants. Auth.TwoFA.Enabled is a bitfield; the wizard
// branches on `enabled & HasTOTP != 0` etc. to decide which second-
// factor screen to render.
const (
	HasTOTP         = gpa.HasTOTP
	HasFIDO2        = gpa.HasFIDO2
	HasFIDO2AndTOTP = gpa.HasFIDO2AndTOTP
)

// ErrNotAuthenticated is returned by methods that require a session
// when the wrapping client was constructed without one (or the session
// has been revoked via Logout).
var ErrNotAuthenticated = errors.New("proton: client has no active session")

// Client is the only Proton surface the rest of Reduit imports. The
// method set is intentionally minimal: just enough to drive the relay
// (auth, mailbox unlock, event polling, message read/send, attachment
// download, logout). Anything outside this set should require a fresh
// ADR before being added.
//
// Concrete implementations are obtained from Manager.NewClient,
// Manager.WithAccount, or Manager.NewClientWithLogin. The interface is
// stable; the underlying upstream library is not.
//
// Note: there is intentionally no Auth method on Client. New sessions
// come from Manager.NewClientWithLogin so that (a) callers can branch
// on the returned *AuthInfo to detect 2FA requirements and (b) one
// session-bearing Client cannot silently swap to a different user's
// tokens mid-flight (which would invalidate any goroutine holding a
// reference to the upstream client).
type Client interface {
	// AuthInfo fetches the SRP challenge for `username`. Pre-auth
	// (does not require a session). Round-trips /auth/v4/info.
	AuthInfo(ctx context.Context, req AuthInfoReq) (AuthInfo, error)

	// AuthTOTP submits a TOTP second factor against /auth/v4/2fa.
	// Requires an active session (post-Auth, pre-2FA-complete).
	AuthTOTP(ctx context.Context, code string) error

	// AuthFIDO2 submits a FIDO2 second factor against /auth/v4/2fa.
	// Requires an active session.
	AuthFIDO2(ctx context.Context, req FIDO2Req) error

	// KeySalts fetches the per-key salt list for the authenticated
	// user. Required input to Unlock.
	KeySalts(ctx context.Context) (Salts, error)

	// GetUser fetches the authenticated Proton user payload (including
	// Keys). Required input to Unlock.
	GetUser(ctx context.Context) (User, error)

	// GetAddresses fetches every address (and per-address keys) belonging
	// to the authenticated user. Required input to Unlock; the returned
	// slice drives the per-address keyring map Unlock returns.
	GetAddresses(ctx context.Context) ([]Address, error)

	// Unlock decrypts the user keyring with the salted mailbox
	// password. Returns the user keyring and per-address keyrings.
	// This is a *pure* function in upstream (no HTTP) — we expose it
	// on Client so callers can stay inside the proton package.
	Unlock(user User, addresses []Address, saltedKeyPass []byte) (userKR *KeyRing, addrKRs map[string]*KeyRing, err error)

	// GetEvent fetches the Proton event(s) since `eventID` from
	// /core/v4/events/{id}. The upstream client coalesces up to 50
	// events per call; we return the slice as-is.
	GetEvent(ctx context.Context, eventID string) ([]Event, bool, error)

	// GetLatestEventID returns the cursor for "right now" — the event
	// ID a brand-new worker should resume from when no on-disk cursor
	// exists. Round-trips /core/v4/events/latest. Required by SPEC-0002
	// REQ "Event Cursor Persistence" so a first-time worker does not
	// re-process the entire historical event log.
	GetLatestEventID(ctx context.Context) (string, error)

	// GetMessage fetches the full body of one message.
	GetMessage(ctx context.Context, messageID string) (Message, error)

	// ListMessages returns metadata for all messages matching `filter`.
	// Wraps the upstream paged GetMessageMetadata.
	ListMessages(ctx context.Context, filter MessageFilter) ([]MessageMetadata, error)

	// SendDraft submits a draft for delivery via /mail/v4/messages/{id}.
	SendDraft(ctx context.Context, draftID string, req SendDraftReq) (Message, error)

	// GetPublicKeys queries /core/v4/keys?Email=<address> and returns
	// the public keys plus the recipient type (internal vs external).
	// The outbox encryption-mode selector consumes both pieces of data
	// to choose between PGP-encrypted (internal/WKD) and cleartext-relay
	// submission for each recipient on a message.
	//
	// Network or server-side errors MUST be surfaced verbatim — the
	// outbox treats them as fail-closed (rejects the send) so a
	// transient lookup failure cannot accidentally downgrade a Proton-
	// internal recipient from PGP-encrypted to cleartext.
	//
	// Governing: SPEC-0004 REQ "Encryption Pipeline".
	GetPublicKeys(ctx context.Context, address string) (PublicKeys, RecipientType, error)

	// GetAttachment downloads the decrypted bytes of one attachment.
	GetAttachment(ctx context.Context, attachmentID string) ([]byte, error)

	// LabelMessages adds the given Proton label ID to each message in
	// messageIDs. Used by the IMAP MOVE / COPY handlers to translate
	// per-mailbox membership into Proton's additive label model.
	//
	// Governing: SPEC-0003 REQ "Folder Hierarchy and Mapping" — moves
	// between system folders or between Labels/* mailboxes are
	// implemented as a remove-old + add-new pair on the Proton side.
	LabelMessages(ctx context.Context, messageIDs []string, labelID string) error

	// UnlabelMessages is the inverse: removes the given Proton label
	// from each message. Paired with LabelMessages by the IMAP MOVE
	// handler to materialise the additive model.
	UnlabelMessages(ctx context.Context, messageIDs []string, labelID string) error

	// Logout revokes the session via /auth/v4 DELETE and releases
	// the underlying upstream client. Idempotent; safe to call on a
	// pre-auth client (returns nil).
	Logout(ctx context.Context) error
}

// clientImpl is the production wrapper around go-proton-api's *Client.
// It also keeps a reference to the owning Manager so pre-auth calls
// (AuthInfo) can route through the Manager-level methods.
//
// Lifecycle invariant: client lifecycle (adopt/Logout) is serialized by
// upMu (RWMutex). Per-call methods take RLock so concurrent reads can
// proceed in parallel but Logout (write lock) drains all in-flight
// reads before tearing down the upstream client. This eliminates the
// race documented in the hostile review of PR #37 where Logout could
// Close() an upstream client mid-request.
type clientImpl struct {
	mgr       *Manager
	upMu      sync.RWMutex
	up        *gpa.Client // nil if pre-auth or post-Logout
	loggedOut bool
}

// adoptUpstream installs `up` as the live upstream client and registers
// the auth handler that drives the refresh-token persistence callback.
// Takes the lifecycle write lock; safe to call concurrently with reads.
func (c *clientImpl) adoptUpstream(up *gpa.Client) {
	c.upMu.Lock()
	defer c.upMu.Unlock()
	if c.up != nil {
		// Replacing an existing session — close the old one so
		// hooks/handlers don't outlive it.
		c.up.Close()
	}
	c.up = up
	c.loggedOut = false
	c.installRefreshHandler(up)
}

// installRefreshHandler wires AddAuthHandler so refresh-token rotations
// invoke whichever RefreshTokenCallback is registered on the Manager
// at *fire time*, not adopt time. Resolving the callback inside the
// closure (instead of capturing it once at adopt time) means the
// composition root can swap the callback in after construction — useful
// when the account service is initialised lazily — without leaving
// adopted clients permanently deaf to rotations.
//
// Governing: hostile-review Blocker 2 of PR #37.
func (c *clientImpl) installRefreshHandler(up *gpa.Client) {
	up.AddAuthHandler(func(a gpa.Auth) {
		cb := c.mgr.refreshTokenCallback()
		if cb == nil {
			return
		}
		// AuthHandler runs synchronously inside go-proton-api's
		// authRefresh path. Use Background ctx so a cancelled
		// caller-ctx doesn't prevent us from persisting the token —
		// the rotation has already happened upstream.
		ctx := context.Background()
		if err := cb(ctx, a.RefreshToken); err != nil {
			c.mgr.opts.Logger.LogAttrs(ctx, slog.LevelError,
				"failed to persist rotated proton refresh token",
				slog.Any("err", err),
			)
		}
	})
}

// requireSession returns the upstream client or ErrNotAuthenticated,
// holding the lifecycle read lock for the caller's duration.
//
// The caller MUST invoke the returned release func when done so Logout
// can proceed. Implemented as a deferred release pattern (instead of a
// raw RLock release in callers) so per-method bodies stay tidy and we
// can't accidentally drop the read lock before the upstream call
// returns. The release func is safe to call multiple times.
func (c *clientImpl) requireSession() (*gpa.Client, func(), error) {
	c.upMu.RLock()
	if c.up == nil || c.loggedOut {
		c.upMu.RUnlock()
		return nil, func() {}, ErrNotAuthenticated
	}
	var released bool
	release := func() {
		if released {
			return
		}
		released = true
		c.upMu.RUnlock()
	}
	return c.up, release, nil
}

// AuthInfo (pre-auth) routes through the Manager.
func (c *clientImpl) AuthInfo(ctx context.Context, req AuthInfoReq) (AuthInfo, error) {
	return c.mgr.up.AuthInfo(ctx, req)
}

// AuthTOTP submits the TOTP second factor.
func (c *clientImpl) AuthTOTP(ctx context.Context, code string) error {
	up, release, err := c.requireSession()
	if err != nil {
		return err
	}
	defer release()
	return up.Auth2FA(ctx, Auth2FAReq{TwoFactorCode: code})
}

// AuthFIDO2 submits the FIDO2 second factor.
func (c *clientImpl) AuthFIDO2(ctx context.Context, req FIDO2Req) error {
	up, release, err := c.requireSession()
	if err != nil {
		return err
	}
	defer release()
	return up.Auth2FA(ctx, Auth2FAReq{FIDO2: req})
}

// KeySalts fetches the per-key salt list.
func (c *clientImpl) KeySalts(ctx context.Context) (Salts, error) {
	up, release, err := c.requireSession()
	if err != nil {
		return nil, err
	}
	defer release()
	return up.GetSalts(ctx)
}

// GetUser fetches the authenticated user.
func (c *clientImpl) GetUser(ctx context.Context) (User, error) {
	up, release, err := c.requireSession()
	if err != nil {
		return User{}, err
	}
	defer release()
	return up.GetUser(ctx)
}

// GetAddresses fetches the authenticated user's addresses.
func (c *clientImpl) GetAddresses(ctx context.Context) ([]Address, error) {
	up, release, err := c.requireSession()
	if err != nil {
		return nil, err
	}
	defer release()
	return up.GetAddresses(ctx)
}

// Unlock is a pure operation upstream; we just forward.
func (c *clientImpl) Unlock(user User, addresses []Address, saltedKeyPass []byte) (*KeyRing, map[string]*KeyRing, error) {
	return gpa.Unlock(user, addresses, saltedKeyPass, nil)
}

// GetEvent forwards to the upstream client.
func (c *clientImpl) GetEvent(ctx context.Context, eventID string) ([]Event, bool, error) {
	up, release, err := c.requireSession()
	if err != nil {
		return nil, false, err
	}
	defer release()
	return up.GetEvent(ctx, eventID)
}

// GetLatestEventID forwards to the upstream client.
func (c *clientImpl) GetLatestEventID(ctx context.Context) (string, error) {
	up, release, err := c.requireSession()
	if err != nil {
		return "", err
	}
	defer release()
	return up.GetLatestEventID(ctx)
}

// GetMessage forwards to the upstream client.
func (c *clientImpl) GetMessage(ctx context.Context, messageID string) (Message, error) {
	up, release, err := c.requireSession()
	if err != nil {
		return Message{}, err
	}
	defer release()
	return up.GetMessage(ctx, messageID)
}

// ListMessages wraps the upstream paged GetMessageMetadata.
func (c *clientImpl) ListMessages(ctx context.Context, filter MessageFilter) ([]MessageMetadata, error) {
	up, release, err := c.requireSession()
	if err != nil {
		return nil, err
	}
	defer release()
	return up.GetMessageMetadata(ctx, filter)
}

// SendDraft submits a draft for delivery.
func (c *clientImpl) SendDraft(ctx context.Context, draftID string, req SendDraftReq) (Message, error) {
	up, release, err := c.requireSession()
	if err != nil {
		return Message{}, err
	}
	defer release()
	return up.SendDraft(ctx, draftID, req)
}

// GetPublicKeys forwards to the upstream client. The outbox uses the
// returned RecipientType to discriminate between PGP-encrypted internal
// recipients and external recipients (with or without a published key).
func (c *clientImpl) GetPublicKeys(ctx context.Context, address string) (PublicKeys, RecipientType, error) {
	up, release, err := c.requireSession()
	if err != nil {
		return nil, RecipientTypeExternal, err
	}
	defer release()
	return up.GetPublicKeys(ctx, address)
}

// GetAttachment downloads the decrypted bytes of an attachment.
func (c *clientImpl) GetAttachment(ctx context.Context, attachmentID string) ([]byte, error) {
	up, release, err := c.requireSession()
	if err != nil {
		return nil, err
	}
	defer release()
	return up.GetAttachment(ctx, attachmentID)
}

// LabelMessages forwards to the upstream client.
func (c *clientImpl) LabelMessages(ctx context.Context, messageIDs []string, labelID string) error {
	up, release, err := c.requireSession()
	if err != nil {
		return err
	}
	defer release()
	return up.LabelMessages(ctx, messageIDs, labelID)
}

// UnlabelMessages forwards to the upstream client.
func (c *clientImpl) UnlabelMessages(ctx context.Context, messageIDs []string, labelID string) error {
	up, release, err := c.requireSession()
	if err != nil {
		return err
	}
	defer release()
	return up.UnlabelMessages(ctx, messageIDs, labelID)
}

// Logout revokes the session and tears down the upstream client.
// Calling Logout twice (or on a pre-auth client) is a no-op.
//
// On a network-partition AuthDelete failure the local state is still
// torn down (the upstream session will expire server-side after the
// access-token TTL). Callers that need stronger revoke-or-fail
// semantics should retry AuthDelete themselves before calling Logout.
//
// Governing: hostile-review Blocker 3 of PR #37 — the previous
// implementation released the lock between AuthDelete and Close, which
// allowed adoptUpstream to swap c.up under our feet and have the second
// Close wipe the wrong client. We now do AuthDelete + Close on a
// snapshot taken under the write lock, hold the write lock across both
// calls, and nil out c.up so the "c.up != nil implies live client"
// invariant is restored.
func (c *clientImpl) Logout(ctx context.Context) error {
	// Phase 1: take the write lock to drain any in-flight reads (each
	// per-call method holds RLock for the duration of its upstream
	// request), snapshot the upstream client, mark loggedOut, and nil
	// c.up so any subsequent read takes the ErrNotAuthenticated path.
	c.upMu.Lock()
	if c.up == nil || c.loggedOut {
		c.upMu.Unlock()
		return nil
	}
	up := c.up
	c.loggedOut = true
	c.up = nil
	c.upMu.Unlock()

	// Phase 2: AuthDelete and Close run on the local snapshot with no
	// lock held, so a slow network can't starve callers of WithAccount
	// or NewClientWithLogin (which need the write lock). No one else
	// holds a reference to `up` (we nilled c.up under the write lock,
	// and per-call methods always re-resolve c.up under RLock), so the
	// snapshot is exclusively ours.
	delErr := up.AuthDelete(ctx)
	up.Close()
	return delErr
}
