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
// Concrete implementations are obtained from Manager.NewClient or
// Manager.NewClientWithLogin. The interface is stable; the underlying
// upstream library is not.
type Client interface {
	// AuthInfo fetches the SRP challenge for `username`. Pre-auth
	// (does not require a session). Round-trips /auth/v4/info.
	AuthInfo(ctx context.Context, req AuthInfoReq) (AuthInfo, error)

	// Auth performs SRP login for `username` with `password` (raw
	// bytes — no salt yet). On success the wrapping Client adopts
	// the returned UID/access/refresh tokens. Pre-auth.
	Auth(ctx context.Context, username string, password []byte) (Auth, error)

	// AuthTOTP submits a TOTP second factor against /auth/v4/2fa.
	// Requires an active session (post-Auth, pre-2FA-complete).
	AuthTOTP(ctx context.Context, code string) error

	// AuthFIDO2 submits a FIDO2 second factor against /auth/v4/2fa.
	// Requires an active session.
	AuthFIDO2(ctx context.Context, req FIDO2Req) error

	// KeySalts fetches the per-key salt list for the authenticated
	// user. Required input to Unlock.
	KeySalts(ctx context.Context) (Salts, error)

	// Unlock decrypts the user keyring with the salted mailbox
	// password. Returns the user keyring and per-address keyrings.
	// This is a *pure* function in upstream (no HTTP) — we expose it
	// on Client so callers can stay inside the proton package.
	Unlock(user User, addresses []Address, saltedKeyPass []byte) (userKR *KeyRing, addrKRs map[string]*KeyRing, err error)

	// GetEvent fetches the Proton event(s) since `eventID` from
	// /core/v4/events/{id}. The upstream client coalesces up to 50
	// events per call; we return the slice as-is.
	GetEvent(ctx context.Context, eventID string) ([]Event, bool, error)

	// GetMessage fetches the full body of one message.
	GetMessage(ctx context.Context, messageID string) (Message, error)

	// ListMessages returns metadata for all messages matching `filter`.
	// Wraps the upstream paged GetMessageMetadata.
	ListMessages(ctx context.Context, filter MessageFilter) ([]MessageMetadata, error)

	// SendDraft submits a draft for delivery via /mail/v4/messages/{id}.
	SendDraft(ctx context.Context, draftID string, req SendDraftReq) (Message, error)

	// GetAttachment downloads the decrypted bytes of one attachment.
	GetAttachment(ctx context.Context, attachmentID string) ([]byte, error)

	// Logout revokes the session via /auth/v4 DELETE and releases
	// the underlying upstream client. Idempotent; safe to call on a
	// pre-auth client (returns nil).
	Logout(ctx context.Context) error
}

// clientImpl is the production wrapper around go-proton-api's *Client.
// It also keeps a reference to the owning Manager so pre-auth calls
// (AuthInfo, Auth) can route through the Manager-level methods.
type clientImpl struct {
	mgr       *Manager
	upMu      sync.Mutex
	up        *gpa.Client // nil if pre-auth or post-Logout
	loggedOut bool
}

// adoptUpstream replaces the underlying *gpa.Client and registers the
// auth handler that drives the refresh-token persistence callback.
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
// invoke the user-supplied RefreshTokenCallback. We call AddAuthHandler
// once per upstream client; the upstream library itself dedupes nothing,
// so we must avoid attaching to the same *gpa.Client twice.
func (c *clientImpl) installRefreshHandler(up *gpa.Client) {
	cb := c.mgr.opts.OnRefreshTokenChange
	if cb == nil {
		return
	}
	log := c.mgr.opts.Logger
	up.AddAuthHandler(func(a gpa.Auth) {
		// AuthHandler runs synchronously inside go-proton-api's
		// authRefresh path. Use Background ctx so a cancelled
		// caller-ctx doesn't prevent us from persisting the token —
		// the rotation has already happened upstream.
		ctx := context.Background()
		if err := cb(ctx, a.RefreshToken); err != nil {
			log.LogAttrs(ctx, slog.LevelError,
				"failed to persist rotated proton refresh token",
				slog.Any("err", err),
			)
		}
	})
}

// requireSession returns the upstream client or ErrNotAuthenticated.
func (c *clientImpl) requireSession() (*gpa.Client, error) {
	c.upMu.Lock()
	defer c.upMu.Unlock()
	if c.up == nil || c.loggedOut {
		return nil, ErrNotAuthenticated
	}
	return c.up, nil
}

// AuthInfo (pre-auth) routes through the Manager.
func (c *clientImpl) AuthInfo(ctx context.Context, req AuthInfoReq) (AuthInfo, error) {
	return c.mgr.up.AuthInfo(ctx, req)
}

// Auth performs SRP login at the Manager level and adopts the resulting
// upstream client. After this call the wrapping Client carries the new
// UID/access/refresh tokens.
func (c *clientImpl) Auth(ctx context.Context, username string, password []byte) (Auth, error) {
	up, auth, err := c.mgr.up.NewClientWithLogin(ctx, username, password)
	if err != nil {
		return Auth{}, err
	}
	c.adoptUpstream(up)
	// Fire the refresh-token callback once on initial login so the
	// account record gets the very first refresh token, not just
	// rotations after that.
	if cb := c.mgr.opts.OnRefreshTokenChange; cb != nil {
		if cbErr := cb(ctx, auth.RefreshToken); cbErr != nil {
			c.mgr.opts.Logger.LogAttrs(ctx, slog.LevelError,
				"failed to persist initial proton refresh token",
				slog.Any("err", cbErr),
			)
		}
	}
	return auth, nil
}

// AuthTOTP submits the TOTP second factor.
func (c *clientImpl) AuthTOTP(ctx context.Context, code string) error {
	up, err := c.requireSession()
	if err != nil {
		return err
	}
	return up.Auth2FA(ctx, Auth2FAReq{TwoFactorCode: code})
}

// AuthFIDO2 submits the FIDO2 second factor.
func (c *clientImpl) AuthFIDO2(ctx context.Context, req FIDO2Req) error {
	up, err := c.requireSession()
	if err != nil {
		return err
	}
	return up.Auth2FA(ctx, Auth2FAReq{FIDO2: req})
}

// KeySalts fetches the per-key salt list.
func (c *clientImpl) KeySalts(ctx context.Context) (Salts, error) {
	up, err := c.requireSession()
	if err != nil {
		return nil, err
	}
	return up.GetSalts(ctx)
}

// Unlock is a pure operation upstream; we just forward.
func (c *clientImpl) Unlock(user User, addresses []Address, saltedKeyPass []byte) (*KeyRing, map[string]*KeyRing, error) {
	return gpa.Unlock(user, addresses, saltedKeyPass, nil)
}

// GetEvent forwards to the upstream client.
func (c *clientImpl) GetEvent(ctx context.Context, eventID string) ([]Event, bool, error) {
	up, err := c.requireSession()
	if err != nil {
		return nil, false, err
	}
	return up.GetEvent(ctx, eventID)
}

// GetMessage forwards to the upstream client.
func (c *clientImpl) GetMessage(ctx context.Context, messageID string) (Message, error) {
	up, err := c.requireSession()
	if err != nil {
		return Message{}, err
	}
	return up.GetMessage(ctx, messageID)
}

// ListMessages wraps the upstream paged GetMessageMetadata.
func (c *clientImpl) ListMessages(ctx context.Context, filter MessageFilter) ([]MessageMetadata, error) {
	up, err := c.requireSession()
	if err != nil {
		return nil, err
	}
	return up.GetMessageMetadata(ctx, filter)
}

// SendDraft submits a draft for delivery.
func (c *clientImpl) SendDraft(ctx context.Context, draftID string, req SendDraftReq) (Message, error) {
	up, err := c.requireSession()
	if err != nil {
		return Message{}, err
	}
	return up.SendDraft(ctx, draftID, req)
}

// GetAttachment downloads the decrypted bytes of an attachment.
func (c *clientImpl) GetAttachment(ctx context.Context, attachmentID string) ([]byte, error) {
	up, err := c.requireSession()
	if err != nil {
		return nil, err
	}
	return up.GetAttachment(ctx, attachmentID)
}

// Logout revokes the session and tears down the upstream client.
// Calling Logout twice (or on a pre-auth client) is a no-op.
func (c *clientImpl) Logout(ctx context.Context) error {
	c.upMu.Lock()
	up := c.up
	already := c.loggedOut
	c.upMu.Unlock()
	if up == nil || already {
		return nil
	}
	delErr := up.AuthDelete(ctx)
	c.upMu.Lock()
	c.loggedOut = true
	if c.up != nil {
		c.up.Close()
	}
	c.upMu.Unlock()
	return delErr
}
