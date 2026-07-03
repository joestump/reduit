package proton

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"time"

	"github.com/ProtonMail/gluon/async"
	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"golang.org/x/net/publicsuffix"
)

// Config configures a GPADialer (and therefore the underlying go-proton-api
// Manager). The auth CLI (#86) supplies it; everything here is non-secret.
type Config struct {
	// HostURL is the Proton API base URL. Empty uses go-proton-api's default
	// production host.
	HostURL string
	// AppVersion is the Proton app-version string. Proton rejects requests
	// without an acceptable value; the auth layer sets reduit's.
	AppVersion string
	// Transport, when non-nil, replaces the default HTTP transport. Tests point
	// it at an httptest.Server; production leaves it nil.
	Transport http.RoundTripper
	// Logger receives go-proton-api's diagnostic logging via a resty.Logger
	// shim (ADR-0001). Nil discards it. Secrets are never logged here
	// (SPEC-0007 REQ "No Secret Leakage").
	Logger *slog.Logger
}

// GPADialer is the go-proton-api-backed Dialer. It owns a single *gpa.Manager
// (the connection pool) and mints Clients from it. The Manager already carries
// the resolved app-version and host (WithAppVersion/WithHostURL below), so the
// Clients it mints need not re-hold them.
type GPADialer struct {
	mgr *gpa.Manager
}

// NewDialer builds a GPADialer and its underlying go-proton-api Manager from
// cfg. The Manager is the thin edge over the network; the Dialer/Client
// interface above it is what reduit's layers depend on (ADR-0001).
func NewDialer(cfg Config) *GPADialer {
	// Note: we pass WithLogger but deliberately NOT WithDebug. go-proton-api
	// gates resty's request/response BODY logging on its own debug flag (default
	// off), not on the logger or its level. So even under reduit's --verbose
	// (which only raises reduit's slog level) the SRP/auth payloads, TOTP code,
	// and refresh token are never written to the logs (SPEC-0007 "No Secret
	// Leakage"). The logger here only receives resty's connection-level
	// diagnostics, which carry no secret.
	opts := []gpa.Option{gpa.WithLogger(newSlogLogger(cfg.Logger))}
	// An in-memory cookie jar is REQUIRED for human verification: Proton sets
	// a session cookie alongside the 9001 challenge that server-side ties the
	// challenge token to THIS client session. Without the jar the cookie is
	// dropped and the post-solve retry presents a verified token from what
	// looks like a different session — Proton rejects it with 12087 "CAPTCHA
	// validation failed" (observed live, twice, on clean solves). Proton
	// Bridge sets a jar for the same reason (its internal/bridge/api.go).
	// In-memory only: nothing persisted, secrets stay in the keychain
	// (ADR-0013). Governing: ADR-0021, SPEC-0007 "SRP and 2FA Handling".
	// cookiejar.New never returns an error for valid options (stdlib contract),
	// but if it ever did, silently proceeding would regress HV to exactly the
	// 12087 mystery this jar fixes — so log loudly rather than swallow it.
	if jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List}); err == nil {
		opts = append(opts, gpa.WithCookieJar(jar))
	} else if cfg.Logger != nil {
		cfg.Logger.Error("proton: cookie jar init failed; human verification will not validate", "error", err)
	}
	if cfg.HostURL != "" {
		opts = append(opts, gpa.WithHostURL(cfg.HostURL))
	}
	if cfg.AppVersion != "" {
		opts = append(opts, gpa.WithAppVersion(cfg.AppVersion))
	}
	if cfg.Transport != nil {
		opts = append(opts, gpa.WithTransport(cfg.Transport))
	}
	return &GPADialer{mgr: gpa.New(opts...)}
}

// Close releases the Manager's pooled connections.
func (d *GPADialer) Close() { d.mgr.Close() }

// NewClient returns a fresh unauthenticated client for the Login flow.
func (d *GPADialer) NewClient() Client {
	return &gpaClient{mgr: d.mgr}
}

// Resume reconstructs an authenticated client from a stored session UID, access
// token, and refresh token (SPEC-0007 "Cross-Process Session Resume"). It uses
// go-proton-api's session-REUSE constructor Manager.NewClient(uid, acc, ref),
// which re-hydrates the cached session from the stored tokens and makes NO
// network call — deliberately NOT Manager.NewClientWithRefresh, whose eager
// /auth/v4/refresh of a freshly-2FA'd session returns a REDUCED scope that later
// fails key/salt access with 403 code 9101 (the "used the wrong newClient
// function" gotcha documented by Proton-API-Bridge). Reusing the cached access
// token preserves the 2FA-elevated scope; go-proton-api lazily refreshes only
// when that token expires (on a 401), and the registered auth handler captures
// the rotated tokens then (setClient). This mirrors Proton Bridge's session
// caching.
//
// Because NewClient performs no I/O, Resume does not validate the session here;
// the first real API call (Labels/Unlock/…) surfaces an invalid session. The
// caller reads AccessToken/RefreshToken/SessionUID after its operations and
// persists any that rotated (ADR-0013). The returned client is authenticated but
// not unlocked; the caller supplies the passphrase to Unlock.
//
// sessionUID is REQUIRED for the later lazy /auth/v4/refresh, which identifies
// the session by its UID (AuthRefreshReq.UID), NOT by the refresh token alone;
// a lazy refresh with UID="" yields 10013 "Invalid refresh token". accessToken
// is REQUIRED to preserve scope; callers that lack it (a pre-fix mailbox row)
// must not reach here — see the actionable re-add error in auth.go/labels.go and
// the sync engine.
//
// No post-resume account-identity check is done: a stored (session_uid, tokens)
// tuple is bound to the session that minted it, which is bound to one account —
// it cannot resolve a different Proton user. The account-switch guard that
// matters lives in the INTERACTIVE re-auth path (auth.go re-login verifies
// proton_user_id). c.userID stays the seeded proton_user_id. Governing:
// SPEC-0007 "Cross-Process Session Resume" / "Re-Auth Flow", ADR-0001.
func (d *GPADialer) Resume(_ context.Context, protonUserID, sessionUID, accessToken, refreshToken string) (Client, error) {
	c := &gpaClient{mgr: d.mgr, userID: protonUserID, uid: sessionUID, accessToken: accessToken, refreshToken: refreshToken}
	c.setClient(d.mgr.NewClient(sessionUID, accessToken, refreshToken))
	return c, nil
}

// gpaClient is the go-proton-api-backed Client for one Proton account. It is
// deliberately thin: each method translates reduit types to/from upstream and
// delegates straight to the *gpa.Client. The wrapper's own (testable) logic
// lives in the pure helpers it calls (classify2FA, classifyError,
// collectEvents, validateOutgoing, buildDraftTemplate).
//
// Not safe for concurrent use; the sync layer runs one client per mailbox
// worker (ADR-0014 "per-mailbox worker").
type gpaClient struct {
	mgr *gpa.Manager
	cli *gpa.Client

	userID       string // immutable proton_user_id, set on Login/Resume
	uid          string // go-proton-api session UID
	accessToken  string // rotated on Login, Refresh, and lazy refresh
	refreshToken string // rotated on Login, Refresh, and lazy refresh

	// Unlock state. Populated by Unlock, used by decrypt/send.
	addrKRs   map[string]*crypto.KeyRing // address id -> unlocked keyring
	addresses []gpa.Address              // address metadata (id -> email)
}

var _ Client = (*gpaClient)(nil)

// Login runs the SRP password exchange via go-proton-api (SPEC-0007 REQ "SRP
// and 2FA Handling"). reduit never implements SRP itself. When Proton demands
// human verification (code 9001), Login returns a typed *HVRequiredError. reduit
// avoids this challenge by identifying as a Proton Bridge client by default
// (DefaultAppVersion), which Proton waves through; the CLI turns any HV that does
// surface into a clear app-version error rather than solving it in-app (ADR-0021,
// SPEC-0007 scenario "Human verification / CAPTCHA is requested").
func (c *gpaClient) Login(ctx context.Context, address string, password []byte) (AuthStatus, error) {
	cli, auth, err := c.mgr.NewClientWithLogin(ctx, address, password)
	if err != nil {
		if hv, ok := hvRequiredFrom(err); ok {
			return AuthStatus{}, hv
		}
		return AuthStatus{}, classifyError(err)
	}
	return c.applyAuth(cli, auth), nil
}

// applyAuth records the authenticated session from a successful login and
// derives the reduit AuthStatus: store the client, session UID, immutable
// proton_user_id, and the rotated access + refresh tokens, and compute the 2FA
// state. The mailbox keyring is loaded later by Unlock, not here.
func (c *gpaClient) applyAuth(cli *gpa.Client, auth gpa.Auth) AuthStatus {
	c.setClient(cli)
	c.uid = auth.UID
	c.userID = auth.UserID
	c.accessToken = auth.AccessToken
	c.refreshToken = auth.RefreshToken
	return AuthStatus{ProtonUserID: auth.UserID, TwoFA: classify2FA(auth.TwoFA)}
}

// setClient installs a freshly-minted *gpa.Client (from login, refresh, or a
// resume's session reuse), closing any prior one, and registers the auth handler
// that keeps this wrapper's tokens in step with go-proton-api's own. When the
// cached access token expires, go-proton-api lazily refreshes on a 401 and
// invokes the handler with the new Auth; capturing it here is how a full-scope
// session is kept fresh across a long-running sync, and how the caller learns
// the rotated tokens to persist (ADR-0013, SPEC-0007 "Cross-Process Session
// Resume"). The wrapper is single-worker (not concurrent), and go-proton-api
// invokes the handler synchronously inside the triggering request, so these
// field writes need no additional locking.
func (c *gpaClient) setClient(cli *gpa.Client) {
	if c.cli != nil {
		c.cli.Close()
	}
	c.cli = cli
	cli.AddAuthHandler(c.onAuth)
}

// onAuth is the go-proton-api AuthHandler installed by setClient. go-proton-api
// invokes it after a lazy /auth/v4/refresh with the rotated session state, so
// the wrapper's tokens track the live session and the caller can persist the
// rotated values (SPEC-0007 "Cross-Process Session Resume"). A lazy refresh may
// omit the account UserID (see refreshWithUID) but always carries the rotated
// session UID and tokens, so UID is guarded against an empty clobber.
func (c *gpaClient) onAuth(auth gpa.Auth) {
	if auth.UID != "" {
		c.uid = auth.UID
	}
	c.accessToken = auth.AccessToken
	c.refreshToken = auth.RefreshToken
}

// SubmitTOTP completes a login that reported TwoFATOTP.
func (c *gpaClient) SubmitTOTP(ctx context.Context, code string) error {
	if c.cli == nil {
		return ErrNotAuthenticated
	}
	if err := c.cli.Auth2FA(ctx, gpa.Auth2FAReq{TwoFactorCode: code}); err != nil {
		return classifyError(err)
	}
	return nil
}

// Unlock decrypts the mailbox OpenPGP keys with the passphrase and retains the
// per-address keyrings (SPEC-0007 REQ "Mailbox Passphrase Capture and Key
// Unlock"). The passphrase and the salted key passphrase derived from it are
// transient locals and are never logged or persisted.
func (c *gpaClient) Unlock(ctx context.Context, passphrase []byte) error {
	if c.cli == nil {
		return ErrNotAuthenticated
	}
	user, err := c.cli.GetUser(ctx)
	if err != nil {
		return classifyError(err)
	}
	addrs, err := c.cli.GetAddresses(ctx)
	if err != nil {
		return classifyError(err)
	}
	salts, err := c.cli.GetSalts(ctx)
	if err != nil {
		return classifyError(err)
	}
	// go-proton-api's Keys.Primary() PANICS when no key carries the Primary
	// flag (#123). Select the primary key id defensively so a malformed key
	// set surfaces as a typed error rather than a crash on the user's login
	// path (SPEC-0007 REQ "Mailbox Passphrase Capture and Key Unlock").
	primaryKeyID, err := primaryKeyID(user.Keys)
	if err != nil {
		return err
	}
	keyPass, err := salts.SaltForKey(passphrase, primaryKeyID)
	if err != nil {
		// Salt lookup for the (already-validated) primary key failed; this is a
		// key-set problem, not a wrong-passphrase one, so don't claim the value
		// was wrong.
		return fmt.Errorf("proton: derive key passphrase: %w", err)
	}
	_, addrKRs, err := gpa.Unlock(user, addrs, keyPass, async.NoopPanicHandler{})
	if err != nil {
		// Wrong passphrase or undecryptable keys. The error from go-proton-api
		// does not contain the passphrase; ErrUnlockFailed carries no secret.
		return fmt.Errorf("%w: %v", ErrUnlockFailed, err)
	}
	c.userID = user.ID
	c.addresses = addrs
	c.addrKRs = addrKRs
	return nil
}

func (c *gpaClient) ProtonUserID() string { return c.userID }
func (c *gpaClient) RefreshToken() string { return c.refreshToken }

// AccessToken returns the Proton access token. It is captured at Login and
// re-read after every Refresh/Resume and lazy refresh, so a rotated value is
// observable here and can be re-persisted (SPEC-0007 "Cross-Process Session
// Resume").
func (c *gpaClient) AccessToken() string { return c.accessToken }

// SessionUID returns the go-proton-api session UID. It is captured at Login
// (applyAuth) and re-read after every Refresh/Resume, so a rotated UID is
// observable here and can be re-persisted.
func (c *gpaClient) SessionUID() string { return c.uid }

// Refresh rotates the session from the stored refresh token.
func (c *gpaClient) Refresh(ctx context.Context) error {
	return c.refreshWithUID(ctx, c.uid)
}

// refreshWithUID performs the refresh-token rotation. uid identifies the session
// to Proton's /auth/v4/refresh (AuthRefreshReq.UID) and is required — Proton
// does NOT derive it from the refresh token, so passing "" yields 10013 "Invalid
// refresh token". The rotated UID from the response is stored back on c.uid so a
// rotated UID is observable via SessionUID().
func (c *gpaClient) refreshWithUID(ctx context.Context, uid string) error {
	if c.refreshToken == "" {
		return ErrNotAuthenticated
	}
	cli, auth, err := c.mgr.NewClientWithRefresh(ctx, uid, c.refreshToken)
	if err != nil {
		return classifyError(err)
	}
	c.setClient(cli)
	c.uid = auth.UID
	// /auth/v4/refresh does not return the account UserID, so auth.UserID is
	// empty on a refresh — do NOT clobber a userID we already know (seeded at
	// Resume from the stored proton_user_id, or set by Login/Unlock in a live
	// session). Only overwrite when the response actually carries one.
	if auth.UserID != "" {
		c.userID = auth.UserID
	}
	c.accessToken = auth.AccessToken
	c.refreshToken = auth.RefreshToken
	return nil
}

// Labels fetches the account's labels, folders, and system mailboxes and maps
// them to reduit's domain type. It needs only an authenticated session (no
// Unlock), making it the cheap end-to-end connectivity check the CLI runs.
func (c *gpaClient) Labels(ctx context.Context) ([]Label, error) {
	if c.cli == nil {
		return nil, ErrNotAuthenticated
	}
	upstream, err := c.cli.GetLabels(ctx, gpa.LabelTypeLabel, gpa.LabelTypeFolder, gpa.LabelTypeSystem)
	if err != nil {
		return nil, classifyError(err)
	}
	out := make([]Label, 0, len(upstream))
	for _, l := range upstream {
		out = append(out, Label{
			ID:    l.ID,
			Name:  l.Name,
			Type:  labelTypeString(l.Type),
			Color: l.Color,
		})
	}
	return out, nil
}

// labelTypeString maps go-proton-api's numeric LabelType onto reduit's stable
// type strings, keeping the upstream enum out of the domain type.
func labelTypeString(t gpa.LabelType) string {
	switch t {
	case gpa.LabelTypeLabel:
		return LabelTypeLabel
	case gpa.LabelTypeFolder:
		return LabelTypeFolder
	case gpa.LabelTypeSystem:
		return LabelTypeSystem
	default:
		return LabelTypeUnknown
	}
}

// primaryKeyID returns the id of the key flagged Primary, or ErrNoPrimaryKey
// if none is. It replaces go-proton-api's Keys.Primary(), which panics on an
// empty/flagless key set (#123).
func primaryKeyID(keys gpa.Keys) (string, error) {
	for _, k := range keys {
		if bool(k.Primary) {
			return k.ID, nil
		}
	}
	return "", ErrNoPrimaryKey
}

// LatestEventID seeds a mailbox's sync cursor (ADR-0014 "Bootstrap then tail").
func (c *gpaClient) LatestEventID(ctx context.Context) (string, error) {
	if c.cli == nil {
		return "", ErrNotAuthenticated
	}
	id, err := c.cli.GetLatestEventID(ctx)
	if err != nil {
		return "", classifyError(err)
	}
	return id, nil
}

// GetEvents advances the cursor and applies the delta (ADR-0014). The cursor
// translation/invariant lives in the pure collectEvents helper.
func (c *gpaClient) GetEvents(ctx context.Context, sinceEventID string) (EventBatch, error) {
	if c.cli == nil {
		return EventBatch{}, ErrNotAuthenticated
	}
	return collectEvents(ctx, c.cli, sinceEventID)
}

// BackfillMessageIDs enumerates the message ids for a mailbox's first sync,
// bounded to since (ADR-0014 "Bootstrap then tail"). It needs only an
// authenticated session (metadata, no keyring); the paging + time-window logic
// lives in the pure collectBackfillIDs helper.
func (c *gpaClient) BackfillMessageIDs(ctx context.Context, since time.Time) ([]string, error) {
	if c.cli == nil {
		return nil, ErrNotAuthenticated
	}
	return collectBackfillIDs(ctx, c.cli, since)
}

// DecryptMessage fetches and decrypts one message with the unlocked address
// keyring (ADR-0014 "Decrypt in the pipeline").
func (c *gpaClient) DecryptMessage(ctx context.Context, messageID string) (DecryptedMessage, error) {
	if c.addrKRs == nil {
		return DecryptedMessage{}, ErrNotUnlocked
	}
	msg, err := c.cli.GetMessage(ctx, messageID)
	if err != nil {
		return DecryptedMessage{}, classifyError(err)
	}
	kr := c.addrKRs[msg.AddressID]
	if kr == nil {
		return DecryptedMessage{}, fmt.Errorf("%w: address %q", ErrNotUnlocked, msg.AddressID)
	}
	body, err := msg.Decrypt(kr)
	if err != nil {
		return DecryptedMessage{}, fmt.Errorf("proton: decrypt message %s: %w", messageID, err)
	}
	return toDecryptedMessage(msg, body), nil
}

// DecryptAttachment fetches and decrypts one attachment with the message's
// address keyring. The attachment's session key is unwrapped from its key
// packet, then the data packet is decrypted (ADR-0016 governs payload
// handling).
func (c *gpaClient) DecryptAttachment(ctx context.Context, messageID, attachmentID string) ([]byte, error) {
	if c.addrKRs == nil {
		return nil, ErrNotUnlocked
	}
	msg, err := c.cli.GetMessage(ctx, messageID)
	if err != nil {
		return nil, classifyError(err)
	}
	kr := c.addrKRs[msg.AddressID]
	if kr == nil {
		return nil, fmt.Errorf("%w: address %q", ErrNotUnlocked, msg.AddressID)
	}
	var att *gpa.Attachment
	for i := range msg.Attachments {
		if msg.Attachments[i].ID == attachmentID {
			att = &msg.Attachments[i]
			break
		}
	}
	if att == nil {
		return nil, fmt.Errorf("proton: attachment %q not found on message %s", attachmentID, messageID)
	}
	data, err := c.cli.GetAttachment(ctx, attachmentID)
	if err != nil {
		return nil, classifyError(err)
	}
	sessionKey, err := kr.DecryptSessionKey(gpa.DecodeKeyPacket(att.KeyPackets))
	if err != nil {
		return nil, fmt.Errorf("proton: decrypt attachment key %s: %w", attachmentID, err)
	}
	plain, err := sessionKey.Decrypt(data)
	if err != nil {
		return nil, fmt.Errorf("proton: decrypt attachment %s: %w", attachmentID, err)
	}
	return plain.GetBinary(), nil
}

// Send submits a user-composed message (ADR-0020). It validates locally,
// resolves the explicit from-address to an unlocked keyring, builds the draft
// template, and creates the draft. The final transmission step — resolving each
// recipient's send preferences (public keys, encryption scheme) and building
// the per-recipient MessagePackages for SendDraft — is the live-server edge
// that cannot be exercised without a real account; it is wired by the send
// feature (ErrSendNotWired). Defining this surface and the deterministic
// composition is the wrapper's job (#82).
func (c *gpaClient) Send(ctx context.Context, msg OutgoingMessage) (SentMessage, error) {
	if c.addrKRs == nil {
		return SentMessage{}, ErrNotUnlocked
	}
	if err := validateOutgoing(msg); err != nil {
		return SentMessage{}, err
	}
	addrKR := c.addrKRs[msg.FromAddressID]
	if addrKR == nil {
		return SentMessage{}, fmt.Errorf("%w: %q", ErrAddressNotUnlocked, msg.FromAddressID)
	}
	sender, ok := c.addressByID(msg.FromAddressID)
	if !ok {
		return SentMessage{}, fmt.Errorf("%w: %q", ErrAddressNotUnlocked, msg.FromAddressID)
	}
	tmpl := buildDraftTemplate(msg, sender)
	draft, err := c.cli.CreateDraft(ctx, addrKR, gpa.CreateDraftReq{Message: tmpl})
	if err != nil {
		return SentMessage{}, classifyError(err)
	}
	// The draft exists in Proton; transmission packaging is the send feature's
	// edge. Surface the draft id so that work can pick it up, but do not report
	// a completed send.
	return SentMessage{MessageID: draft.ID}, fmt.Errorf("%w (draft %s created)", ErrSendNotWired, draft.ID)
}

// Close releases the session transport.
func (c *gpaClient) Close() {
	if c.cli != nil {
		c.cli.Close()
	}
}

// addressByID resolves an unlocked address id to its reduit Address.
func (c *gpaClient) addressByID(id string) (Address, bool) {
	for _, a := range c.addresses {
		if a.ID == id {
			return Address{Name: a.DisplayName, Email: a.Email}, true
		}
	}
	return Address{}, false
}

// toDecryptedMessage maps a decrypted go-proton-api message onto reduit's type.
func toDecryptedMessage(msg gpa.Message, body []byte) DecryptedMessage {
	out := DecryptedMessage{
		MessageID: msg.ID,
		AddressID: msg.AddressID,
		Subject:   msg.Subject,
		Date:      time.Unix(msg.Time, 0).UTC(),
		MIMEType:  string(msg.MIMEType),
		Body:      body,
		Unread:    bool(msg.Unread),
		LabelIDs:  msg.LabelIDs,
	}
	if msg.Sender != nil {
		out.Sender = Address{Name: msg.Sender.Name, Email: msg.Sender.Address}
	}
	out.To = fromMailAddresses(msg.ToList)
	out.CC = fromMailAddresses(msg.CCList)
	out.BCC = fromMailAddresses(msg.BCCList)
	if len(msg.Attachments) > 0 {
		out.Attachments = make([]AttachmentMeta, 0, len(msg.Attachments))
		for _, a := range msg.Attachments {
			out.Attachments = append(out.Attachments, AttachmentMeta{
				ID:       a.ID,
				Name:     a.Name,
				MIMEType: string(a.MIMEType),
				Size:     a.Size,
			})
		}
	}
	return out
}
