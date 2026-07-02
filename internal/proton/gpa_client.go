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

// Resume reconstructs an authenticated client from a stored refresh token
// (SPEC-0007 "Secrets read non-interactively at use time"). go-proton-api may
// rotate the token; the caller reads RefreshToken afterward and persists it
// (ADR-0013). The returned client is authenticated but not unlocked; the caller
// supplies the passphrase to Unlock. The expected proton user id is verified to
// catch a token that resolves a different account (SPEC-0007 "Re-Auth Flow").
func (d *GPADialer) Resume(ctx context.Context, protonUserID, refreshToken string) (Client, error) {
	c := &gpaClient{mgr: d.mgr, userID: protonUserID, refreshToken: refreshToken}
	// A resume needs a session UID; NewClientWithRefresh derives a fresh one
	// from the refresh token. We have no stored UID here, so pass "" — the
	// upstream auth-refresh path re-establishes the session from the token.
	if err := c.refreshWithUID(ctx, ""); err != nil {
		return nil, err
	}
	if protonUserID != "" && c.userID != protonUserID {
		// Token resolved a different account than expected.
		return nil, fmt.Errorf("%w: token resolved proton user %q, expected %q",
			ErrRefreshTokenInvalid, c.userID, protonUserID)
	}
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
	refreshToken string // rotated on Login and Refresh

	// Unlock state. Populated by Unlock, used by decrypt/send.
	addrKRs   map[string]*crypto.KeyRing // address id -> unlocked keyring
	addresses []gpa.Address              // address metadata (id -> email)
}

var _ Client = (*gpaClient)(nil)

// Login runs the SRP password exchange via go-proton-api (SPEC-0007 REQ "SRP
// and 2FA Handling"). reduit never implements SRP itself. When Proton demands
// human verification (code 9001), Login returns a typed *HVRequiredError so the
// CLI can solve the CAPTCHA and retry via LoginWithHV, rather than dying with a
// generic "login failed" (SPEC-0007 scenario "Human verification / CAPTCHA is
// requested").
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

// LoginWithHV retries the SRP password exchange after Login reported human
// verification, passing back the SAME challenge (SPEC-0007, ADR-0001). Mirroring
// Proton Bridge, the operator has already completed Proton's hosted verify page
// (which verifies the token server-side); we simply hand the same {Methods,
// Token} to go-proton-api. It mirrors Login's post-processing; if Proton STILL
// demands verification (the operator did not complete it) it returns an
// *HVRequiredError again so the caller can offer another attempt.
func (c *gpaClient) LoginWithHV(ctx context.Context, address string, password []byte, hv *HVRequiredError) (AuthStatus, error) {
	cli, auth, err := c.mgr.NewClientWithLoginWithHVToken(ctx, address, password,
		&gpa.APIHVDetails{Methods: hv.Methods, Token: hv.Token})
	if err != nil {
		if hv, ok := hvRequiredFrom(err); ok {
			return AuthStatus{}, hv
		}
		return AuthStatus{}, classifyError(err)
	}
	return c.applyAuth(cli, auth), nil
}

// applyAuth records the authenticated session from a successful login and
// derives the reduit AuthStatus. It is the shared post-login processing for
// Login and LoginWithHV: store the client, session UID, immutable
// proton_user_id, and rotated refresh token, and compute the 2FA state. The
// mailbox keyring is loaded later by Unlock, not here.
func (c *gpaClient) applyAuth(cli *gpa.Client, auth gpa.Auth) AuthStatus {
	c.cli = cli
	c.uid = auth.UID
	c.userID = auth.UserID
	c.refreshToken = auth.RefreshToken
	return AuthStatus{ProtonUserID: auth.UserID, TwoFA: classify2FA(auth.TwoFA)}
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

// Refresh rotates the session from the stored refresh token.
func (c *gpaClient) Refresh(ctx context.Context) error {
	return c.refreshWithUID(ctx, c.uid)
}

// refreshWithUID performs the refresh-token rotation. uid may be "" on a cold
// resume, where go-proton-api re-derives the session from the refresh token.
func (c *gpaClient) refreshWithUID(ctx context.Context, uid string) error {
	if c.refreshToken == "" {
		return ErrNotAuthenticated
	}
	cli, auth, err := c.mgr.NewClientWithRefresh(ctx, uid, c.refreshToken)
	if err != nil {
		return classifyError(err)
	}
	if c.cli != nil {
		c.cli.Close()
	}
	c.cli = cli
	c.uid = auth.UID
	c.userID = auth.UserID
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
