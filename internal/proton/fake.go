package proton

import (
	"context"
	"sync"
)

// Fake is an in-memory Client for testing the auth, sync, and send layers
// without a live Proton account. It records calls and returns
// programmable/scripted results, and it enforces the same lifecycle invariants
// as the real client (auth before data methods, unlock before decrypt/send) so
// downstream tests exercise realistic ordering.
//
// It is safe for concurrent use; the sync layer's per-mailbox workers
// (ADR-0014) may drive separate Fakes in parallel.
type Fake struct {
	mu sync.Mutex

	// --- Programmable behavior (set by the test before use) ---

	// UserID is the proton_user_id reported after Login/Resume.
	UserID string
	// Token is the current refresh token; rotated values can be scripted via
	// RefreshTokens.
	Token string
	// TwoFA is the 2FA state Login (or LoginWithHV, once HV is passed) reports.
	TwoFA TwoFAState

	// HVChallenge, when non-nil, makes the FIRST Login fail with it — modeling
	// Proton's 9001 anti-abuse wall — so tests can drive the CAPTCHA solve →
	// LoginWithHV → 2FA → unlock sequence. Later Logins (and a LoginWithHV with
	// an accepted token) succeed. A LoginWithHV whose token is rejected (see
	// HVToken) fails with this same challenge again, modeling an expired/failed
	// token.
	HVChallenge *HVRequiredError
	// CaptchaHTML is returned by Captcha; CaptchaErr, when set, is returned
	// instead.
	CaptchaHTML []byte
	CaptchaErr  error
	// HVToken, when non-empty, is the only solved token LoginWithHV accepts; any
	// other value re-issues HVChallenge (or ErrHumanVerification if none is set).
	// Empty accepts any token.
	HVToken string
	// TOTPCode, when non-empty, is the only code SubmitTOTP accepts; any other
	// code yields ErrAuthFailed. Empty accepts any code.
	TOTPCode string
	// Passphrase, when non-empty, is the only passphrase Unlock accepts; any
	// other yields ErrUnlockFailed. Empty accepts any passphrase.
	Passphrase string

	// AppVer / HostURL back AppVersion() / Host(). Empty reports the same
	// defaults the real client uses (FallbackAppVersion / mail.proton.me API),
	// so a test that doesn't care about the CAPTCHA solver need not set them.
	AppVer  string
	HostURL string

	// LoginErr/UnlockErr/RefreshErr/SendErr, when set, are returned by the
	// corresponding method instead of succeeding.
	LoginErr   error
	UnlockErr  error
	RefreshErr error
	SendErr    error

	// LabelList is returned by a successful Labels call; LabelsErr, when set,
	// is returned instead.
	LabelList []Label
	LabelsErr error

	// LatestEvent is returned by LatestEventID.
	LatestEvent string
	// Batches are returned by successive GetEvents calls (FIFO); when drained,
	// GetEvents returns an empty batch whose cursor echoes the request.
	Batches []EventBatch
	// Messages maps message id -> decrypted message for DecryptMessage.
	Messages map[string]DecryptedMessage
	// Attachments maps "messageID/attachmentID" -> bytes for DecryptAttachment.
	Attachments map[string][]byte
	// RefreshTokens are handed out (FIFO) on successive Refresh calls to
	// simulate rotation; when drained, Token is left unchanged.
	RefreshTokens []string
	// SentID is the message id returned by a successful Send.
	SentID string

	// --- Recorded calls (inspected by the test after use) ---

	Sent          []OutgoingMessage
	TOTPSubmitted []string
	CaptchaTokens []string // tokens passed to Captcha
	HVTokens      []string // solved tokens passed to LoginWithHV
	RefreshCalls  int
	Closed        bool

	// internal lifecycle state
	authed   bool
	unlocked bool
	pending  bool // 2FA outstanding
	hvIssued bool // first HVChallenge has been handed out
	batchIdx int
}

var _ Client = (*Fake)(nil)

// NewFake returns a Fake with initialized maps.
func NewFake() *Fake {
	return &Fake{
		Messages:    map[string]DecryptedMessage{},
		Attachments: map[string][]byte{},
	}
}

func (f *Fake) Login(_ context.Context, _ string, _ []byte) (AuthStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.LoginErr != nil {
		return AuthStatus{}, f.LoginErr
	}
	if f.HVChallenge != nil && !f.hvIssued {
		f.hvIssued = true
		return AuthStatus{}, f.HVChallenge
	}
	f.authed = true
	f.pending = f.TwoFA == TwoFATOTP
	return AuthStatus{ProtonUserID: f.UserID, TwoFA: f.TwoFA}, nil
}

func (f *Fake) Captcha(_ context.Context, token string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.CaptchaTokens = append(f.CaptchaTokens, token)
	if f.CaptchaErr != nil {
		return nil, f.CaptchaErr
	}
	return f.CaptchaHTML, nil
}

func (f *Fake) LoginWithHV(_ context.Context, _ string, _ []byte, hvToken string) (AuthStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.HVTokens = append(f.HVTokens, hvToken)
	if f.HVToken != "" && hvToken != f.HVToken {
		// Token rejected/expired: Proton re-issues the challenge.
		if f.HVChallenge != nil {
			return AuthStatus{}, f.HVChallenge
		}
		return AuthStatus{}, ErrHumanVerification
	}
	f.authed = true
	f.pending = f.TwoFA == TwoFATOTP
	return AuthStatus{ProtonUserID: f.UserID, TwoFA: f.TwoFA}, nil
}

func (f *Fake) SubmitTOTP(_ context.Context, code string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.TOTPSubmitted = append(f.TOTPSubmitted, code)
	if !f.authed {
		return ErrNotAuthenticated
	}
	if !f.pending {
		return ErrNo2FAPending
	}
	if f.TOTPCode != "" && code != f.TOTPCode {
		return ErrAuthFailed
	}
	f.pending = false
	return nil
}

func (f *Fake) Unlock(_ context.Context, passphrase []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.authed {
		return ErrNotAuthenticated
	}
	if f.pending {
		return ErrAuthFailed
	}
	if f.UnlockErr != nil {
		return f.UnlockErr
	}
	if f.Passphrase != "" && string(passphrase) != f.Passphrase {
		return ErrUnlockFailed
	}
	f.unlocked = true
	return nil
}

func (f *Fake) ProtonUserID() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.UserID
}

func (f *Fake) RefreshToken() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Token
}

func (f *Fake) AppVersion() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.AppVer != "" {
		return f.AppVer
	}
	return FallbackAppVersion
}

func (f *Fake) Host() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.HostURL != "" {
		return f.HostURL
	}
	return "https://mail.proton.me/api"
}

func (f *Fake) Refresh(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.RefreshCalls++
	if f.RefreshErr != nil {
		return f.RefreshErr
	}
	f.authed = true
	if len(f.RefreshTokens) > 0 {
		f.Token = f.RefreshTokens[0]
		f.RefreshTokens = f.RefreshTokens[1:]
	}
	return nil
}

func (f *Fake) Labels(_ context.Context) ([]Label, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.authed {
		return nil, ErrNotAuthenticated
	}
	if f.LabelsErr != nil {
		return nil, f.LabelsErr
	}
	return f.LabelList, nil
}

func (f *Fake) LatestEventID(_ context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.authed {
		return "", ErrNotAuthenticated
	}
	return f.LatestEvent, nil
}

func (f *Fake) GetEvents(_ context.Context, sinceEventID string) (EventBatch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.authed {
		return EventBatch{}, ErrNotAuthenticated
	}
	if f.batchIdx >= len(f.Batches) {
		return EventBatch{NextCursor: sinceEventID}, nil
	}
	b := f.Batches[f.batchIdx]
	f.batchIdx++
	return b, nil
}

func (f *Fake) DecryptMessage(_ context.Context, messageID string) (DecryptedMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.unlocked {
		return DecryptedMessage{}, ErrNotUnlocked
	}
	m, ok := f.Messages[messageID]
	if !ok {
		return DecryptedMessage{}, ErrMessageNotFound
	}
	return m, nil
}

func (f *Fake) DecryptAttachment(_ context.Context, messageID, attachmentID string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.unlocked {
		return nil, ErrNotUnlocked
	}
	b, ok := f.Attachments[messageID+"/"+attachmentID]
	if !ok {
		return nil, ErrMessageNotFound
	}
	return b, nil
}

func (f *Fake) Send(_ context.Context, msg OutgoingMessage) (SentMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.unlocked {
		return SentMessage{}, ErrNotUnlocked
	}
	if err := validateOutgoing(msg); err != nil {
		return SentMessage{}, err
	}
	if f.SendErr != nil {
		return SentMessage{}, f.SendErr
	}
	f.Sent = append(f.Sent, msg)
	return SentMessage{MessageID: f.SentID}, nil
}

func (f *Fake) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Closed = true
}
