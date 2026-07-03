package proton

import (
	"context"
	"sync"
	"time"
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
	// Access is the current access token reported by AccessToken; rotated values
	// can be scripted via AccessTokens (applied on Refresh, mirroring Token).
	Access string
	// UID is the current session UID reported by SessionUID; rotated values can
	// be scripted via SessionUIDs (applied on Refresh, mirroring Token).
	UID string
	// TwoFA is the 2FA state Login reports.
	TwoFA TwoFAState

	// HVChallenge, when non-nil, makes Login fail with it — modeling Proton's 9001
	// anti-abuse wall — so tests can drive the human-verification path. reduit does
	// not solve the challenge in-app (ADR-0021); it surfaces a clear app-version
	// error, so the challenge is terminal for the login rather than retried.
	HVChallenge *HVRequiredError
	// TOTPCode, when non-empty, is the only code SubmitTOTP accepts; any other
	// code yields ErrAuthFailed. Empty accepts any code.
	TOTPCode string
	// Passphrase, when non-empty, is the only passphrase Unlock accepts; any
	// other yields ErrUnlockFailed. Empty accepts any passphrase.
	Passphrase string

	// SaltedKeyPassValue is the salted key passphrase a successful Unlock derives
	// and SaltedKeyPass reports — the value the auth layer persists to the
	// keychain. UnlockWithKeyPass succeeds iff its argument matches this value
	// (when it is non-empty), so tests can drive a stale-keypass → ErrUnlockFailed
	// fallback. Empty accepts any key pass.
	SaltedKeyPassValue []byte
	// UnlockWithKeyPassErr, when set, is returned by UnlockWithKeyPass instead of
	// the match check — used to model a scope-independent unlock failure.
	UnlockWithKeyPassErr error

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
	// BackfillIDs is the scripted id list returned by BackfillMessageIDs, in the
	// oldest-first order the real client guarantees; the engine's backfill can be
	// driven offline from it. BackfillErr, when set, is returned instead.
	BackfillIDs []string
	BackfillErr error
	// Messages maps message id -> decrypted message for DecryptMessage.
	Messages map[string]DecryptedMessage
	// Attachments maps "messageID/attachmentID" -> bytes for DecryptAttachment.
	Attachments map[string][]byte
	// RefreshTokens are handed out (FIFO) on successive Refresh calls to
	// simulate rotation; when drained, Token is left unchanged.
	RefreshTokens []string
	// AccessTokens are handed out (FIFO) on successive Refresh calls to simulate
	// access-token rotation; when drained, Access is left unchanged.
	AccessTokens []string
	// SessionUIDs are handed out (FIFO) on successive Refresh calls to simulate
	// UID rotation; when drained, UID is left unchanged.
	SessionUIDs []string
	// SentID is the message id returned by a successful Send.
	SentID string

	// --- Recorded calls (inspected by the test after use) ---

	Sent          []OutgoingMessage
	TOTPSubmitted []string
	RefreshCalls  int
	Closed        bool

	// UnlockCalls / UnlockWithKeyPassCalls count the two unlock entry points so a
	// test can assert a resume used the persisted key pass (UnlockWithKeyPass) and
	// did NOT take the salts-fetching Unlock path — the Fake's stand-in for
	// "GetSalts was not called" (only Unlock reaches GetSalts on the real client).
	UnlockCalls            int
	UnlockWithKeyPassCalls int

	// internal lifecycle state
	authed        bool
	unlocked      bool
	pending       bool // 2FA outstanding
	batchIdx      int
	saltedKeyPass []byte // set on a successful Unlock/UnlockWithKeyPass
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
	if f.HVChallenge != nil {
		return AuthStatus{}, f.HVChallenge
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
	f.UnlockCalls++
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
	f.saltedKeyPass = f.SaltedKeyPassValue
	return nil
}

// UnlockWithKeyPass models the resume-time unlock that skips the salts endpoint:
// it never consults f.Passphrase (the salts path is not taken) and succeeds iff
// the supplied key pass matches the scripted SaltedKeyPassValue.
func (f *Fake) UnlockWithKeyPass(_ context.Context, keyPass []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.UnlockWithKeyPassCalls++
	if !f.authed {
		return ErrNotAuthenticated
	}
	if f.pending {
		return ErrAuthFailed
	}
	if f.UnlockWithKeyPassErr != nil {
		return f.UnlockWithKeyPassErr
	}
	if len(f.SaltedKeyPassValue) != 0 && string(keyPass) != string(f.SaltedKeyPassValue) {
		return ErrUnlockFailed
	}
	f.unlocked = true
	f.saltedKeyPass = keyPass
	return nil
}

// SaltedKeyPass reports the key pass a successful unlock retained, mirroring the
// real client so the auth layer can persist it.
func (f *Fake) SaltedKeyPass() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.saltedKeyPass
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

func (f *Fake) AccessToken() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Access
}

func (f *Fake) SessionUID() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.UID
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
	if len(f.AccessTokens) > 0 {
		f.Access = f.AccessTokens[0]
		f.AccessTokens = f.AccessTokens[1:]
	}
	if len(f.SessionUIDs) > 0 {
		f.UID = f.SessionUIDs[0]
		f.SessionUIDs = f.SessionUIDs[1:]
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

func (f *Fake) BackfillMessageIDs(_ context.Context, _ time.Time) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.authed {
		return nil, ErrNotAuthenticated
	}
	if f.BackfillErr != nil {
		return nil, f.BackfillErr
	}
	return f.BackfillIDs, nil
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
