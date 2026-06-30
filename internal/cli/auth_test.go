package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/joestump/reduit/internal/keychain"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/store"
)

// --- test doubles -----------------------------------------------------------

// fakeDialer adapts a *proton.Fake to the proton.Dialer (+ Close) seam so the
// CLI auth/labels flow runs without a live account. NewClient hands out the
// pre-scripted Fake; Resume marks it authenticated like the real cold-resume.
type fakeDialer struct {
	client    *proton.Fake
	resumeErr error
	resumed   bool
}

func (d *fakeDialer) NewClient() proton.Client { return d.client }

func (d *fakeDialer) Resume(ctx context.Context, protonUserID, token string) (proton.Client, error) {
	_, _ = protonUserID, token
	if d.resumeErr != nil {
		return nil, d.resumeErr
	}
	d.resumed = true
	_ = d.client.Refresh(ctx) // a real resume authenticates the returned client
	return d.client, nil
}

func (d *fakeDialer) Close() {}

// scriptPrompter returns canned answers in order, so the mid-flow password /
// TOTP / passphrase prompts are satisfied without a TTY.
type scriptPrompter struct {
	secrets []string
	lines   []string
	err     error
}

func (p *scriptPrompter) secret(string) ([]byte, error) {
	if p.err != nil {
		return nil, p.err
	}
	s := p.secrets[0]
	p.secrets = p.secrets[1:]
	return []byte(s), nil
}

func (p *scriptPrompter) line(string) (string, error) {
	if p.err != nil {
		return "", p.err
	}
	s := p.lines[0]
	p.lines = p.lines[1:]
	return s, nil
}

// --- helpers ----------------------------------------------------------------

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(""); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return st
}

// newTestKeychain installs the in-memory keyring mock and returns a Store over
// it. The mock is a process global, so these tests do not run in parallel.
func newTestKeychain(t *testing.T) keychain.Store {
	t.Helper()
	keyring.MockInit()
	return keychain.New()
}

// --- auth add ---------------------------------------------------------------

func TestAuthAdd_HappyPath(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)
	fake := proton.NewFake()
	fake.UserID = "proton-user-1"
	fake.Token = "refresh-token-1"
	dialer := &fakeDialer{client: fake}
	p := &scriptPrompter{secrets: []string{"hunter2", "mailbox-pass"}}

	var out bytes.Buffer
	if err := authAdd(ctx, st, ks, dialer, p, "joe@proton.test", &out); err != nil {
		t.Fatalf("authAdd: %v", err)
	}

	m, err := st.GetMailboxByAddress(ctx, "joe@proton.test")
	if err != nil {
		t.Fatalf("mailbox not created: %v", err)
	}
	if m.State != store.MailboxStateActive {
		t.Errorf("state = %q, want active", m.State)
	}
	if m.ProtonUserID == nil || *m.ProtonUserID != "proton-user-1" {
		t.Errorf("proton_user_id = %v, want proton-user-1", m.ProtonUserID)
	}
	if got, _ := ks.Get(m.ID, keychain.RefreshToken); got != "refresh-token-1" {
		t.Errorf("stored refresh token = %q", got)
	}
	if got, _ := ks.Get(m.ID, keychain.MailboxPassphrase); got != "mailbox-pass" {
		t.Errorf("stored passphrase = %q", got)
	}
	// No-leak: the success line names the address but must not contain ANY
	// secret value — not the password, refresh token, or passphrase.
	if !strings.Contains(out.String(), "joe@proton.test") {
		t.Errorf("success line missing address: %q", out.String())
	}
	for _, secret := range []string{"hunter2", "refresh-token-1", "mailbox-pass"} {
		if strings.Contains(out.String(), secret) {
			t.Errorf("secret %q leaked to output: %q", secret, out.String())
		}
	}
}

func TestAuthAdd_DuplicateRejected(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)
	if err := st.InsertMailbox(ctx, "existing-id", "joe@proton.test"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	dialer := &fakeDialer{client: proton.NewFake()}
	p := &scriptPrompter{secrets: []string{"hunter2", "mailbox-pass"}}

	err := authAdd(ctx, st, ks, dialer, p, "joe@proton.test", &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "already configured") {
		t.Fatalf("expected duplicate rejection, got %v", err)
	}
	// The password prompt must not have fired — the duplicate check precedes it.
	if len(p.secrets) != 2 {
		t.Errorf("prompts consumed before duplicate check: %v", p.secrets)
	}
}

func TestAuthAdd_TOTPBranch(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)
	fake := proton.NewFake()
	fake.UserID = "proton-user-2"
	fake.Token = "rt-2"
	fake.TwoFA = proton.TwoFATOTP
	fake.TOTPCode = "654321"
	dialer := &fakeDialer{client: fake}
	p := &scriptPrompter{secrets: []string{"pw", "pass"}, lines: []string{"654321"}}

	if err := authAdd(ctx, st, ks, dialer, p, "totp@proton.test", &bytes.Buffer{}); err != nil {
		t.Fatalf("authAdd TOTP: %v", err)
	}
	if len(fake.TOTPSubmitted) != 1 || fake.TOTPSubmitted[0] != "654321" {
		t.Errorf("TOTP not submitted: %v", fake.TOTPSubmitted)
	}
	m, err := st.GetMailboxByAddress(ctx, "totp@proton.test")
	if err != nil || m.State != store.MailboxStateActive {
		t.Errorf("mailbox not active after TOTP: %v %v", m.State, err)
	}
}

func TestAuthAdd_Unsupported2FA(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)
	fake := proton.NewFake()
	fake.TwoFA = proton.TwoFAUnsupported
	dialer := &fakeDialer{client: fake}
	p := &scriptPrompter{secrets: []string{"pw", "pass"}}

	err := authAdd(ctx, st, ks, dialer, p, "fido@proton.test", &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "TOTP") {
		t.Fatalf("expected unsupported-2FA error, got %v", err)
	}
	if _, err := st.GetMailboxByAddress(ctx, "fido@proton.test"); !errors.Is(err, store.ErrMailboxNotFound) {
		t.Error("no mailbox row should exist after a pre-insert failure")
	}
}

func TestAuthAdd_CleanupOnSecretFailure(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	fake := proton.NewFake()
	fake.UserID = "u3"
	fake.Token = "rt-3"
	dialer := &fakeDialer{client: fake}
	p := &scriptPrompter{secrets: []string{"pw", "pass"}}

	// Force the keychain write to fail AFTER login+unlock+row-insert succeed, so
	// the cleanup path (delete secrets + row) is exercised.
	keyring.MockInitWithError(errors.New("dbus: connection refused"))
	t.Cleanup(keyring.MockInit)
	ks := keychain.New()

	err := authAdd(ctx, st, ks, dialer, p, "boom@proton.test", &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "store secrets") {
		t.Fatalf("expected secret-store failure, got %v", err)
	}
	// Cleanup must have removed the half-written row.
	if _, err := st.GetMailboxByAddress(ctx, "boom@proton.test"); !errors.Is(err, store.ErrMailboxNotFound) {
		t.Errorf("half-written mailbox row not cleaned up: %v", err)
	}
}

// --- auth list / remove -----------------------------------------------------

func TestAuthRemove(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)
	fake := proton.NewFake()
	fake.UserID = "u4"
	fake.Token = "rt-4"
	dialer := &fakeDialer{client: fake}
	p := &scriptPrompter{secrets: []string{"pw", "pass"}}
	if err := authAdd(ctx, st, ks, dialer, p, "rm@proton.test", &bytes.Buffer{}); err != nil {
		t.Fatalf("seed add: %v", err)
	}
	m, _ := st.GetMailboxByAddress(ctx, "rm@proton.test")

	if err := authRemove(ctx, st, ks, "rm@proton.test", &bytes.Buffer{}); err != nil {
		t.Fatalf("authRemove: %v", err)
	}
	if _, err := st.GetMailboxByAddress(ctx, "rm@proton.test"); !errors.Is(err, store.ErrMailboxNotFound) {
		t.Error("mailbox row not removed")
	}
	if _, err := ks.Get(m.ID, keychain.RefreshToken); !errors.Is(err, keychain.ErrNotFound) {
		t.Error("refresh-token secret not removed")
	}
	if _, err := ks.Get(m.ID, keychain.MailboxPassphrase); !errors.Is(err, keychain.ErrNotFound) {
		t.Error("passphrase secret not removed")
	}

	// Removing an unknown address is a clear error, not a silent success.
	if err := authRemove(ctx, st, ks, "nope@proton.test", &bytes.Buffer{}); err == nil {
		t.Error("expected error removing unknown mailbox")
	}
}

func TestAuthList(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)
	fake := proton.NewFake()
	fake.UserID = "u5"
	fake.Token = "rt-5"
	dialer := &fakeDialer{client: fake}
	p := &scriptPrompter{secrets: []string{"pw", "pass"}}
	if err := authAdd(ctx, st, ks, dialer, p, "list@proton.test", &bytes.Buffer{}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var out bytes.Buffer
	if err := authList(ctx, st, &out); err != nil {
		t.Fatalf("authList: %v", err)
	}
	if !strings.Contains(out.String(), "list@proton.test") || !strings.Contains(out.String(), "active") {
		t.Errorf("list output unexpected: %q", out.String())
	}
}

// --- labels (connection test) ----------------------------------------------

func TestRunLabels_ViaFake(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)
	fake := proton.NewFake()
	fake.UserID = "u6"
	fake.Token = "rt-6"
	fake.LabelList = []proton.Label{
		{ID: "0", Name: "Inbox", Type: proton.LabelTypeSystem},
		{ID: "x1", Name: "Receipts", Type: proton.LabelTypeLabel, Color: "#c44800"},
	}
	dialer := &fakeDialer{client: fake}

	// Seed an active mailbox with a stored refresh token.
	p := &scriptPrompter{secrets: []string{"pw", "pass"}}
	if err := authAdd(ctx, st, ks, dialer, p, "labels@proton.test", &bytes.Buffer{}); err != nil {
		t.Fatalf("seed add: %v", err)
	}

	var out bytes.Buffer
	if err := runLabels(ctx, st, ks, dialer, "", &out); err != nil {
		t.Fatalf("runLabels: %v", err)
	}
	if !dialer.resumed {
		t.Error("expected Resume to be called")
	}
	for _, want := range []string{"Inbox", "system", "Receipts", "label"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("labels output missing %q: %q", want, out.String())
		}
	}
}

func TestRunLabels_MultipleMailboxesNeedsFlag(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)
	if err := st.InsertMailbox(ctx, "id-a", "a@proton.test"); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertMailbox(ctx, "id-b", "b@proton.test"); err != nil {
		t.Fatal(err)
	}
	dialer := &fakeDialer{client: proton.NewFake()}
	err := runLabels(ctx, st, ks, dialer, "", &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "--mailbox") {
		t.Fatalf("expected multi-mailbox guidance, got %v", err)
	}
}

// --- auth refresh -----------------------------------------------------------

func TestAuthRefresh(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)
	fake := proton.NewFake()
	fake.UserID = "u7"
	fake.Token = "rt-7"
	fake.RefreshTokens = []string{"rt-7-rotated"} // resume rotates the token
	dialer := &fakeDialer{client: fake}

	p := &scriptPrompter{secrets: []string{"pw", "pass"}}
	if err := authAdd(ctx, st, ks, dialer, p, "refresh@proton.test", &bytes.Buffer{}); err != nil {
		t.Fatalf("seed add: %v", err)
	}
	m, _ := st.GetMailboxByAddress(ctx, "refresh@proton.test")

	p2 := &scriptPrompter{} // resume path succeeds; no prompts consumed
	if err := authRefresh(ctx, st, ks, dialer, p2, "refresh@proton.test", &bytes.Buffer{}); err != nil {
		t.Fatalf("authRefresh: %v", err)
	}
	// The rotated token must have been persisted.
	if got, _ := ks.Get(m.ID, keychain.RefreshToken); got != "rt-7-rotated" {
		t.Errorf("rotated token not persisted: %q", got)
	}
}

// TestAuthRefresh_DeadTokenReLogin covers the spec-critical recovery path: a
// needs_reauth mailbox whose stored token is dead (Resume fails) is restored to
// active by a full interactive re-login that reuses the existing row, verifies
// the same proton_user_id, and rewrites both secrets.
func TestAuthRefresh_DeadTokenReLogin(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)
	fake := proton.NewFake()
	fake.UserID = "user-recover"
	fake.Token = "rt-original"
	dialer := &fakeDialer{client: fake}

	// Seed an active mailbox.
	if err := authAdd(ctx, st, ks, dialer, &scriptPrompter{secrets: []string{"pw", "pass"}}, "recover@proton.test", &bytes.Buffer{}); err != nil {
		t.Fatalf("seed add: %v", err)
	}
	m, _ := st.GetMailboxByAddress(ctx, "recover@proton.test")
	if err := st.SetMailboxState(ctx, m.ID, store.MailboxStateNeedsReauth); err != nil {
		t.Fatal(err)
	}

	// Now the token is dead: Resume fails, and the re-login mints a new token.
	dialer.resumeErr = errors.New("refresh token invalid")
	fake.Token = "rt-after-relogin"

	var out bytes.Buffer
	p := &scriptPrompter{secrets: []string{"new-pw", "new-pass"}}
	if err := authRefresh(ctx, st, ks, dialer, p, "recover@proton.test", &out); err != nil {
		t.Fatalf("authRefresh recovery: %v", err)
	}
	got, _ := st.GetMailboxByAddress(ctx, "recover@proton.test")
	if got.State != store.MailboxStateActive {
		t.Errorf("state = %q, want active after re-login", got.State)
	}
	if tok, _ := ks.Get(m.ID, keychain.RefreshToken); tok != "rt-after-relogin" {
		t.Errorf("refresh token not rewritten: %q", tok)
	}
	if pass, _ := ks.Get(m.ID, keychain.MailboxPassphrase); pass != "new-pass" {
		t.Errorf("passphrase not rewritten: %q", pass)
	}
	if !strings.Contains(out.String(), "Re-authenticated") {
		t.Errorf("unexpected output: %q", out.String())
	}
}

// TestAuthRefresh_ProtonUserIDMismatch rejects a re-login that resolves a
// DIFFERENT Proton account than the row was first authenticated against
// (proton_user_id immutability).
func TestAuthRefresh_ProtonUserIDMismatch(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)
	// Seed a mailbox bound to account "user-A" with a (now dead) token.
	if err := st.InsertMailbox(ctx, "mbox-id", "mismatch@proton.test"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetProtonUserID(ctx, "mbox-id", "user-A"); err != nil {
		t.Fatal(err)
	}
	if err := ks.Set("mbox-id", keychain.RefreshToken, "dead"); err != nil {
		t.Fatal(err)
	}

	fake := proton.NewFake()
	fake.UserID = "user-B" // re-login resolves a different account
	dialer := &fakeDialer{client: fake, resumeErr: errors.New("refresh token invalid")}
	p := &scriptPrompter{secrets: []string{"pw", "pass"}}

	err := authRefresh(ctx, st, ks, dialer, p, "mismatch@proton.test", &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "different Proton account") {
		t.Fatalf("expected proton_user_id mismatch rejection, got %v", err)
	}
}

// flakyKeychain is an in-memory keychain.Store whose Set can be made to fail,
// to exercise the rotated-token-write failure path.
type flakyKeychain struct {
	m      map[string]string
	setErr error
}

func newFlakyKeychain() *flakyKeychain { return &flakyKeychain{m: map[string]string{}} }

func (f *flakyKeychain) key(id string, k keychain.Kind) string { return id + "/" + string(k) }

func (f *flakyKeychain) Set(id string, k keychain.Kind, secret string) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.m[f.key(id, k)] = secret
	return nil
}

func (f *flakyKeychain) Get(id string, k keychain.Kind) (string, error) {
	v, ok := f.m[f.key(id, k)]
	if !ok {
		return "", keychain.ErrNotFound
	}
	return v, nil
}

func (f *flakyKeychain) Delete(id string, k keychain.Kind) error {
	delete(f.m, f.key(id, k))
	return nil
}

func (f *flakyKeychain) DeleteAll(string) error { return nil }

// TestPersistRotatedTokenOrFlag_FlagsOnWriteFailure verifies that a failed write
// of a rotated (one-time-use) token flags the mailbox needs_reauth so it does
// not linger as a silently-broken "active" row.
func TestPersistRotatedTokenOrFlag_FlagsOnWriteFailure(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.InsertMailbox(ctx, "id-1", "flag@proton.test"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetProtonUserID(ctx, "id-1", "u"); err != nil { // → active
		t.Fatal(err)
	}
	ks := newFlakyKeychain()
	ks.setErr = errors.New("keyring write failed")

	err := persistRotatedTokenOrFlag(ctx, st, ks, "id-1", "old-token", "new-token")
	if err == nil {
		t.Fatal("expected write error to propagate")
	}
	m, _ := st.GetMailbox(ctx, "id-1")
	if m.State != store.MailboxStateNeedsReauth {
		t.Errorf("state = %q, want needs_reauth after rotated-token write failure", m.State)
	}
}

// TestAuthAdd_DuplicateProtonUserID rejects adding the SAME Proton account under
// a second address with a clear message and no new row.
func TestAuthAdd_DuplicateProtonUserID(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)

	first := proton.NewFake()
	first.UserID = "same-account"
	first.Token = "rt-a"
	if err := authAdd(ctx, st, ks, &fakeDialer{client: first}, &scriptPrompter{secrets: []string{"pw", "pass"}}, "one@proton.test", &bytes.Buffer{}); err != nil {
		t.Fatalf("first add: %v", err)
	}

	second := proton.NewFake()
	second.UserID = "same-account" // same Proton account, different address
	second.Token = "rt-b"
	err := authAdd(ctx, st, ks, &fakeDialer{client: second}, &scriptPrompter{secrets: []string{"pw", "pass"}}, "two@proton.test", &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "already configured as one@proton.test") {
		t.Fatalf("expected same-account rejection, got %v", err)
	}
	if _, err := st.GetMailboxByAddress(ctx, "two@proton.test"); !errors.Is(err, store.ErrMailboxNotFound) {
		t.Error("no row should be inserted for the duplicate account")
	}
}
