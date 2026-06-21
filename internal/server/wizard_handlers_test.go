// Tests for the /accounts/setup wizard handlers.
//
// Covers SPEC-0005 REQ "Add-Proton-Account Wizard" scenarios:
//
//   - Step 1 renders on first visit; the wizard creates a pending
//     account row.
//   - Happy path with no 2FA: credentials -> unlock -> active.
//   - Happy path with TOTP: credentials -> 2FA -> unlock -> active.
//   - Three failed TOTP attempts abort the wizard.
//   - Wrong mailbox passphrase keeps the wizard alive on step 3
//     with an inline error.
//   - FIDO2-only account renders the "not yet supported" terminal
//     screen.
//   - Wizard idle (TTL elapsed) discards in-flight credentials from
//     the in-memory wizard store.
//
// The proton.Manager surface is stubbed via a server.ProtonLoginer
// implementation that returns a controllable proton.Client. We do
// NOT drive a real SRP exchange against an httptest fake -- the SRP
// code path lives in go-proton-api and is tested upstream; what this
// file exercises is the wizard handler's behavior.
//
// Governing: SPEC-0005 REQ "Add-Proton-Account Wizard".

package server_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/joestump/reduit/internal/account"
	authoidc "github.com/joestump/reduit/internal/auth/oidc"
	"github.com/joestump/reduit/internal/auth/session"
	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/pubsub"
	"github.com/joestump/reduit/internal/server"
	"github.com/joestump/reduit/internal/store"
	"github.com/joestump/reduit/internal/users"
)

// --- stubs --------------------------------------------------------

type stubProton struct {
	mu    sync.Mutex
	calls []stubLoginCall
	queue []stubLoginResult
}

type stubLoginCall struct {
	username string
	password string
}

type stubLoginResult struct {
	client *stubProtonClient
	auth   *proton.Auth
	err    error
}

func (s *stubProton) NewClientWithLogin(_ context.Context, username, password string) (proton.Client, *proton.Auth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, stubLoginCall{username: username, password: password})
	if len(s.queue) == 0 {
		return nil, nil, errors.New("stubProton: no scripted result")
	}
	r := s.queue[0]
	s.queue = s.queue[1:]
	if r.err != nil {
		return nil, r.auth, r.err
	}
	return r.client, r.auth, nil
}

func (s *stubProton) push(r stubLoginResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue = append(s.queue, r)
}

// stubProtonClient is a controllable proton.Client.
type stubProtonClient struct {
	mu sync.Mutex

	// AuthTOTP behavior: each call pulls from totpResults; nil = success.
	// Empty slice means "every call succeeds".
	totpResults []error

	getUserResult      proton.User
	getUserErr         error
	keySaltsResult     proton.Salts
	keySaltsErr        error
	getAddressesResult []proton.Address
	getAddressesErr    error
	unlockErr          error

	// latestRefresh is what LatestRefreshToken returns. Tests set it
	// to assert the wizard persists the freshest value (vs. the
	// initial token captured at login).
	latestRefresh string

	totpCalls   []string
	unlockCalls int
	logoutCalls int
}

// AuthInfo returns a zero-value AuthInfo. The wizard handlers do not
// call AuthInfo on the per-session client (Manager.NewClientWithLogin
// routes the SRP info exchange through gpa internally), so this stub
// is unreachable in production test paths. We keep the method (rather
// than dropping it) to satisfy the proton.Client interface and return
// a typed sentinel instead of panicking so any future call site that
// quietly starts touching AuthInfo gets a debuggable empty response
// rather than crashing the test binary.
//
// Governing: issue #81 (dead AuthInfo stub cleanup).
func (c *stubProtonClient) AuthInfo(context.Context, proton.AuthInfoReq) (proton.AuthInfo, error) {
	return proton.AuthInfo{}, nil
}

func (c *stubProtonClient) AuthTOTP(_ context.Context, code string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.totpCalls = append(c.totpCalls, code)
	if len(c.totpResults) == 0 {
		return nil
	}
	r := c.totpResults[0]
	c.totpResults = c.totpResults[1:]
	return r
}

func (c *stubProtonClient) AuthFIDO2(context.Context, proton.FIDO2Req) error {
	panic("stubProtonClient.AuthFIDO2: unexpected")
}

func (c *stubProtonClient) KeySalts(context.Context) (proton.Salts, error) {
	return c.keySaltsResult, c.keySaltsErr
}

func (c *stubProtonClient) GetUser(context.Context) (proton.User, error) {
	return c.getUserResult, c.getUserErr
}

func (c *stubProtonClient) GetAddresses(context.Context) ([]proton.Address, error) {
	return c.getAddressesResult, c.getAddressesErr
}

func (c *stubProtonClient) Unlock(proton.User, []proton.Address, []byte) (*proton.KeyRing, map[string]*proton.KeyRing, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.unlockCalls++
	if c.unlockErr != nil {
		return nil, nil, c.unlockErr
	}
	return nil, map[string]*proton.KeyRing{}, nil
}

func (c *stubProtonClient) GetEvent(context.Context, string) ([]proton.Event, bool, error) {
	panic("unexpected")
}
func (c *stubProtonClient) GetLatestEventID(context.Context) (string, error) {
	panic("unexpected")
}
func (c *stubProtonClient) GetMessage(context.Context, string) (proton.Message, error) {
	panic("unexpected")
}
func (c *stubProtonClient) GetMessageRFC822(context.Context, string) ([]byte, error) {
	panic("unexpected")
}
func (c *stubProtonClient) ListMessages(context.Context, proton.MessageFilter) ([]proton.MessageMetadata, error) {
	panic("unexpected")
}
func (c *stubProtonClient) ListMessagesPage(context.Context, int, int, proton.MessageFilter) ([]proton.MessageMetadata, error) {
	panic("unexpected")
}
func (c *stubProtonClient) GroupedMessageCount(context.Context) ([]proton.MessageGroupCount, error) {
	panic("unexpected")
}
func (c *stubProtonClient) GetLabels(context.Context, ...proton.LabelType) ([]proton.Label, error) {
	panic("unexpected")
}
func (c *stubProtonClient) SendDraft(context.Context, string, proton.SendDraftReq) (proton.Message, error) {
	panic("unexpected")
}
func (c *stubProtonClient) GetPublicKeys(context.Context, string) (proton.PublicKeys, proton.RecipientType, error) {
	panic("unexpected")
}
func (c *stubProtonClient) GetAttachment(context.Context, string) ([]byte, error) {
	panic("unexpected")
}
func (c *stubProtonClient) LabelMessages(context.Context, []string, string) error {
	panic("unexpected")
}
func (c *stubProtonClient) UnlabelMessages(context.Context, []string, string) error {
	panic("unexpected")
}
func (c *stubProtonClient) MarkMessagesRead(context.Context, ...string) error {
	panic("unexpected")
}
func (c *stubProtonClient) MarkMessagesUnread(context.Context, ...string) error {
	panic("unexpected")
}
func (c *stubProtonClient) Logout(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logoutCalls++
	return nil
}
func (c *stubProtonClient) LatestRefreshToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.latestRefresh
}

// --- fixture ------------------------------------------------------

type wizardFixture struct {
	url       string
	idp       *fakeIdP
	stub      *stubProton
	wizards   *server.WizardSessionStore
	accSvc    account.Service
	usrSvc    users.Service
	store     *store.Store
	statusBus *pubsub.Bus
}

// newWizardFixture spins up a real httptest server with the full
// production middleware chain and the wizard wiring (ProtonLoginer +
// WizardSessionStore). The fixture exposes the stub manager so each
// test can script Proton-side responses.
func newWizardFixture(t *testing.T, ttl time.Duration) *wizardFixture {
	t.Helper()
	return newWizardFixtureWithWriteTimeout(t, ttl, 0)
}

// newWizardFixtureWithWriteTimeout is newWizardFixture with an explicit
// http.Server WriteTimeout on the test server. A non-zero timeout
// reproduces the production admin listener's absolute write deadline so
// the SSE WriteTimeout regression test can prove the handler survives
// it. The default httptest.NewServer sets no WriteTimeout, which is
// exactly why the original bug slipped past the first round of tests.
func newWizardFixtureWithWriteTimeout(t *testing.T, ttl, writeTimeout time.Duration) *wizardFixture {
	t.Helper()
	st := openTempStore(t)
	master, err := cryptenv.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	accSvc := account.New(st, master)
	usrSvc := users.New(st)
	idp := newFakeIdP(t, "reduit-test-client")
	stub := &stubProton{}
	if ttl == 0 {
		ttl = time.Minute
	}
	wizardSessions := server.NewWizardSessionStore(ttl)
	t.Cleanup(wizardSessions.Stop)

	// Status bus + transition publisher, mirroring cli/serve.go so the
	// SSE handler has a live event source: every account.Transition
	// republishes as a pubsub.StateChanged update on the account's
	// status topic.
	statusBus := pubsub.New()
	t.Cleanup(statusBus.Close)
	unsub := accSvc.OnTransition(
		func(_ context.Context, prev, next account.State, a *account.Account) {
			statusBus.Publish(pubsub.StatusKey(a.ID), pubsub.Update{
				Kind: pubsub.StateChanged,
				From: string(prev),
				To:   string(next),
			})
		})
	t.Cleanup(unsub)

	mgr, cleanup, err := session.New(st.DB.DB, session.Options{Insecure: true})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	t.Cleanup(cleanup)

	mux := http.NewServeMux()
	// Use an unstarted server so we can set WriteTimeout on the
	// underlying http.Server BEFORE it begins accepting connections --
	// http.Server reads WriteTimeout when it sets up each accepted
	// connection, so it must be in place before Start().
	srv := httptest.NewUnstartedServer(mux)
	if writeTimeout > 0 {
		srv.Config.WriteTimeout = writeTimeout
	}
	srv.Start()
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	oidcClient, err := authoidc.New(ctx, authoidc.Config{
		IssuerURL:    idp.URL(),
		ClientID:     "reduit-test-client",
		ClientSecret: "test-secret",
		RedirectURL:  srv.URL + "/auth/callback",
		Scopes:       []string{"openid", "profile", "email"},
	})
	if err != nil {
		t.Fatalf("authoidc.New: %v", err)
	}
	preSessions := authoidc.NewPreSessionStore(0)

	deps := server.Deps{
		Store:           st,
		Logger:          slog.Default(),
		Version:         "test",
		SessionManager:  mgr,
		OIDC:            oidcClient,
		PreSessions:     preSessions,
		UsersService:    usrSvc,
		AccountService:  accSvc,
		ProtonManager:   stub,
		WizardSessions:  wizardSessions,
		AutoCreate:      true, // production default; admit fresh test subjects
		InsecureCookies: true,
		StatusBus:       statusBus,
	}
	_, handler := server.NewForTest(deps)
	mux.Handle("/", handler)

	return &wizardFixture{
		url:       srv.URL,
		idp:       idp,
		stub:      stub,
		wizards:   wizardSessions,
		accSvc:    accSvc,
		usrSvc:    usrSvc,
		store:     st,
		statusBus: statusBus,
	}
}

// makeUser creates a Reduit user via OIDC login through the fake IdP
// and returns a cookie-jarred client + the user's ID. Equivalent to
// loginAndFollow but also returns the canonical UserID for seeding.
func (f *wizardFixture) makeUser(t *testing.T, sub, email, name string) (*http.Client, string) {
	t.Helper()
	c := loginAndFollow(t, f.url, f.idp, sub, email, name)
	return c, f.usrIDFor(t, sub)
}

// usrIDFor resolves an OIDC subject to its Reduit user ID via the
// users service.
func (f *wizardFixture) usrIDFor(t *testing.T, sub string) string {
	t.Helper()
	u, err := f.usrSvc.GetByOIDCSubject(t.Context(), sub)
	if err != nil {
		t.Fatalf("GetByOIDCSubject(%s): %v", sub, err)
	}
	return u.ID
}

// post is a tiny POST helper for form-urlencoded bodies.
func post(t *testing.T, c *http.Client, target string, values url.Values) *http.Response {
	t.Helper()
	body := strings.NewReader(values.Encode())
	req, err := http.NewRequest(http.MethodPost, target, body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	return resp
}

// readBody drains and closes the response body, returning the contents.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// --- tests --------------------------------------------------------

// stubProtonUserWithKeys returns a proton.User with one primary key
// whose ID is "key-1". Unlock is stubbed to ignore the salt math; we
// just need GetUser/Unlock to succeed in the happy paths.
func stubProtonUserWithKeys() proton.User {
	return proton.User{Keys: gpa.Keys{{ID: "key-1", Primary: gpa.Bool(true)}}}
}

// stubKeySalts returns a Salts slice with a base64'd 16-byte salt
// for "key-1". The exact bytes don't matter for tests because we
// mock Unlock; we just need SaltForKey to return without error.
func stubKeySalts() proton.Salts {
	return proton.Salts{{ID: "key-1", KeySalt: "AAAAAAAAAAAAAAAAAAAAAA=="}}
}

// readyClient returns a stubProtonClient pre-wired with a primary
// key + matching salt so commitWizard's read-side calls succeed.
// Tests that need to inject Unlock failures or 2FA-rejection scripts
// mutate the returned struct.
func readyClient() *stubProtonClient {
	return &stubProtonClient{
		getUserResult:  stubProtonUserWithKeys(),
		keySaltsResult: stubKeySalts(),
	}
}

// stubAuth returns a proton.Auth carrying the supplied 2FA shape and
// the canonical "joe" identity tokens used across tests.
func stubAuth(twoFA proton.TwoFAStatus) *proton.Auth {
	return &proton.Auth{
		UserID:       "proton-user-joe",
		UID:          "proton-uid",
		AccessToken:  "proton-access",
		RefreshToken: "proton-refresh",
		TwoFA:        proton.TwoFAInfo{Enabled: twoFA},
	}
}

func TestWizard_Step1_RendersAndCreatesPendingAccount(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-1", "joe@example.com", "Joe")

	resp, err := c.Get(f.url + "/accounts/setup")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "Sign in to your Proton account") {
		t.Errorf("step 1 copy missing; body excerpt=%s", body[:min(len(body), 600)])
	}

	// A pending account row was created for this user.
	accts, err := f.accSvc.ListByUser(t.Context(), userID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(accts) != 1 {
		t.Fatalf("expected 1 pending account, got %d", len(accts))
	}
	if accts[0].State != account.StatePendingProtonSetup {
		t.Errorf("state = %s, want pending_proton_setup", accts[0].State)
	}
}

func TestWizard_HappyPath_NoTwoFA(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-noTOTP", "joe@example.com", "Joe")

	stubClient := readyClient()
	f.stub.push(stubLoginResult{client: stubClient, auth: stubAuth(0)})

	// Step 1: GET creates the pending row.
	resp, _ := c.Get(f.url + "/accounts/setup")
	resp.Body.Close()

	// Step 1 submit: credentials -> jump to step 3 (no 2FA).
	resp = post(t, c, f.url+"/accounts/setup/auth", url.Values{
		"username": {"joe@protonmail.com"},
		"password": {"hunter2"},
	})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("auth status = %d, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "Unlock your Proton mailbox") {
		t.Errorf("expected unlock screen; got body excerpt=%s", body[:min(len(body), 500)])
	}

	// Step 3 submit: passphrase -> success -> Done page (issue #104).
	// The wizard now renders the IMAP password before redirecting; a
	// follow-up POST /accounts/setup/complete drops the session and
	// redirects to /accounts.
	resp = post(t, c, f.url+"/accounts/setup/unlock", url.Values{
		"passphrase": {"my-mailbox-passphrase"},
	})
	body = readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unlock status = %d, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "Set up your mail client") {
		t.Errorf("expected Done page; body excerpt=%s", body[:min(len(body), 600)])
	}
	if !strings.Contains(body, "data-imap-password") {
		t.Errorf("expected IMAP password block on Done page; body excerpt=%s", body[:min(len(body), 600)])
	}

	accts, _ := f.accSvc.ListByUser(t.Context(), userID)
	if len(accts) != 1 {
		t.Fatalf("expected 1 account, got %d", len(accts))
	}
	a := accts[0]
	if a.State != account.StateActive {
		t.Errorf("state = %s, want active", a.State)
	}
	if a.ProtonUserID != "proton-user-joe" {
		t.Errorf("ProtonUserID = %q, want proton-user-joe", a.ProtonUserID)
	}
	if a.Email != "joe@protonmail.com" {
		t.Errorf("Email = %q, want joe@protonmail.com", a.Email)
	}
	if !a.HasRefreshToken {
		t.Error("refresh token not persisted")
	}
	if !a.HasMailboxPassphrase {
		t.Error("mailbox passphrase not persisted")
	}
	if stubClient.unlockCalls != 1 {
		t.Errorf("Unlock calls = %d, want 1", stubClient.unlockCalls)
	}

	// The persisted refresh token must round-trip to the captured-
	// at-login value (the stub didn't simulate a rotation).
	plaintext, err := f.accSvc.OpenRefreshToken(t.Context(), a.ID)
	if err != nil {
		t.Fatalf("OpenRefreshToken: %v", err)
	}
	if got := string(plaintext); got != "proton-refresh" {
		t.Errorf("persisted refresh token = %q, want proton-refresh", got)
	}

	// Wizard commit-success path doesn't fire upstream Logout (we
	// keep the session alive so the supervisor can adopt the tokens).
	// Issue #104: the wizard session is held open across the Done
	// step so the IMAP password stays renderable across a refresh;
	// it gets dropped when the user POSTs to /complete.
	if _, ok := f.wizards.Get(a.ID); !ok {
		t.Error("wizard session dropped before Done step; want still in store")
	}

	// IMAP password was generated and persisted; the alias is set.
	if !a.HasIMAPPassword {
		t.Error("IMAP password not persisted")
	}
	if a.PrimaryAlias == "" {
		t.Error("primary alias not assigned at commit time")
	}

	// Now complete the wizard. The session should be dropped and
	// the user redirected to the dashboard.
	resp = post(t, c, f.url+"/accounts/setup/complete", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("complete status = %d, want 303", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/accounts" {
		t.Errorf("redirect = %q, want /accounts", got)
	}
	if _, ok := f.wizards.Get(a.ID); ok {
		t.Error("wizard session still in store after complete; want dropped")
	}
}

// TestWizard_HappyPath_PersistsRotatedRefreshToken asserts the C2
// fix: if the upstream client's refresh token rotates between login
// and the unlock-time persist, the wizard persists the *rotated*
// value, not the captured-at-login one.
func TestWizard_HappyPath_PersistsRotatedRefreshToken(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, _ := f.makeUser(t, "sub-rotated", "joe@example.com", "Joe")

	stubClient := readyClient()
	// Simulate a rotation: between login and commit the upstream
	// auth handler fired and updated latestRefresh.
	stubClient.latestRefresh = "rotated-refresh"
	f.stub.push(stubLoginResult{client: stubClient, auth: stubAuth(0)})

	c.Get(f.url + "/accounts/setup")
	post(t, c, f.url+"/accounts/setup/auth", url.Values{
		"username": {"joe@protonmail.com"}, "password": {"hunter2"},
	}).Body.Close()
	post(t, c, f.url+"/accounts/setup/unlock", url.Values{
		"passphrase": {"my-mailbox-passphrase"},
	}).Body.Close()

	accts, _ := f.accSvc.ListByUser(t.Context(), f.usrIDFor(t, "sub-rotated"))
	if len(accts) != 1 {
		t.Fatalf("expected 1 account, got %d", len(accts))
	}
	plaintext, err := f.accSvc.OpenRefreshToken(t.Context(), accts[0].ID)
	if err != nil {
		t.Fatalf("OpenRefreshToken: %v", err)
	}
	if got := string(plaintext); got != "rotated-refresh" {
		t.Errorf("persisted refresh token = %q, want rotated-refresh (the upstream-rotated value)", got)
	}
}

func TestWizard_HappyPath_WithTOTP(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-totp", "joe@example.com", "Joe")

	stubClient := readyClient()
	f.stub.push(stubLoginResult{client: stubClient, auth: stubAuth(proton.HasTOTP)})

	c.Get(f.url + "/accounts/setup")
	resp := post(t, c, f.url+"/accounts/setup/auth", url.Values{
		"username": {"joe@protonmail.com"},
		"password": {"hunter2"},
	})
	body := readBody(t, resp)
	if !strings.Contains(body, "Enter your two-factor code") {
		t.Errorf("expected TOTP screen; body excerpt=%s", body[:min(len(body), 500)])
	}

	// TOTP submit (default stubProtonClient.totpResults is empty so
	// AuthTOTP succeeds).
	resp = post(t, c, f.url+"/accounts/setup/2fa", url.Values{"code": {"123456"}})
	body = readBody(t, resp)
	if !strings.Contains(body, "Unlock your Proton mailbox") {
		t.Errorf("expected unlock screen; body excerpt=%s", body[:min(len(body), 500)])
	}
	if got := stubClient.totpCalls; len(got) != 1 || got[0] != "123456" {
		t.Errorf("totpCalls = %v, want [123456]", got)
	}

	// Unlock submit -> Done page (issue #104).
	resp = post(t, c, f.url+"/accounts/setup/unlock", url.Values{
		"passphrase": {"my-mailbox-passphrase"},
	})
	body = readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unlock status = %d, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "Set up your mail client") {
		t.Errorf("expected Done page; body excerpt=%s", body[:min(len(body), 600)])
	}

	accts, _ := f.accSvc.ListByUser(t.Context(), userID)
	if len(accts) != 1 || accts[0].State != account.StateActive {
		t.Errorf("expected one active account, got %v", accts)
	}

	// Complete the wizard.
	resp = post(t, c, f.url+"/accounts/setup/complete", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("complete status = %d, want 303", resp.StatusCode)
	}
}

func TestWizard_TOTP_ThreeFailuresAbort(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-3fails", "joe@example.com", "Joe")

	totpErr := errors.New("invalid 2fa code")
	stubClient := readyClient()
	// 3 rejections = abort. The wizard never gets a 4th call.
	stubClient.totpResults = []error{totpErr, totpErr, totpErr}
	f.stub.push(stubLoginResult{client: stubClient, auth: stubAuth(proton.HasTOTP)})

	c.Get(f.url + "/accounts/setup")
	resp := post(t, c, f.url+"/accounts/setup/auth", url.Values{
		"username": {"joe@protonmail.com"}, "password": {"hunter2"},
	})
	resp.Body.Close()

	// First two failed attempts: status 200 with inline retry message.
	for i := 1; i <= 2; i++ {
		resp = post(t, c, f.url+"/accounts/setup/2fa", url.Values{"code": {"000000"}})
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("attempt %d: status = %d, body=%s", i, resp.StatusCode, body)
		}
		if !strings.Contains(body, "Code rejected") {
			t.Errorf("attempt %d: expected retry message, body excerpt=%s", i, body[:min(len(body), 500)])
		}
	}

	// Third failure aborts: terminal page rendered.
	resp = post(t, c, f.url+"/accounts/setup/2fa", url.Values{"code": {"000000"}})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("third attempt status = %d, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "Wizard reset") || !strings.Contains(body, "Three failed") {
		t.Errorf("expected aborted page; body excerpt=%s", body[:min(len(body), 500)])
	}

	// Pending account row was soft-deleted.
	accts, _ := f.accSvc.ListByUser(t.Context(), userID)
	for _, a := range accts {
		if a.State != account.StateSoftDeleted {
			t.Errorf("account %s state = %s, want soft_deleted", a.ID, a.State)
		}
	}
	if stubClient.logoutCalls == 0 {
		t.Error("expected Logout to be called on abort")
	}
}

func TestWizard_WrongPassphrase_StaysOnStep3(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, _ := f.makeUser(t, "sub-bad-pass", "joe@example.com", "Joe")

	stubClient := readyClient()
	stubClient.unlockErr = errors.New("failed to unlock any user keys")
	f.stub.push(stubLoginResult{client: stubClient, auth: stubAuth(0)})

	c.Get(f.url + "/accounts/setup")
	post(t, c, f.url+"/accounts/setup/auth", url.Values{
		"username": {"joe@protonmail.com"}, "password": {"hunter2"},
	}).Body.Close()

	resp := post(t, c, f.url+"/accounts/setup/unlock", url.Values{"passphrase": {"wrong"}})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "Unlock your Proton mailbox") {
		t.Errorf("expected to remain on unlock screen; body excerpt=%s", body[:min(len(body), 500)])
	}
	if !strings.Contains(body, "could not unlock your mailbox") {
		t.Errorf("expected inline error; body excerpt=%s", body[:min(len(body), 500)])
	}
}

func TestWizard_NoKeys_RendersTerminalError(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-nokeys", "joe@example.com", "Joe")

	// User with no keys -- a brand-new Proton account shape.
	stubClient := readyClient()
	stubClient.getUserResult = proton.User{} // empty Keys slice
	f.stub.push(stubLoginResult{client: stubClient, auth: stubAuth(0)})

	c.Get(f.url + "/accounts/setup")
	post(t, c, f.url+"/accounts/setup/auth", url.Values{
		"username": {"joe@protonmail.com"}, "password": {"hunter2"},
	}).Body.Close()
	resp := post(t, c, f.url+"/accounts/setup/unlock", url.Values{
		"passphrase": {"x"},
	})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "no encryption keys") {
		t.Errorf("expected no-keys terminal copy; body excerpt=%s", body[:min(len(body), 500)])
	}

	// Pending row was soft-deleted; client logged out.
	accts, _ := f.accSvc.ListByUser(t.Context(), userID)
	for _, a := range accts {
		if a.State != account.StateSoftDeleted {
			t.Errorf("account %s state = %s, want soft_deleted", a.ID, a.State)
		}
	}
	if stubClient.logoutCalls == 0 {
		t.Error("expected Logout to be called on no-keys abort")
	}
}

func TestWizard_FIDO2Only_RendersTerminalError(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-fido", "joe@example.com", "Joe")

	stubClient := readyClient()
	f.stub.push(stubLoginResult{client: stubClient, auth: stubAuth(proton.HasFIDO2)})

	c.Get(f.url + "/accounts/setup")
	resp := post(t, c, f.url+"/accounts/setup/auth", url.Values{
		"username": {"joe@protonmail.com"}, "password": {"hunter2"},
	})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "FIDO2") || !strings.Contains(body, "TOTP-based 2FA") {
		t.Errorf("expected FIDO2 terminal copy; body excerpt=%s", body[:min(len(body), 500)])
	}

	// Pending row was soft-deleted; client logged out.
	accts, _ := f.accSvc.ListByUser(t.Context(), userID)
	for _, a := range accts {
		if a.State != account.StateSoftDeleted {
			t.Errorf("account %s state = %s, want soft_deleted", a.ID, a.State)
		}
	}
	if stubClient.logoutCalls == 0 {
		t.Error("expected Logout to be called on FIDO2 abort")
	}
}

func TestWizard_BadCredentials_StaysOnStep1(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, _ := f.makeUser(t, "sub-bad-cred", "joe@example.com", "Joe")

	f.stub.push(stubLoginResult{err: errors.New("401: bad credentials")})

	c.Get(f.url + "/accounts/setup")
	resp := post(t, c, f.url+"/accounts/setup/auth", url.Values{
		"username": {"joe@protonmail.com"}, "password": {"wrong"},
	})
	body := readBody(t, resp)
	if !strings.Contains(body, "Sign in to your Proton account") {
		t.Errorf("expected to stay on step 1; body excerpt=%s", body[:min(len(body), 500)])
	}
	if !strings.Contains(body, "Proton rejected those credentials") {
		t.Errorf("expected inline error; body excerpt=%s", body[:min(len(body), 500)])
	}
}

func TestWizard_IdleTimeout_DiscardsCredentials(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 50*time.Millisecond)
	c, _ := f.makeUser(t, "sub-idle", "joe@example.com", "Joe")

	stubClient := readyClient()
	f.stub.push(stubLoginResult{client: stubClient, auth: stubAuth(proton.HasTOTP)})

	c.Get(f.url + "/accounts/setup")
	post(t, c, f.url+"/accounts/setup/auth", url.Values{
		"username": {"joe@protonmail.com"}, "password": {"hunter2"},
	}).Body.Close()

	// Wait long enough for the wizard janitor to expire our session.
	time.Sleep(150 * time.Millisecond)

	// Submitting TOTP after expiry must NOT validate against the
	// dropped client; the handler bounces to /accounts/setup which
	// mints a fresh session.
	resp := post(t, c, f.url+"/accounts/setup/2fa", url.Values{"code": {"123456"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect after expiry, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/accounts/setup" {
		t.Errorf("redirect = %q, want /accounts/setup", got)
	}
	if len(stubClient.totpCalls) != 0 {
		t.Errorf("expected 0 TOTP calls after expiry, got %v", stubClient.totpCalls)
	}
}

func TestWizard_DuplicateProtonAccount_AbortsWithTerminalError(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-dup", "joe@example.com", "Joe")

	// Pre-seed an active account already bound to "proton-user-joe"
	// for this user. The wizard's SetProtonIdentity step will then
	// trip the unique (user_id, proton_user_id) index.
	pre, err := f.accSvc.Create(t.Context(), account.CreateParams{
		UserID:       userID,
		ProtonUserID: "proton-user-joe",
		Email:        "first@protonmail.com",
	})
	if err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if _, err := f.accSvc.Transition(t.Context(), pre.ID, account.StateActive); err != nil {
		t.Fatalf("transition: %v", err)
	}

	stubClient := readyClient()
	f.stub.push(stubLoginResult{client: stubClient, auth: stubAuth(0)})

	c.Get(f.url + "/accounts/setup")
	post(t, c, f.url+"/accounts/setup/auth", url.Values{
		"username": {"joe@protonmail.com"}, "password": {"hunter2"},
	}).Body.Close()
	resp := post(t, c, f.url+"/accounts/setup/unlock", url.Values{
		"passphrase": {"my-mailbox-passphrase"},
	})
	body := readBody(t, resp)

	if !strings.Contains(body, "already linked") {
		t.Errorf("expected duplicate-account terminal copy; body excerpt=%s", body[:min(len(body), 600)])
	}

	// The pending row created at GET time must be soft-deleted; the
	// pre-seeded active row stays put.
	accts, _ := f.accSvc.ListByUser(t.Context(), userID)
	var active, soft int
	for _, a := range accts {
		switch a.State {
		case account.StateActive:
			active++
		case account.StateSoftDeleted:
			soft++
		}
	}
	if active != 1 {
		t.Errorf("expected 1 active account post-abort, got %d", active)
	}
	if soft != 1 {
		t.Errorf("expected 1 soft-deleted (the wizard's pending row), got %d", soft)
	}

	// And the cipher columns on the soft-deleted row must NOT have
	// been written -- C4 requires the dedup check to run before any
	// seal does.
	for _, a := range accts {
		if a.State == account.StateSoftDeleted {
			if a.HasRefreshToken || a.HasMailboxPassphrase {
				t.Errorf("aborted wizard's row has ciphertext (HasRefresh=%v HasPass=%v); want neither — seals must run AFTER the dedup check",
					a.HasRefreshToken, a.HasMailboxPassphrase)
			}
		}
	}
}

// TestWizard_ProtonIdentityMismatch_AbortsWithFriendlyError pins the
// spec-review gap: when commitWizard's SetProtonIdentity trips
// ErrProtonIdentityMismatch (the pending row was already stamped with a
// DIFFERENT Proton identity on a prior run), the wizard MUST surface a
// friendly terminal error and tear the in-flight state down -- NOT fall
// through the default arm and 500.
//
// Governing: SPEC-0001 REQ "Account Identity".
func TestWizard_ProtonIdentityMismatch_AbortsWithFriendlyError(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-mismatch", "joe@example.com", "Joe")

	stubClient := readyClient()
	f.stub.push(stubLoginResult{client: stubClient, auth: stubAuth(0)})

	// GET creates the pending row; auth captures the (stub) Proton
	// session whose UserID is "proton-user-joe".
	c.Get(f.url + "/accounts/setup")
	post(t, c, f.url+"/accounts/setup/auth", url.Values{
		"username": {"joe@protonmail.com"}, "password": {"hunter2"},
	}).Body.Close()

	// Simulate a prior run having already stamped a DIFFERENT Proton
	// identity onto this same pending row. The unlock step's
	// SetProtonIdentity("proton-user-joe") will then mismatch the stored
	// "proton-user-OTHER" and the guard must reject it.
	accts, err := f.accSvc.ListByUser(t.Context(), userID)
	if err != nil || len(accts) != 1 {
		t.Fatalf("expected 1 pending account after auth, got %d (err=%v)", len(accts), err)
	}
	pendingID := accts[0].ID
	if err := f.accSvc.SetProtonIdentity(t.Context(), pendingID, userID, "proton-user-OTHER", "other@protonmail.com"); err != nil {
		t.Fatalf("pre-stamp different identity: %v", err)
	}

	resp := post(t, c, f.url+"/accounts/setup/unlock", url.Values{
		"passphrase": {"my-mailbox-passphrase"},
	})
	body := readBody(t, resp)

	// Friendly terminal copy, NOT a 500.
	if resp.StatusCode == http.StatusInternalServerError {
		t.Fatalf("identity mismatch returned 500; want a friendly terminal error. body=%s", body[:min(len(body), 600)])
	}
	if !strings.Contains(body, "different Proton account") {
		t.Errorf("expected identity-mismatch terminal copy; body excerpt=%s", body[:min(len(body), 600)])
	}

	// The pending row must be soft-deleted by the teardown; its stored
	// identity ("proton-user-OTHER") must be preserved (never silently
	// overwritten to "proton-user-joe").
	accts, _ = f.accSvc.ListByUser(t.Context(), userID)
	var soft int
	for _, a := range accts {
		if a.State == account.StateSoftDeleted {
			soft++
			if a.ProtonUserID != "proton-user-OTHER" {
				t.Errorf("stored ProtonUserID = %q, want proton-user-OTHER (must NOT be silently overwritten)", a.ProtonUserID)
			}
		}
	}
	if soft != 1 {
		t.Errorf("expected 1 soft-deleted pending row after mismatch abort, got %d", soft)
	}
}

func TestWizard_Cancel_SoftDeletesPendingAccount(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-cancel", "joe@example.com", "Joe")

	c.Get(f.url + "/accounts/setup")
	resp := post(t, c, f.url+"/accounts/setup/cancel", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/accounts" {
		t.Errorf("redirect = %q, want /accounts", got)
	}

	accts, _ := f.accSvc.ListByUser(t.Context(), userID)
	if len(accts) != 1 {
		t.Fatalf("expected 1 row, got %d", len(accts))
	}
	if accts[0].State != account.StateSoftDeleted {
		t.Errorf("state = %s, want soft_deleted", accts[0].State)
	}
}

// TestWizard_Repeatable_SecondRun covers the SPEC-0005 scenario where
// a user with one active Proton account runs the wizard a second time
// to add another. The implementation supports this naturally
// (handleWizardStart picks up an existing pending row owned by the
// user or creates a new one; the unique (user_id, proton_user_id)
// constraint only fires on truly-duplicate Proton bindings), but the
// other tests only exercise first-run shapes. This test pre-seeds an
// active account and asserts the second run lands a *distinct*
// second active account with the new proton_user_id.
//
// Governing: SPEC-0005 REQ "Add-Proton-Account Wizard" (a user with
// one or more active Proton accounts MAY run the wizard again to
// add another); issue #80.
func TestWizard_Repeatable_SecondRun(t *testing.T) {
	t.Parallel()
	f := newWizardFixture(t, 0)
	c, userID := f.makeUser(t, "sub-second-run", "joe@example.com", "Joe")

	// Pre-seed an active "first" account bound to proton_user_id="first".
	// The wizard's second run will bind to "second" and the unique
	// (user_id, proton_user_id) index MUST NOT fire because the pair
	// is distinct.
	pre, err := f.accSvc.Create(t.Context(), account.CreateParams{
		UserID:       userID,
		ProtonUserID: "first",
		Email:        "first@protonmail.com",
	})
	if err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if _, err := f.accSvc.Transition(t.Context(), pre.ID, account.StateActive); err != nil {
		t.Fatalf("transition: %v", err)
	}

	// Stub the second-run Proton login. UserID="second" so the
	// SetProtonIdentity write picks a fresh slot in the unique index.
	stubClient := readyClient()
	f.stub.push(stubLoginResult{
		client: stubClient,
		auth: &proton.Auth{
			UserID:       "second",
			UID:          "proton-uid-2",
			AccessToken:  "proton-access-2",
			RefreshToken: "proton-refresh-2",
		},
	})

	// Run the wizard end-to-end.
	resp, err := c.Get(f.url + "/accounts/setup")
	if err != nil {
		t.Fatalf("GET setup: %v", err)
	}
	resp.Body.Close()
	post(t, c, f.url+"/accounts/setup/auth", url.Values{
		"username": {"joe-second@protonmail.com"},
		"password": {"hunter2"},
	}).Body.Close()
	resp = post(t, c, f.url+"/accounts/setup/unlock", url.Values{
		"passphrase": {"my-mailbox-passphrase"},
	})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unlock status = %d, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "Set up your mail client") {
		t.Errorf("expected Done page; body excerpt=%s", body[:min(len(body), 600)])
	}
	// Complete to drop the wizard session and land on the dashboard.
	resp = post(t, c, f.url+"/accounts/setup/complete", url.Values{})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("complete status = %d, want 303", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/accounts" {
		t.Errorf("redirect = %q, want /accounts", got)
	}

	// User now owns two active accounts, one per proton_user_id.
	// Soft-deleted rows are excluded from this assertion: we want
	// the second-run path to leave NO collateral pending/soft rows.
	accts, err := f.accSvc.ListByUser(t.Context(), userID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	var active []*account.Account
	for _, a := range accts {
		if a.State == account.StateActive {
			active = append(active, a)
		}
	}
	if len(active) != 2 {
		t.Fatalf("expected 2 active accounts after second-run wizard, got %d (all=%d)", len(active), len(accts))
	}
	seen := map[string]bool{}
	for _, a := range active {
		seen[a.ProtonUserID] = true
	}
	if !seen["first"] || !seen["second"] {
		t.Errorf("active proton_user_ids = %v, want both first and second", seen)
	}
}
