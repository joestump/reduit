package protonlive

import (
	"context"
	"errors"
	"sync"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/proton"
)

// fakeClient is a minimal proton.Client for registry/reunlock tests. It
// records Logout calls and lets each test pin the GetUser/KeySalts/
// GetAddresses/Unlock results the ReUnlock sequence consumes. Every other
// method returns a zero value — none are exercised by these tests.
type fakeClient struct {
	mu          sync.Mutex
	logoutCalls int
	logoutErr   error

	user      proton.User
	userErr   error
	salts     proton.Salts
	saltsErr  error
	addrs     []proton.Address
	addrsErr  error
	unlockErr error
}

func (f *fakeClient) logouts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logoutCalls
}

func (f *fakeClient) Logout(context.Context) error {
	f.mu.Lock()
	f.logoutCalls++
	f.mu.Unlock()
	return f.logoutErr
}

func (f *fakeClient) GetUser(context.Context) (proton.User, error) { return f.user, f.userErr }
func (f *fakeClient) KeySalts(context.Context) (proton.Salts, error) {
	return f.salts, f.saltsErr
}
func (f *fakeClient) GetAddresses(context.Context) ([]proton.Address, error) {
	return f.addrs, f.addrsErr
}
func (f *fakeClient) Unlock(proton.User, []proton.Address, []byte) (*proton.KeyRing, map[string]*proton.KeyRing, error) {
	return nil, nil, f.unlockErr
}

// --- unused proton.Client surface (zero-value stubs) ---

func (f *fakeClient) AuthInfo(context.Context, proton.AuthInfoReq) (proton.AuthInfo, error) {
	return proton.AuthInfo{}, nil
}
func (f *fakeClient) AuthTOTP(context.Context, string) error           { return nil }
func (f *fakeClient) AuthFIDO2(context.Context, proton.FIDO2Req) error { return nil }
func (f *fakeClient) GetEvent(context.Context, string) ([]proton.Event, bool, error) {
	return nil, false, nil
}
func (f *fakeClient) GetLatestEventID(context.Context) (string, error) { return "", nil }
func (f *fakeClient) GetMessage(context.Context, string) (proton.Message, error) {
	return proton.Message{}, nil
}
func (f *fakeClient) GetMessageRFC822(context.Context, string) ([]byte, error) { return nil, nil }
func (f *fakeClient) ListMessages(context.Context, proton.MessageFilter) ([]proton.MessageMetadata, error) {
	return nil, nil
}
func (f *fakeClient) ListMessagesPage(context.Context, int, int, proton.MessageFilter) ([]proton.MessageMetadata, error) {
	return nil, nil
}
func (f *fakeClient) GroupedMessageCount(context.Context) ([]proton.MessageGroupCount, error) {
	return nil, nil
}
func (f *fakeClient) GetLabels(context.Context, ...proton.LabelType) ([]proton.Label, error) {
	return nil, nil
}
func (f *fakeClient) SendDraft(context.Context, string, proton.SendDraftReq) (proton.Message, error) {
	return proton.Message{}, nil
}
func (f *fakeClient) GetPublicKeys(context.Context, string) (proton.PublicKeys, proton.RecipientType, error) {
	return nil, proton.RecipientTypeExternal, nil
}
func (f *fakeClient) GetAttachment(context.Context, string) ([]byte, error)   { return nil, nil }
func (f *fakeClient) LabelMessages(context.Context, []string, string) error   { return nil }
func (f *fakeClient) UnlabelMessages(context.Context, []string, string) error { return nil }
func (f *fakeClient) MarkMessagesRead(context.Context, ...string) error       { return nil }
func (f *fakeClient) MarkMessagesUnread(context.Context, ...string) error     { return nil }
func (f *fakeClient) LatestRefreshToken() string                              { return "" }

var _ proton.Client = (*fakeClient)(nil)

func TestRegistry_SetGetDrop(t *testing.T) {
	r := New(nil)
	if _, ok := r.Get("acct"); ok {
		t.Fatal("empty registry returned a client")
	}

	c := &fakeClient{}
	r.Set("acct", c)
	got, ok := r.Get("acct")
	if !ok || got != c {
		t.Fatalf("Get after Set: ok=%v got=%v want %v", ok, got, c)
	}
	if r.Len() != 1 {
		t.Fatalf("Len = %d, want 1", r.Len())
	}

	r.Drop(context.Background(), "acct")
	if _, ok := r.Get("acct"); ok {
		t.Fatal("Get after Drop still returned a client")
	}
	if c.logouts() != 1 {
		t.Fatalf("Drop did not Logout: logouts=%d", c.logouts())
	}
	// Idempotent.
	r.Drop(context.Background(), "acct")
	if c.logouts() != 1 {
		t.Fatalf("second Drop logged out again: logouts=%d", c.logouts())
	}
}

func TestRegistry_SetReplacesAndLogsOutPrevious(t *testing.T) {
	r := New(nil)
	old := &fakeClient{}
	fresh := &fakeClient{}
	r.Set("acct", old)
	r.Set("acct", fresh)

	if old.logouts() != 1 {
		t.Fatalf("replaced client not logged out: logouts=%d", old.logouts())
	}
	if fresh.logouts() != 0 {
		t.Fatalf("replacement client should not be logged out: logouts=%d", fresh.logouts())
	}
	got, _ := r.Get("acct")
	if got != fresh {
		t.Fatal("registry did not hold the replacement client")
	}
}

func TestRegistry_SetNilIsNoOp(t *testing.T) {
	r := New(nil)
	r.Set("acct", nil)
	if _, ok := r.Get("acct"); ok {
		t.Fatal("nil client was registered")
	}
	if r.Len() != 0 {
		t.Fatalf("Len = %d, want 0", r.Len())
	}
}

func TestRegistry_CloseAll(t *testing.T) {
	r := New(nil)
	a, b := &fakeClient{}, &fakeClient{}
	r.Set("a", a)
	r.Set("b", b)
	r.CloseAll(context.Background())
	if r.Len() != 0 {
		t.Fatalf("Len after CloseAll = %d, want 0", r.Len())
	}
	if a.logouts() != 1 || b.logouts() != 1 {
		t.Fatalf("CloseAll did not Logout every client: a=%d b=%d", a.logouts(), b.logouts())
	}
}

// fakeAuth implements Authenticator. It returns a preconfigured client
// (and optional error) from NewClientWithRefresh and records the UID it
// was called with.
type fakeAuth struct {
	client proton.Client
	auth   *proton.Auth
	err    error
	gotUID string
	gotRef string
	calls  int
}

func (f *fakeAuth) NewClientWithRefresh(_ context.Context, uid, ref string) (proton.Client, *proton.Auth, error) {
	f.calls++
	f.gotUID, f.gotRef = uid, ref
	if f.err != nil {
		return nil, nil, f.err
	}
	return f.client, f.auth, nil
}

// userWithPrimaryKey builds a gpa.User whose primary key ID matches a
// salt entry so SaltForKey resolves. The salt value is a valid base64
// string so SaltForKey's decode succeeds.
func userWithPrimaryKey(keyID string) (proton.User, proton.Salts) {
	u := gpa.User{
		Keys: gpa.Keys{
			{ID: keyID, Primary: true},
		},
	}
	// "c2FsdHNhbHRzYWx0c2FsdA==" is base64("saltsaltsaltsalt").
	salts := proton.Salts{{ID: keyID, KeySalt: "c2FsdHNhbHRzYWx0c2FsdA=="}}
	return u, salts
}

func TestReUnlock_NoSessionUID(t *testing.T) {
	_, err := ReUnlock(context.Background(), &fakeAuth{}, ReUnlockInputs{
		AccountID:    "acct",
		RefreshToken: "ref",
	})
	if !errors.Is(err, ErrNoSessionUID) {
		t.Fatalf("want ErrNoSessionUID, got %v", err)
	}
}

func TestReUnlock_Success(t *testing.T) {
	keyID := "primary-key"
	user, salts := userWithPrimaryKey(keyID)
	fc := &fakeClient{user: user, salts: salts}
	auth := &fakeAuth{client: fc, auth: &proton.Auth{UID: "sess-uid"}}

	got, err := ReUnlock(context.Background(), auth, ReUnlockInputs{
		AccountID:         "acct",
		SessionUID:        "sess-uid",
		RefreshToken:      "ref",
		MailboxPassphrase: []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("ReUnlock: %v", err)
	}
	if got != fc {
		t.Fatal("ReUnlock returned a different client than the authenticator produced")
	}
	if auth.gotUID != "sess-uid" || auth.gotRef != "ref" {
		t.Fatalf("authenticator got uid=%q ref=%q", auth.gotUID, auth.gotRef)
	}
	if fc.logouts() != 0 {
		t.Fatalf("successful ReUnlock should not Logout: logouts=%d", fc.logouts())
	}
}

func TestReUnlock_UnlockFailureIsCredentialRejected(t *testing.T) {
	keyID := "primary-key"
	user, salts := userWithPrimaryKey(keyID)
	fc := &fakeClient{user: user, salts: salts, unlockErr: errors.New("bad passphrase")}
	auth := &fakeAuth{client: fc, auth: &proton.Auth{UID: "sess-uid"}}

	_, err := ReUnlock(context.Background(), auth, ReUnlockInputs{
		AccountID:         "acct",
		SessionUID:        "sess-uid",
		RefreshToken:      "ref",
		MailboxPassphrase: []byte("wrong"),
	})
	if err == nil {
		t.Fatal("expected error on unlock failure")
	}
	// A wrong passphrase is a durable credential failure, not transient.
	if !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("unlock failure must be credential-rejected: %v", err)
	}
	if fc.logouts() != 1 {
		t.Fatalf("failed ReUnlock must Logout the half-open session: logouts=%d", fc.logouts())
	}
}

func TestReUnlock_RefreshRevokedIsCredentialRejected(t *testing.T) {
	// A 10013 / AuthRefreshTokenInvalid on /auth/v4/refresh is the
	// explicit revoked-token case -> credential-rejected.
	auth := &fakeAuth{err: &gpa.APIError{Code: gpa.AuthRefreshTokenInvalid, Status: 400}}
	_, err := ReUnlock(context.Background(), auth, ReUnlockInputs{
		AccountID:         "acct",
		SessionUID:        "sess-uid",
		RefreshToken:      "ref",
		MailboxPassphrase: []byte("x"),
	})
	if !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("revoked refresh token must be credential-rejected: %v", err)
	}
}

func TestReUnlock_RefreshTransientIsNotCredentialRejected(t *testing.T) {
	// A plain network/5xx error on /auth/v4/refresh is transient: the
	// account must NOT be classified as credential-rejected.
	auth := &fakeAuth{err: errors.New("dial tcp: connection refused")}
	_, err := ReUnlock(context.Background(), auth, ReUnlockInputs{
		AccountID:         "acct",
		SessionUID:        "sess-uid",
		RefreshToken:      "ref",
		MailboxPassphrase: []byte("x"),
	})
	if err == nil {
		t.Fatal("expected error when refresh auth fails")
	}
	if errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("transient refresh failure must NOT be credential-rejected: %v", err)
	}
}

func TestReUnlock_GetUser5xxIsTransient(t *testing.T) {
	// A 500 on GetUser (post-auth data fetch) is transient.
	fc := &fakeClient{userErr: &gpa.APIError{Status: 500}}
	auth := &fakeAuth{client: fc, auth: &proton.Auth{UID: "sess-uid"}}
	_, err := ReUnlock(context.Background(), auth, ReUnlockInputs{
		AccountID:         "acct",
		SessionUID:        "sess-uid",
		RefreshToken:      "ref",
		MailboxPassphrase: []byte("x"),
	})
	if errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("5xx on GetUser must NOT be credential-rejected: %v", err)
	}
	if fc.logouts() != 1 {
		t.Fatalf("failed ReUnlock must Logout: logouts=%d", fc.logouts())
	}
}

func TestReUnlock_GetUser403IsCredentialRejected(t *testing.T) {
	// A 403 on GetUser means the just-minted session is forbidden.
	fc := &fakeClient{userErr: &gpa.APIError{Status: 403}}
	auth := &fakeAuth{client: fc, auth: &proton.Auth{UID: "sess-uid"}}
	_, err := ReUnlock(context.Background(), auth, ReUnlockInputs{
		AccountID:         "acct",
		SessionUID:        "sess-uid",
		RefreshToken:      "ref",
		MailboxPassphrase: []byte("x"),
	})
	if !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("403 on GetUser must be credential-rejected: %v", err)
	}
}

// fakeSecrets implements SecretSource.
type fakeSecrets struct {
	refresh    []byte
	refreshErr error
	pass       []byte
	passErr    error
}

func (f *fakeSecrets) OpenRefreshToken(context.Context, string) ([]byte, error) {
	return f.refresh, f.refreshErr
}
func (f *fakeSecrets) OpenMailboxPassphrase(context.Context, string) ([]byte, error) {
	return f.pass, f.passErr
}

// fakeUIDs implements UIDSource.
type fakeUIDs struct {
	uid string
	err error
}

func (f *fakeUIDs) OpenSessionUID(context.Context, string) (string, error) { return f.uid, f.err }

// fakeTrans implements Transitioner, recording the requested transition.
type fakeTrans struct {
	to    account.State
	calls int
	err   error
}

func (f *fakeTrans) Transition(_ context.Context, _ string, next account.State) (*account.Account, error) {
	f.calls++
	f.to = next
	return nil, f.err
}

func TestLifecycle_RegisterActiveAccounts_MissingUIDSkips(t *testing.T) {
	reg := New(nil)
	auth := &fakeAuth{}
	secrets := &fakeSecrets{refresh: []byte("ref"), pass: []byte("pw")}
	trans := &fakeTrans{}
	// nil UIDSource => the missing-UID gap path.
	lc := NewLifecycle(reg, auth, secrets, nil, trans, nil)

	lc.RegisterActiveAccounts(context.Background(), []*account.Account{
		{ID: "acct", State: account.StateActive},
	})

	if reg.Len() != 0 {
		t.Fatalf("missing UID should not register a client: Len=%d", reg.Len())
	}
	if auth.calls != 0 {
		t.Fatalf("missing UID should not attempt refresh auth: calls=%d", auth.calls)
	}
	if trans.calls != 0 {
		t.Fatalf("missing UID is NOT a credential failure; must not transition: calls=%d", trans.calls)
	}
}

func TestLifecycle_RegisterActiveAccounts_Success(t *testing.T) {
	keyID := "primary-key"
	user, salts := userWithPrimaryKey(keyID)
	fc := &fakeClient{user: user, salts: salts}
	auth := &fakeAuth{client: fc, auth: &proton.Auth{UID: "sess-uid"}}
	secrets := &fakeSecrets{refresh: []byte("ref"), pass: []byte("pw")}
	uids := &fakeUIDs{uid: "sess-uid"}
	trans := &fakeTrans{}
	lc := NewLifecycle(reg(t), auth, secrets, uids, trans, nil)

	lc.reg.Set("ignore-me", &fakeClient{}) // ensure other entries untouched
	lc.RegisterActiveAccounts(context.Background(), []*account.Account{
		{ID: "acct", State: account.StateActive},
	})

	got, ok := lc.reg.Get("acct")
	if !ok || got != fc {
		t.Fatalf("account not registered: ok=%v got=%v", ok, got)
	}
	if trans.calls != 0 {
		t.Fatalf("successful re-unlock must not transition: calls=%d", trans.calls)
	}
}

func TestLifecycle_RegisterActiveAccounts_CredentialFailureTransitionsToPending(t *testing.T) {
	// A revoked refresh token (credential-rejected) must drive the account
	// to pending_proton_setup, matching the #12 sync-worker policy.
	auth := &fakeAuth{err: &gpa.APIError{Code: gpa.AuthRefreshTokenInvalid, Status: 400}}
	secrets := &fakeSecrets{refresh: []byte("ref"), pass: []byte("pw")}
	uids := &fakeUIDs{uid: "sess-uid"}
	trans := &fakeTrans{}
	lc := NewLifecycle(New(nil), auth, secrets, uids, trans, nil)

	lc.RegisterActiveAccounts(context.Background(), []*account.Account{
		{ID: "acct", State: account.StateActive},
	})

	if lc.reg.Len() != 0 {
		t.Fatalf("credential failure must not register a client: Len=%d", lc.reg.Len())
	}
	if trans.calls != 1 || trans.to != account.StatePendingProtonSetup {
		t.Fatalf("credential failure must transition to pending: calls=%d to=%q", trans.calls, trans.to)
	}
}

func TestLifecycle_RegisterActiveAccounts_TransientFailureLeavesActive(t *testing.T) {
	// A transient failure (network blip / 5xx) on ReUnlock must NOT
	// transition the account; it stays active for a later retry. This is
	// the bug the hostile review of PR #35 caught: previously ANY ReUnlock
	// error kicked the account to pending.
	auth := &fakeAuth{err: errors.New("dial tcp: connection refused")}
	secrets := &fakeSecrets{refresh: []byte("ref"), pass: []byte("pw")}
	uids := &fakeUIDs{uid: "sess-uid"}
	trans := &fakeTrans{}
	lc := NewLifecycle(New(nil), auth, secrets, uids, trans, nil)

	lc.RegisterActiveAccounts(context.Background(), []*account.Account{
		{ID: "acct", State: account.StateActive},
	})

	if lc.reg.Len() != 0 {
		t.Fatalf("transient failure must not register a client: Len=%d", lc.reg.Len())
	}
	if trans.calls != 0 {
		t.Fatalf("transient failure must NOT transition (account stays active): calls=%d to=%q", trans.calls, trans.to)
	}
}

func TestLifecycle_RegisterActiveAccounts_SecretOpenFailureLeavesActive(t *testing.T) {
	// A local secret-open failure (DB read / envelope decrypt) is treated
	// as transient: the account stays active, no transition.
	auth := &fakeAuth{}
	secrets := &fakeSecrets{refreshErr: errors.New("sqlite: database is locked")}
	uids := &fakeUIDs{uid: "sess-uid"}
	trans := &fakeTrans{}
	lc := NewLifecycle(New(nil), auth, secrets, uids, trans, nil)

	lc.RegisterActiveAccounts(context.Background(), []*account.Account{
		{ID: "acct", State: account.StateActive},
	})

	if auth.calls != 0 {
		t.Fatalf("secret-open failure must short-circuit before refresh auth: calls=%d", auth.calls)
	}
	if trans.calls != 0 {
		t.Fatalf("secret-open failure must NOT transition: calls=%d", trans.calls)
	}
}

func TestLifecycle_OnAccountStateChange_DropsOnLeaveActive(t *testing.T) {
	reg := New(nil)
	c := &fakeClient{}
	reg.Set("acct", c)
	lc := NewLifecycle(reg, &fakeAuth{}, &fakeSecrets{}, nil, &fakeTrans{}, nil)

	// Active -> suspended drops.
	lc.OnAccountStateChange(context.Background(), account.StateActive, account.StateSuspended, "acct")
	if reg.Len() != 0 {
		t.Fatalf("leave-active did not drop: Len=%d", reg.Len())
	}
	if c.logouts() != 1 {
		t.Fatalf("drop did not Logout: logouts=%d", c.logouts())
	}
}

func TestLifecycle_OnAccountStateChange_IgnoresNonActiveEdges(t *testing.T) {
	reg := New(nil)
	c := &fakeClient{}
	reg.Set("acct", c)
	lc := NewLifecycle(reg, &fakeAuth{}, &fakeSecrets{}, nil, &fakeTrans{}, nil)

	// pending -> active must NOT drop (population is the wizard's job).
	lc.OnAccountStateChange(context.Background(), account.StatePendingProtonSetup, account.StateActive, "acct")
	if reg.Len() != 1 {
		t.Fatalf("active-edge wrongly dropped the client: Len=%d", reg.Len())
	}
	if c.logouts() != 0 {
		t.Fatalf("active-edge wrongly logged out: logouts=%d", c.logouts())
	}
}

// reg is a tiny helper so a test can build a Lifecycle whose registry it
// also inspects via lc.reg.
func reg(t *testing.T) *Registry {
	t.Helper()
	return New(nil)
}

// TestRegistry_ConcurrentAccess hammers Set/Get/Drop/CloseAll from many
// goroutines so `go test -race` exercises the mutex under contention —
// the registry is read by IMAP/MCP/outbox request goroutines and written
// by the wizard + supervisor concurrently in production.
func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := New(nil)
	const accounts = 8
	const workers = 64

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				id := string(rune('a' + (seed+i)%accounts))
				switch (seed + i) % 4 {
				case 0:
					r.Set(id, &fakeClient{})
				case 1:
					r.Get(id)
				case 2:
					r.Drop(context.Background(), id)
				default:
					r.Len()
				}
			}
		}(w)
	}
	wg.Wait()
	// CloseAll concurrently with no in-flight writers must not race or panic.
	r.CloseAll(context.Background())
}
