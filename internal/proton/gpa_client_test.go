package proton

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"
)

// These tests exercise the concrete client's lifecycle guards, which are pure
// (they short-circuit before any network call) and so run without a live
// account. The network paths themselves are the thin edge delegated to
// go-proton-api and are not unit-tested here (ADR-0001).

func TestGPAClient_GuardsBeforeAuth(t *testing.T) {
	ctx := context.Background()
	c := &gpaClient{} // no manager call needed; cli is nil

	if err := c.SubmitTOTP(ctx, "123"); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("SubmitTOTP: %v", err)
	}
	if err := c.Unlock(ctx, []byte("p")); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("Unlock: %v", err)
	}
	if _, err := c.LatestEventID(ctx); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("LatestEventID: %v", err)
	}
	if _, err := c.GetEvents(ctx, "e0"); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("GetEvents: %v", err)
	}
	if err := c.Refresh(ctx); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("Refresh without token: %v", err)
	}
}

func TestGPAClient_GuardsBeforeUnlock(t *testing.T) {
	ctx := context.Background()
	c := &gpaClient{} // addrKRs nil => not unlocked

	if _, err := c.DecryptMessage(ctx, "m1"); !errors.Is(err, ErrNotUnlocked) {
		t.Errorf("DecryptMessage: %v", err)
	}
	if _, err := c.DecryptAttachment(ctx, "m1", "a1"); !errors.Is(err, ErrNotUnlocked) {
		t.Errorf("DecryptAttachment: %v", err)
	}
	if _, err := c.Send(ctx, validMsg()); !errors.Is(err, ErrNotUnlocked) {
		t.Errorf("Send: %v", err)
	}
}

func TestGPAClient_AccessorsZeroValue(t *testing.T) {
	c := &gpaClient{}
	if c.ProtonUserID() != "" {
		t.Error("ProtonUserID should be empty before auth")
	}
	if c.RefreshToken() != "" {
		t.Error("RefreshToken should be empty before auth")
	}
	if c.SessionUID() != "" {
		t.Error("SessionUID should be empty before auth")
	}
	c.Close() // must not panic with nil cli
}

func TestNewDialer_NewClientImplementsInterface(t *testing.T) {
	d := NewDialer(Config{HostURL: "https://example.invalid", AppVersion: "reduit@test"})
	defer d.Close()

	var _ Dialer = d
	c := d.NewClient()
	if c == nil {
		t.Fatal("NewClient returned nil")
	}
	if c.ProtonUserID() != "" {
		t.Error("fresh client should have no proton user id")
	}
	c.Close()
}

// addressByID resolves only unlocked addresses (used by Send to fill the
// sender). Verify the lookup logic directly.
func TestGPAClient_AddressByID(t *testing.T) {
	c := &gpaClient{}
	if _, ok := c.addressByID("missing"); ok {
		t.Error("addressByID found an address with empty table")
	}
}

// recordingRT records every outbound request and returns a canned proton success
// envelope, so a test can observe whether a network call happened and which auth
// token it carried.
type recordingRT struct {
	mu   sync.Mutex
	reqs []recordedReq
	body string // response body to return (proton envelope)
}

type recordedReq struct {
	path string
	auth string
	uid  string
}

func (r *recordingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.reqs = append(r.reqs, recordedReq{
		path: req.URL.Path,
		auth: req.Header.Get("Authorization"),
		uid:  req.Header.Get("x-pm-uid"),
	})
	r.mu.Unlock()
	body := r.body
	if body == "" {
		body = `{"Code":1000}`
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
			// go-proton-api parses the Date header to track server time; a missing
			// or empty value makes response processing error before our assertions.
			"Date": []string{time.Now().UTC().Format(http.TimeFormat)},
		},
		Body:    io.NopCloser(bytes.NewBufferString(body)),
		Request: req,
	}, nil
}

func (r *recordingRT) snapshot() []recordedReq {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedReq(nil), r.reqs...)
}

// TestGPADialer_ResumeReusesCachedSession is the regression guard for the 9101
// scope bug: Resume MUST rebuild the session by REUSING the cached tokens
// (Manager.NewClient) and MUST NOT eagerly refresh (Manager.NewClientWithRefresh
// hits /auth/v4/refresh, which reduces a 2FA session's scope). We prove it two
// ways: Resume makes no network call at all, and the FIRST real API call carries
// the seeded access token — never a token minted by a prior refresh.
func TestGPADialer_ResumeReusesCachedSession(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRT{body: `{"Code":1000,"Labels":[]}`}
	d := NewDialer(Config{HostURL: "https://proton.invalid", AppVersion: "reduit@test", Transport: rt})
	defer d.Close()

	c, err := d.Resume(ctx, "user-1", "uid-1", "acc-1", "ref-1")
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	defer c.Close()

	// The crux: NewClient does no I/O, so a correct Resume touches the network
	// zero times. An eager refresh (the bug) would show a /auth/v4/refresh here.
	if got := rt.snapshot(); len(got) != 0 {
		t.Fatalf("Resume made %d network call(s), want 0 (eager refresh regressed): %+v", len(got), got)
	}

	// The seeded session state is observable immediately, without any refresh.
	if c.AccessToken() != "acc-1" {
		t.Errorf("AccessToken() = %q, want acc-1", c.AccessToken())
	}
	if c.RefreshToken() != "ref-1" {
		t.Errorf("RefreshToken() = %q, want ref-1", c.RefreshToken())
	}
	if c.SessionUID() != "uid-1" {
		t.Errorf("SessionUID() = %q, want uid-1", c.SessionUID())
	}

	// The first real call presents the SEEDED access token and session UID
	// directly — proof the cached session was reused, not refreshed first.
	if _, err := c.Labels(ctx); err != nil {
		t.Fatalf("Labels: %v", err)
	}
	got := rt.snapshot()
	if len(got) == 0 {
		t.Fatal("Labels made no network call")
	}
	first := got[0]
	if first.path == "/auth/v4/refresh" {
		t.Fatalf("first call was an eager refresh (%s); the cached session was not reused", first.path)
	}
	if first.auth != "Bearer acc-1" {
		t.Errorf("first call Authorization = %q, want %q (seeded access token)", first.auth, "Bearer acc-1")
	}
	if first.uid != "uid-1" {
		t.Errorf("first call x-pm-uid = %q, want uid-1", first.uid)
	}
}

// TestGPAClient_UnlockWithKeyPassSkipsSalts is the regression guard for the
// 9101-on-resume fix: UnlockWithKeyPass MUST NOT call the salts endpoint
// (/core/v4/keys/salts) — that endpoint needs the 2FA-elevated scope a
// lazily-refreshed session loses. It fetches user + address metadata (both work
// on the reduced mail scope) and runs the local crypto unlock from the persisted
// key pass. We assert the salts path is absent from the recorded requests, the
// two metadata paths are present, and the key pass is retained for persistence.
func TestGPAClient_UnlockWithKeyPassSkipsSalts(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRT{body: `{"Code":1000}`}
	d := NewDialer(Config{HostURL: "https://proton.invalid", AppVersion: "reduit@test", Transport: rt})
	defer d.Close()

	c, err := d.Resume(ctx, "user-1", "uid-1", "acc-1", "ref-1")
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	defer c.Close()

	keyPass := []byte("salted-key-pass")
	// The canned envelope yields an empty key set, so the local gpa.Unlock cannot
	// build a keyring and returns ErrUnlockFailed — but ONLY after GetUser and
	// GetAddresses ran and WITHOUT ever calling the salts endpoint, which is the
	// property under test. (A real account's keys would unlock; here we only
	// assert the request shape, not the crypto outcome.)
	if err := c.UnlockWithKeyPass(ctx, keyPass); !errors.Is(err, ErrUnlockFailed) {
		t.Fatalf("UnlockWithKeyPass = %v, want ErrUnlockFailed on the empty-key envelope", err)
	}

	var sawUsers, sawAddresses, sawSalts bool
	for _, r := range rt.snapshot() {
		switch r.path {
		case "/core/v4/keys/salts":
			sawSalts = true
		case "/core/v4/users":
			sawUsers = true
		case "/core/v4/addresses":
			sawAddresses = true
		}
	}
	if sawSalts {
		t.Error("UnlockWithKeyPass called /core/v4/keys/salts; it must skip the salts endpoint on a resume")
	}
	if !sawUsers {
		t.Error("UnlockWithKeyPass did not fetch /core/v4/users")
	}
	if !sawAddresses {
		t.Error("UnlockWithKeyPass did not fetch /core/v4/addresses")
	}
}

// TestGPAClient_UnlockWithKeyPassGuardsBeforeAuth verifies the nil-session guard.
func TestGPAClient_UnlockWithKeyPassGuardsBeforeAuth(t *testing.T) {
	c := &gpaClient{}
	if err := c.UnlockWithKeyPass(context.Background(), []byte("kp")); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("UnlockWithKeyPass before auth = %v, want ErrNotAuthenticated", err)
	}
	if c.SaltedKeyPass() != nil {
		t.Error("SaltedKeyPass should be nil before any unlock")
	}
}

// TestGPAClient_UnlockWithKeyPassErrorHasNoKeyPass guards SPEC-0007 "No Secret
// Leakage" for the new path: an ErrUnlockFailed from a stale/wrong key pass must
// not embed the key pass bytes. gpa.Unlock's error carries a crypto message, not
// the secret, and the wrap adds only that.
func TestGPAClient_UnlockWithKeyPassErrorHasNoKeyPass(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRT{body: `{"Code":1000}`}
	d := NewDialer(Config{HostURL: "https://proton.invalid", AppVersion: "reduit@test", Transport: rt})
	defer d.Close()
	c, err := d.Resume(ctx, "u", "uid", "acc", "ref")
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	defer c.Close()

	const secret = "SUPER-SECRET-KEY-PASS-BYTES"
	uerr := c.UnlockWithKeyPass(ctx, []byte(secret))
	if uerr == nil {
		t.Fatal("expected an unlock error on the empty-key envelope")
	}
	if strings.Contains(uerr.Error(), secret) {
		t.Errorf("UnlockWithKeyPass error leaked the key pass: %q", uerr.Error())
	}
}

// TestGPAClient_OnAuthCapturesRotation proves the AuthHandler setClient installs
// keeps the wrapper's session state in step when go-proton-api lazily refreshes:
// a captured Auth updates the UID, access token, and refresh token so the caller
// can persist the rotated values (SPEC-0007 "Cross-Process Session Resume"). A
// refresh Auth carrying no UID must not clobber the known one.
func TestGPAClient_OnAuthCapturesRotation(t *testing.T) {
	c := &gpaClient{uid: "uid-1", accessToken: "acc-1", refreshToken: "ref-1"}

	c.onAuth(gpa.Auth{UID: "uid-2", AccessToken: "acc-2", RefreshToken: "ref-2"})
	if c.SessionUID() != "uid-2" || c.AccessToken() != "acc-2" || c.RefreshToken() != "ref-2" {
		t.Fatalf("after rotation: uid=%q acc=%q ref=%q, want uid-2/acc-2/ref-2",
			c.SessionUID(), c.AccessToken(), c.RefreshToken())
	}

	// A lazy refresh may return no UID; the tokens still rotate but the UID must
	// be preserved, not blanked.
	c.onAuth(gpa.Auth{UID: "", AccessToken: "acc-3", RefreshToken: "ref-3"})
	if c.SessionUID() != "uid-2" {
		t.Errorf("SessionUID clobbered by empty-UID refresh: %q, want uid-2", c.SessionUID())
	}
	if c.AccessToken() != "acc-3" || c.RefreshToken() != "ref-3" {
		t.Errorf("tokens not rotated: acc=%q ref=%q, want acc-3/ref-3", c.AccessToken(), c.RefreshToken())
	}
}
