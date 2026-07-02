package cli

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/store"
)

// stubBrowser swaps runCaptchaBrowser for the duration of a test so the
// solve→LoginWithHV orchestration is exercised without launching a real Chrome
// (the live solve is the operator's — ADR-0021). It records the wrapper URL and
// app version it was called with so the URL/header wiring can be asserted.
func stubBrowser(t *testing.T, token string, err error) *struct{ url, appVersion string } {
	t.Helper()
	prev := runCaptchaBrowser
	got := &struct{ url, appVersion string }{}
	runCaptchaBrowser = func(_ context.Context, wrapperURL, appVersion string) (string, error) {
		got.url, got.appVersion = wrapperURL, appVersion
		return token, err
	}
	t.Cleanup(func() { runCaptchaBrowser = prev })
	return got
}

// TestCaptchaWrapperURL confirms the wrapper URL is built against the client
// host with the HV token URL-escaped and ForceWebMessaging=1 appended
// (ADR-0021). This is the one live-solve input we can assert offline.
func TestCaptchaWrapperURL(t *testing.T) {
	got := captchaWrapperURL("https://mail.proton.me/api", "tok/with+special=")
	const want = "https://mail.proton.me/api/core/v4/captcha?Token=tok%2Fwith%2Bspecial%3D&ForceWebMessaging=1"
	if got != want {
		t.Errorf("captchaWrapperURL = %q, want %q", got, want)
	}

	// A trailing slash on the host must not double up.
	if got := captchaWrapperURL("https://mail.proton.me/api/", "abc"); strings.Contains(got, "api//core") {
		t.Errorf("trailing-slash host produced %q", got)
	}

	// A custom (operator-overridden) host is honored verbatim.
	if got := captchaWrapperURL("http://127.0.0.1:8443/api", "abc"); !strings.HasPrefix(got, "http://127.0.0.1:8443/api/core/v4/captcha?Token=abc") {
		t.Errorf("custom host produced %q", got)
	}
}

// TestContainsFold covers the method-set guard used before attempting a solve.
func TestContainsFold(t *testing.T) {
	if !containsFold([]string{"email", "CAPTCHA"}, "captcha") {
		t.Error("containsFold should match case-insensitively")
	}
	if containsFold([]string{"email", "sms"}, "captcha") {
		t.Error("containsFold matched a missing method")
	}
}

// TestIsChromeNotFound covers the browser-launch failure classification that maps
// a raw exec error to the actionable errChromeRequired (ADR-0021).
func TestIsChromeNotFound(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"exec.ErrNotFound", exec.ErrNotFound, true},
		{"wrapped exec.ErrNotFound", errors.Join(errors.New("start browser"), exec.ErrNotFound), true},
		{"exec message", errors.New(`exec: "google-chrome": executable file not found in $PATH`), true},
		{"chrome not found", errors.New("chrome binary not found"), true},
		{"other", errors.New("navigation timeout"), false},
	}
	for _, tc := range cases {
		if got := isChromeNotFound(tc.err); got != tc.want {
			t.Errorf("%s: isChromeNotFound = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestSolveCaptchaHV_NonCaptchaMethod asserts a non-solvable HV method (email/sms)
// fails fast with clear guidance and never reaches the browser (ADR-0021).
func TestSolveCaptchaHV_NonCaptchaMethod(t *testing.T) {
	got := stubBrowser(t, "should-not-be-used", nil)
	fake := proton.NewFake()
	hv := &proton.HVRequiredError{Methods: []string{"email", "sms"}, Token: "chal"}

	_, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv, &bytes.Buffer{}, &scriptPrompter{})
	if err == nil || !strings.Contains(err.Error(), "cannot solve yet") {
		t.Fatalf("expected non-captcha guidance error, got %v", err)
	}
	if got.url != "" {
		t.Errorf("browser was invoked for a non-captcha method: %q", got.url)
	}
}

// TestSolveCaptchaHV_Success drives the happy path: the (stubbed) browser returns
// a token, LoginWithHV accepts it, and the retried login's AuthStatus flows back.
// It also asserts the wrapper URL and app-version handed to the browser come from
// the client (host + resolved app version).
func TestSolveCaptchaHV_Success(t *testing.T) {
	got := stubBrowser(t, "solved-token", nil)
	fake := proton.NewFake()
	fake.UserID = "proton-user"
	fake.AppVer = "web-mail@9.9.9"
	fake.HostURL = "https://mail.proton.me/api"
	fake.TwoFA = proton.TwoFATOTP // the retried login may still require 2FA
	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "hv tok/&"}

	status, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv, &bytes.Buffer{}, &scriptPrompter{})
	if err != nil {
		t.Fatalf("solveCaptchaHV: %v", err)
	}
	if status.TwoFA != proton.TwoFATOTP {
		t.Errorf("AuthStatus.TwoFA = %v, want TOTP passthrough", status.TwoFA)
	}
	if len(fake.HVTokens) != 1 || fake.HVTokens[0] != "solved-token" {
		t.Errorf("LoginWithHV got tokens %v, want [solved-token]", fake.HVTokens)
	}
	if got.appVersion != "web-mail@9.9.9" {
		t.Errorf("browser app version = %q, want the client's resolved value", got.appVersion)
	}
	const wantURL = "https://mail.proton.me/api/core/v4/captcha?Token=hv+tok%2F%26&ForceWebMessaging=1"
	if got.url != wantURL {
		t.Errorf("browser wrapper URL = %q, want %q", got.url, wantURL)
	}
}

// TestSolveCaptchaHV_Closed maps a closed/timeout browser (empty token, no error)
// to actionable "rerun and solve" guidance, and asserts the login is not retried.
func TestSolveCaptchaHV_Closed(t *testing.T) {
	stubBrowser(t, "", nil)
	fake := proton.NewFake()
	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}

	_, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv, &bytes.Buffer{}, &scriptPrompter{})
	if err == nil || !strings.Contains(err.Error(), "closed without solving") {
		t.Fatalf("expected closed-window guidance, got %v", err)
	}
	if len(fake.HVTokens) != 0 {
		t.Errorf("login retried after a closed window: %v", fake.HVTokens)
	}
}

// TestSolveCaptchaHV_ChromeRequired propagates the browser's Chrome-required error
// verbatim so a headless operator gets the handoff/import guidance (ADR-0021).
func TestSolveCaptchaHV_ChromeRequired(t *testing.T) {
	stubBrowser(t, "", errChromeRequired)
	fake := proton.NewFake()
	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}

	_, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv, &bytes.Buffer{}, &scriptPrompter{})
	if !errors.Is(err, errChromeRequired) {
		t.Fatalf("expected errChromeRequired, got %v", err)
	}
}

// TestSolveCaptchaHV_TokenRejected turns a LoginWithHV that still reports HV
// (expired/rejected token) into a clean "solve it again" error.
func TestSolveCaptchaHV_TokenRejected(t *testing.T) {
	stubBrowser(t, "stale-token", nil)
	fake := proton.NewFake()
	fake.HVChallenge = &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}
	fake.HVToken = "the-only-good-token" // any other solved token is re-challenged
	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}

	_, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv, &bytes.Buffer{}, &scriptPrompter{})
	if err == nil || !strings.Contains(err.Error(), "rejected or expired") {
		t.Fatalf("expected token-rejected guidance, got %v", err)
	}
}

// TestAuthAdd_HumanVerification_SolvesAndPersists drives the whole add flow into
// Proton's 9001 wall and confirms the HV plumbing (interactiveAuth →
// solveCaptchaHV → LoginWithHV → 2FA → unlock) routes correctly with a solved
// token and persists an active mailbox (SPEC-0007). The browser is stubbed so no
// real Chrome launches; the live solve is the operator's.
func TestAuthAdd_HumanVerification_SolvesAndPersists(t *testing.T) {
	stubBrowser(t, "solved-token", nil)
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)

	fake := proton.NewFake()
	fake.UserID = "proton-user-hv"
	fake.Token = "refresh-tok"
	fake.HVChallenge = &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "hv-tok"}

	dialer := &fakeDialer{client: fake}
	p := &scriptPrompter{secrets: []string{"hunter2", "mailbox-pass"}}

	var out bytes.Buffer
	if err := authAdd(ctx, st, ks, dialer, p, "hv@proton.test", &out); err != nil {
		t.Fatalf("authAdd with solved CAPTCHA: %v", err)
	}
	if _, err := st.GetMailboxByAddress(ctx, "hv@proton.test"); err != nil {
		t.Fatalf("expected an active mailbox after a solved HV add, got %v", err)
	}
	if len(fake.HVTokens) != 1 || fake.HVTokens[0] != "solved-token" {
		t.Errorf("LoginWithHV got %v, want [solved-token]", fake.HVTokens)
	}
}

// TestAuthAdd_HumanVerification_ChromeMissingIsAtomic confirms that when the
// solve fails because no Chrome is present, authAdd surfaces the actionable error
// AND leaves no half-written mailbox row behind (SPEC-0007 "adds are atomic").
func TestAuthAdd_HumanVerification_ChromeMissingIsAtomic(t *testing.T) {
	stubBrowser(t, "", errChromeRequired)
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)

	fake := proton.NewFake()
	fake.UserID = "proton-user-hv"
	fake.HVChallenge = &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "hv-tok"}

	dialer := &fakeDialer{client: fake}
	p := &scriptPrompter{secrets: []string{"hunter2"}}

	var out bytes.Buffer
	err := authAdd(ctx, st, ks, dialer, p, "hv@proton.test", &out)
	if !errors.Is(err, errChromeRequired) {
		t.Fatalf("expected errChromeRequired from authAdd, got %v", err)
	}
	if _, gerr := st.GetMailboxByAddress(ctx, "hv@proton.test"); gerr == nil {
		t.Error("a mailbox row was left behind after the failed HV add")
	} else if !errors.Is(gerr, store.ErrMailboxNotFound) {
		t.Fatalf("unexpected lookup error: %v", gerr)
	}
}
