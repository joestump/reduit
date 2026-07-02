package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/store"
)

// stubOpenBrowser swaps openBrowser for the duration of a test so no real
// browser is launched (the live solve is the operator's) and the URL passed to
// it can be asserted. It returns a pointer to the captured URL.
func stubOpenBrowser(t *testing.T, err error) *string {
	t.Helper()
	prev := openBrowser
	var got string
	openBrowser = func(url string) error {
		got = url
		return err
	}
	t.Cleanup(func() { openBrowser = prev })
	return &got
}

// enterPrompter answers every line() prompt with an empty string (the operator
// pressing Enter). It records how many times it was asked so a test can assert
// exactly one foreground read per attempt (no concurrent stdin reads).
type enterPrompter struct{ calls int }

func (p *enterPrompter) secret(string) ([]byte, error) {
	return nil, errors.New("no secret prompt expected")
}
func (p *enterPrompter) line(string) (string, error) { p.calls++; return "", nil }

// TestVerifyURL confirms the verify URL is built like Proton Bridge: the offered
// methods joined with commas and the token, each query-escaped.
func TestVerifyURL(t *testing.T) {
	hv := &proton.HVRequiredError{Methods: []string{"captcha", "email"}, Token: "tok/with+special="}
	got := verifyURL(hv)
	const want = "https://verify.proton.me/?methods=captcha,email&token=tok%2Fwith%2Bspecial%3D"
	if got != want {
		t.Errorf("verifyURL = %q, want %q", got, want)
	}

	// A single method still produces a well-formed URL (no trailing comma).
	if got := verifyURL(&proton.HVRequiredError{Methods: []string{"captcha"}, Token: "abc"}); got != "https://verify.proton.me/?methods=captcha&token=abc" {
		t.Errorf("single-method verifyURL = %q", got)
	}
}

// TestSolveCaptchaHV_Success drives the happy path: the verify page opens, the
// operator presses Enter, LoginWithHV accepts the same challenge, and the
// retried login's AuthStatus flows back. It asserts the URL handed to the
// browser and that exactly one foreground prompt fired.
func TestSolveCaptchaHV_Success(t *testing.T) {
	openedURL := stubOpenBrowser(t, nil)
	fake := proton.NewFake()
	fake.UserID = "proton-user"
	fake.TwoFA = proton.TwoFATOTP // the retried login may still require 2FA
	hv := &proton.HVRequiredError{Methods: []string{"captcha", "email"}, Token: "hv tok/&"}

	p := &enterPrompter{}
	status, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv, &bytes.Buffer{}, p)
	if err != nil {
		t.Fatalf("solveCaptchaHV: %v", err)
	}
	if status.TwoFA != proton.TwoFATOTP {
		t.Errorf("AuthStatus.TwoFA = %v, want TOTP passthrough", status.TwoFA)
	}
	if len(fake.HVTokens) != 1 || fake.HVTokens[0] != "hv tok/&" {
		t.Errorf("LoginWithHV got tokens %v, want the challenge token", fake.HVTokens)
	}
	const wantURL = "https://verify.proton.me/?methods=captcha,email&token=hv+tok%2F%26"
	if *openedURL != wantURL {
		t.Errorf("browser URL = %q, want %q", *openedURL, wantURL)
	}
	if p.calls != 1 {
		t.Errorf("prompt fired %d times, want exactly 1 foreground read", p.calls)
	}
}

// TestSolveCaptchaHV_BrowserOpenFailsIsNonFatal confirms a failed browser launch
// (headless host) does not abort the solve: the URL is printed for copy/paste
// and the flow proceeds on the operator's Enter.
func TestSolveCaptchaHV_BrowserOpenFailsIsNonFatal(t *testing.T) {
	stubOpenBrowser(t, errors.New("no browser"))
	fake := proton.NewFake()
	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}

	var out bytes.Buffer
	if _, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv, &out, &enterPrompter{}); err != nil {
		t.Fatalf("solveCaptchaHV should proceed despite a browser-open failure: %v", err)
	}
	if !strings.Contains(out.String(), "https://verify.proton.me/") {
		t.Errorf("verify URL not printed for copy/paste: %q", out.String())
	}
}

// TestSolveCaptchaHV_SecondHVThenRetry covers the "verification didn't register"
// path: the first LoginWithHV re-issues the challenge, the operator solves again
// (a second Enter), and the second LoginWithHV succeeds.
func TestSolveCaptchaHV_SecondHVThenRetry(t *testing.T) {
	stubOpenBrowser(t, nil)
	fake := proton.NewFake()
	fake.UserID = "proton-user"
	// Reject the first token, accept the second: the token value is the same
	// challenge token both times, so drive the re-challenge via a scripted
	// prompter/HV instead — see rejectOnceFake below.
	rf := &rejectOnceFake{Fake: fake}
	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}

	p := &enterPrompter{}
	status, err := solveCaptchaHV(context.Background(), rf, "joe@proton.test", []byte("pw"), hv, &bytes.Buffer{}, p)
	if err != nil {
		t.Fatalf("solveCaptchaHV second-attempt: %v", err)
	}
	if status.ProtonUserID != "proton-user" {
		t.Errorf("AuthStatus.ProtonUserID = %q, want the retried login's user", status.ProtonUserID)
	}
	if p.calls != 2 {
		t.Errorf("prompt fired %d times, want 2 (initial + one retry)", p.calls)
	}
	if len(rf.HVTokens) != 2 {
		t.Errorf("LoginWithHV called %d times, want 2", len(rf.HVTokens))
	}
	// The second attempt must present the re-issued challenge's FRESH token,
	// not the consumed original (Proton rotates the token per 9001).
	if len(rf.HVTokens) == 2 && rf.HVTokens[1] != "fresh-chal" {
		t.Errorf("second LoginWithHV used token %q, want the re-issued %q", rf.HVTokens[1], "fresh-chal")
	}
}

// TestSolveCaptchaHV_GivesUpAfterSecondHV confirms that when verification never
// registers, the operator gets one retry and then a clear give-up error.
func TestSolveCaptchaHV_GivesUpAfterSecondHV(t *testing.T) {
	stubOpenBrowser(t, nil)
	fake := proton.NewFake()
	// Always re-issue the challenge: a token that never matches HVToken.
	fake.HVChallenge = &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}
	fake.HVToken = "never-matches"
	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}

	p := &enterPrompter{}
	_, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv, &bytes.Buffer{}, p)
	if err == nil || !strings.Contains(err.Error(), "did not register") {
		t.Fatalf("expected give-up guidance, got %v", err)
	}
	if p.calls != 2 {
		t.Errorf("prompt fired %d times, want 2 before giving up", p.calls)
	}
}

// TestSolveCaptchaHV_Cancel maps a "cancel" answer to a clean abort error, with
// no login retry.
func TestSolveCaptchaHV_Cancel(t *testing.T) {
	stubOpenBrowser(t, nil)
	fake := proton.NewFake()
	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}

	_, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv, &bytes.Buffer{}, &cancelPrompter{})
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("expected cancellation error, got %v", err)
	}
	if len(fake.HVTokens) != 0 {
		t.Errorf("login retried after cancel: %v", fake.HVTokens)
	}
}

// TestSolveCaptchaHV_ContextCancelled aborts before opening the browser when the
// context is already cancelled (e.g. Ctrl-C during the flow).
func TestSolveCaptchaHV_ContextCancelled(t *testing.T) {
	openedURL := stubOpenBrowser(t, nil)
	fake := proton.NewFake()
	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := solveCaptchaHV(ctx, fake, "joe@proton.test", []byte("pw"), hv, &bytes.Buffer{}, &enterPrompter{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if *openedURL != "" {
		t.Errorf("browser opened despite a cancelled context: %q", *openedURL)
	}
}

// cancelPrompter answers the verification prompt with "cancel".
type cancelPrompter struct{}

func (cancelPrompter) secret(string) ([]byte, error) {
	return nil, errors.New("no secret prompt expected")
}
func (cancelPrompter) line(string) (string, error) { return "cancel", nil }

// rejectOnceFake wraps a Fake and makes the FIRST LoginWithHV re-issue an HV
// challenge — with a FRESH token, as the real Proton does on every 9001 —
// before the second call succeeds. The second call only succeeds when it
// presents the fresh token: re-solving the consumed original is futile, so
// the retry loop must adopt each re-issued challenge (hostile-review finding).
type rejectOnceFake struct {
	*proton.Fake
	rejected bool
}

func (f *rejectOnceFake) LoginWithHV(ctx context.Context, address string, password []byte, hv *proton.HVRequiredError) (proton.AuthStatus, error) {
	f.HVTokens = append(f.HVTokens, hv.Token)
	if !f.rejected {
		f.rejected = true
		return proton.AuthStatus{}, &proton.HVRequiredError{Methods: hv.Methods, Token: "fresh-" + hv.Token}
	}
	if hv.Token != "fresh-chal" {
		// A stale (consumed) token can never verify.
		return proton.AuthStatus{}, &proton.HVRequiredError{Methods: hv.Methods, Token: "fresh-" + hv.Token}
	}
	return proton.AuthStatus{ProtonUserID: "proton-user"}, nil
}

// --- full add-flow integration (interactiveAuth → solveCaptchaHV) -----------

// TestAuthAdd_HumanVerification_SolvesAndPersists drives the whole add flow into
// Proton's 9001 wall and confirms the HV plumbing (interactiveAuth →
// solveCaptchaHV → LoginWithHV → 2FA → unlock) routes correctly and persists an
// active mailbox (SPEC-0007). The browser is stubbed and the operator's Enter is
// scripted so no real browser launches; the live solve is the operator's.
func TestAuthAdd_HumanVerification_SolvesAndPersists(t *testing.T) {
	stubOpenBrowser(t, nil)
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)

	fake := proton.NewFake()
	fake.UserID = "proton-user-hv"
	fake.Token = "refresh-tok"
	fake.HVChallenge = &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "hv-tok"}

	dialer := &fakeDialer{client: fake}
	// password, then Enter at the verify prompt, then passphrase.
	p := &scriptPrompter{secrets: []string{"hunter2", "mailbox-pass"}, lines: []string{""}}

	var out bytes.Buffer
	if err := authAdd(ctx, st, ks, dialer, p, "hv@proton.test", &out); err != nil {
		t.Fatalf("authAdd with completed human verification: %v", err)
	}
	if _, err := st.GetMailboxByAddress(ctx, "hv@proton.test"); err != nil {
		t.Fatalf("expected an active mailbox after a completed HV add, got %v", err)
	}
	// LoginWithHV must have been retried with the SAME challenge token Login
	// reported (Bridge's flow — no token is captured from the browser).
	if len(fake.HVTokens) != 1 || fake.HVTokens[0] != "hv-tok" {
		t.Errorf("LoginWithHV got %v, want [hv-tok] (the same challenge token)", fake.HVTokens)
	}
}

// TestAuthAdd_HumanVerification_CancelIsAtomic confirms that when the operator
// cancels the verification, authAdd surfaces the error AND leaves no half-written
// mailbox row behind (SPEC-0007 "adds are atomic"). Cancel happens before any row
// is inserted, so this also guards that ordering.
func TestAuthAdd_HumanVerification_CancelIsAtomic(t *testing.T) {
	stubOpenBrowser(t, nil)
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)

	fake := proton.NewFake()
	fake.UserID = "proton-user-hv"
	fake.HVChallenge = &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "hv-tok"}

	dialer := &fakeDialer{client: fake}
	// password, then "cancel" at the verify prompt.
	p := &scriptPrompter{secrets: []string{"hunter2"}, lines: []string{"cancel"}}

	var out bytes.Buffer
	err := authAdd(ctx, st, ks, dialer, p, "hv@proton.test", &out)
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("expected cancellation error from authAdd, got %v", err)
	}
	if _, gerr := st.GetMailboxByAddress(ctx, "hv@proton.test"); gerr == nil {
		t.Error("a mailbox row was left behind after the cancelled HV add")
	} else if !errors.Is(gerr, store.ErrMailboxNotFound) {
		t.Fatalf("unexpected lookup error: %v", gerr)
	}
}
