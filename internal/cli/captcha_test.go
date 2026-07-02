package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/store"
)

// captureResult scripts one runVerifyCapture invocation: the token/method it
// returns (as if received over the native-app bridge) and any error.
type captureResult struct {
	token  string
	method string
	err    error
}

// stubVerifyCapture swaps runVerifyCapture for the duration of a test so no real
// browser launches. Each call consumes the next scripted result (the last is
// reused if the loop asks for more than were scripted). It records the verify URLs
// it was handed so a test can assert the challenge URL passed to the browser.
func stubVerifyCapture(t *testing.T, results ...captureResult) *[]string {
	t.Helper()
	prev := runVerifyCapture
	var urls []string
	i := 0
	runVerifyCapture = func(_ context.Context, verifyURL string, _ io.Writer) (string, string, error) {
		urls = append(urls, verifyURL)
		r := results[i]
		if i < len(results)-1 {
			i++
		}
		return r.token, r.method, r.err
	}
	t.Cleanup(func() { runVerifyCapture = prev })
	return &urls
}

// TestVerifyURL confirms the verify URL is built from the offered methods joined
// with commas and the challenge token, each query-escaped.
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

// TestSolveCaptchaHV_RetriesWithCapturedTokenNotChallenge is the core regression
// test: the solve captures a NEW token over the bridge, and LoginWithHV must be
// retried with THAT captured token (and its method) — NOT the URL challenge token.
// Re-presenting the challenge token is exactly the bug that made every solve score
// 12087.
func TestSolveCaptchaHV_RetriesWithCapturedTokenNotChallenge(t *testing.T) {
	stubVerifyCapture(t, captureResult{token: "SOLVED-PAYLOAD-TOKEN", method: "captcha"})
	fake := proton.NewFake()
	fake.UserID = "proton-user"
	fake.TwoFA = proton.TwoFATOTP // the retried login may still require 2FA
	// The challenge token is deliberately different from the captured token.
	hv := &proton.HVRequiredError{Methods: []string{"captcha", "email"}, Token: "URL-CHALLENGE-TOKEN"}

	status, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("solveCaptchaHV: %v", err)
	}
	if status.TwoFA != proton.TwoFATOTP {
		t.Errorf("AuthStatus.TwoFA = %v, want TOTP passthrough", status.TwoFA)
	}
	if len(fake.HVTokens) != 1 {
		t.Fatalf("LoginWithHV called %d times, want 1", len(fake.HVTokens))
	}
	if fake.HVTokens[0] != "SOLVED-PAYLOAD-TOKEN" {
		t.Errorf("LoginWithHV got token %q, want the CAPTURED payload token %q (not the challenge token)", fake.HVTokens[0], "SOLVED-PAYLOAD-TOKEN")
	}
	if fake.HVTokens[0] == "URL-CHALLENGE-TOKEN" {
		t.Error("LoginWithHV was retried with the URL challenge token — the 12087 regression")
	}
}

// TestSolveCaptchaHV_PassesCapturedMethod confirms the captured method flows into
// the LoginWithHV challenge's Methods (x-pm-human-verification-token-type), and
// that an empty method falls back to captcha.
func TestSolveCaptchaHV_PassesCapturedMethod(t *testing.T) {
	if got := capturedMethods("captcha"); len(got) != 1 || got[0] != "captcha" {
		t.Errorf("capturedMethods(captcha) = %v, want [captcha]", got)
	}
	if got := capturedMethods(""); len(got) != 1 || got[0] != "captcha" {
		t.Errorf("capturedMethods(empty) = %v, want [captcha] fallback", got)
	}
	if got := capturedMethods("  "); len(got) != 1 || got[0] != "captcha" {
		t.Errorf("capturedMethods(blank) = %v, want [captcha] fallback", got)
	}
}

// TestSolveCaptchaHV_ChallengeURLPassedToBrowser confirms the challenge URL handed
// to the browser is built from the offered methods and the URL challenge token.
func TestSolveCaptchaHV_ChallengeURLPassedToBrowser(t *testing.T) {
	urls := stubVerifyCapture(t, captureResult{token: "solved", method: "captcha"})
	fake := proton.NewFake()
	hv := &proton.HVRequiredError{Methods: []string{"captcha", "email"}, Token: "chal/&"}

	if _, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv, &bytes.Buffer{}); err != nil {
		t.Fatalf("solveCaptchaHV: %v", err)
	}
	const wantURL = "https://verify.proton.me/?methods=captcha,email&token=chal%2F%26"
	if len(*urls) != 1 || (*urls)[0] != wantURL {
		t.Errorf("verify URL(s) = %v, want [%q]", *urls, wantURL)
	}
}

// TestSolveCaptchaHV_ChromeMissing surfaces errChromeRequired unchanged (the
// controlled browser could not launch) with no login retry.
func TestSolveCaptchaHV_ChromeMissing(t *testing.T) {
	stubVerifyCapture(t, captureResult{err: errChromeRequired})
	fake := proton.NewFake()
	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}

	_, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv, &bytes.Buffer{})
	if !errors.Is(err, errChromeRequired) {
		t.Fatalf("expected errChromeRequired, got %v", err)
	}
	if len(fake.HVTokens) != 0 {
		t.Errorf("login retried despite no browser: %v", fake.HVTokens)
	}
}

// TestSolveCaptchaHV_WindowClosed maps an empty capture (operator closed the
// window / no solve) to a clear rerun error, with no login retry.
func TestSolveCaptchaHV_WindowClosed(t *testing.T) {
	stubVerifyCapture(t, captureResult{token: "", method: ""})
	fake := proton.NewFake()
	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}

	_, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "closed before it was solved") {
		t.Fatalf("expected window-closed guidance, got %v", err)
	}
	if len(fake.HVTokens) != 0 {
		t.Errorf("login retried after a closed window: %v", fake.HVTokens)
	}
}

// TestSolveCaptchaHV_SecondHVThenRetry covers the "verification didn't register"
// path: the first LoginWithHV re-issues the challenge, the window re-opens on the
// FRESH challenge, and the second LoginWithHV succeeds. Each attempt captures a
// distinct solved token.
func TestSolveCaptchaHV_SecondHVThenRetry(t *testing.T) {
	stubVerifyCapture(t,
		captureResult{token: "solved-1", method: "captcha"},
		captureResult{token: "fresh-chal", method: "captcha"},
	)
	fake := proton.NewFake()
	fake.UserID = "proton-user"
	rf := &rejectOnceFake{Fake: fake}
	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}

	status, err := solveCaptchaHV(context.Background(), rf, "joe@proton.test", []byte("pw"), hv, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("solveCaptchaHV second-attempt: %v", err)
	}
	if status.ProtonUserID != "proton-user" {
		t.Errorf("AuthStatus.ProtonUserID = %q, want the retried login's user", status.ProtonUserID)
	}
	if len(rf.HVTokens) != 2 {
		t.Fatalf("LoginWithHV called %d times, want 2", len(rf.HVTokens))
	}
	// First attempt used the first captured token; the second used the token
	// captured after re-opening on the re-issued challenge.
	if rf.HVTokens[0] != "solved-1" {
		t.Errorf("first LoginWithHV used token %q, want %q", rf.HVTokens[0], "solved-1")
	}
	if rf.HVTokens[1] != "fresh-chal" {
		t.Errorf("second LoginWithHV used token %q, want the second captured %q", rf.HVTokens[1], "fresh-chal")
	}
}

// TestSolveCaptchaHV_GivesUpAfterRepeatedHV confirms that when verification never
// registers, the operator gets the initial attempt plus two retries and then a
// clear give-up error.
func TestSolveCaptchaHV_GivesUpAfterRepeatedHV(t *testing.T) {
	urls := stubVerifyCapture(t, captureResult{token: "solved", method: "captcha"})
	fake := proton.NewFake()
	// Always re-issue the challenge: a captured token that never matches HVToken.
	fake.HVChallenge = &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}
	fake.HVToken = "never-matches"
	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}

	_, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "did not register") {
		t.Fatalf("expected give-up guidance, got %v", err)
	}
	if len(*urls) != 3 {
		t.Errorf("verification window opened %d times, want 3 before giving up", len(*urls))
	}
}

// TestSolveCaptchaHV_ValidationFailedGetsFreshChallenge covers the 12087 path: the
// solve completes and a token is captured, but Proton scores it as failed
// (ErrHVValidationFailed). The loop must issue a brand-new Login to mint a FRESH
// challenge (the captured token is dead) and re-open the window — not re-present
// the dead token, and not hard-fail.
func TestSolveCaptchaHV_ValidationFailedGetsFreshChallenge(t *testing.T) {
	urls := stubVerifyCapture(t,
		captureResult{token: "solved-1", method: "captcha"},
		captureResult{token: "chal-2", method: "captcha"},
	)
	f := &validationFailFake{Fake: proton.NewFake()}
	f.UserID = "proton-user"
	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal-1"}

	status, err := solveCaptchaHV(context.Background(), f, "joe@proton.test", []byte("pw"), hv, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("solveCaptchaHV after 12087: %v", err)
	}
	if status.ProtonUserID != "proton-user" {
		t.Errorf("AuthStatus.ProtonUserID = %q, want the fresh solve's user", status.ProtonUserID)
	}
	if len(*urls) != 2 {
		t.Errorf("verification window opened %d times, want 2 (initial + fresh-challenge solve)", len(*urls))
	}
	// The fresh Login re-issued challenge "chal-2"; the second window must open on
	// that URL, not the dead "chal-1".
	if len(*urls) == 2 && !strings.Contains((*urls)[1], "token=chal-2") {
		t.Errorf("second verify URL = %q, want the fresh challenge token chal-2", (*urls)[1])
	}
	if f.logins != 1 {
		t.Errorf("fresh Login called %d times, want 1", f.logins)
	}
}

// validationFailFake rejects the first LoginWithHV with 12087-style
// ErrHVValidationFailed, hands out a fresh challenge on the next Login, and accepts
// only the fresh-challenge token.
type validationFailFake struct {
	*proton.Fake
	logins int
}

func (f *validationFailFake) Login(ctx context.Context, address string, password []byte) (proton.AuthStatus, error) {
	f.logins++
	return proton.AuthStatus{}, &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal-2"}
}

func (f *validationFailFake) LoginWithHV(ctx context.Context, address string, password []byte, hv *proton.HVRequiredError) (proton.AuthStatus, error) {
	f.HVTokens = append(f.HVTokens, hv.Token)
	if hv.Token != "chal-2" {
		return proton.AuthStatus{}, fmt.Errorf("%w (code 12087)", proton.ErrHVValidationFailed)
	}
	return proton.AuthStatus{ProtonUserID: "proton-user"}, nil
}

// TestSolveCaptchaHV_ContextCancelled aborts before opening the browser when the
// context is already cancelled (e.g. Ctrl-C during the flow).
func TestSolveCaptchaHV_ContextCancelled(t *testing.T) {
	urls := stubVerifyCapture(t, captureResult{token: "solved", method: "captcha"})
	fake := proton.NewFake()
	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := solveCaptchaHV(ctx, fake, "joe@proton.test", []byte("pw"), hv, &bytes.Buffer{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if len(*urls) != 0 {
		t.Errorf("browser opened despite a cancelled context: %v", *urls)
	}
}

// TestSolveCaptchaHV_CaptureCancelPropagates confirms a ctx.Err() surfaced from the
// capture layer (Ctrl-C while the window is open) propagates unchanged.
func TestSolveCaptchaHV_CaptureCancelPropagates(t *testing.T) {
	stubVerifyCapture(t, captureResult{err: context.Canceled})
	fake := proton.NewFake()
	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}

	_, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv, &bytes.Buffer{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled to propagate, got %v", err)
	}
	if len(fake.HVTokens) != 0 {
		t.Errorf("login retried after a cancelled capture: %v", fake.HVTokens)
	}
}

// rejectOnceFake wraps a Fake and makes the FIRST LoginWithHV re-issue an HV
// challenge — with a FRESH token, as the real Proton does on every 9001 — before
// the second call succeeds. The second call only succeeds when it presents the
// "fresh-chal" token (the token captured after re-opening on the re-issued
// challenge), so the retry loop must adopt each re-issued challenge.
type rejectOnceFake struct {
	*proton.Fake
	rejected bool
}

func (f *rejectOnceFake) LoginWithHV(ctx context.Context, address string, password []byte, hv *proton.HVRequiredError) (proton.AuthStatus, error) {
	f.HVTokens = append(f.HVTokens, hv.Token)
	if !f.rejected {
		f.rejected = true
		return proton.AuthStatus{}, &proton.HVRequiredError{Methods: hv.Methods, Token: "fresh-chal"}
	}
	if hv.Token != "fresh-chal" {
		return proton.AuthStatus{}, &proton.HVRequiredError{Methods: hv.Methods, Token: "fresh-chal"}
	}
	return proton.AuthStatus{ProtonUserID: "proton-user"}, nil
}

// --- full add-flow integration (interactiveAuth → solveCaptchaHV) -----------

// TestAuthAdd_HumanVerification_SolvesAndPersists drives the whole add flow into
// Proton's 9001 wall and confirms the HV plumbing (interactiveAuth →
// solveCaptchaHV → LoginWithHV → 2FA → unlock) routes correctly and persists an
// active mailbox (SPEC-0007). The browser capture is stubbed so no real browser
// launches; the live solve is the operator's. LoginWithHV must receive the
// CAPTURED token, not the challenge token.
func TestAuthAdd_HumanVerification_SolvesAndPersists(t *testing.T) {
	stubVerifyCapture(t, captureResult{token: "captured-tok", method: "captcha"})
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)

	fake := proton.NewFake()
	fake.UserID = "proton-user-hv"
	fake.Token = "refresh-tok"
	fake.HVChallenge = &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "hv-tok"}

	dialer := &fakeDialer{client: fake}
	// password, then passphrase (no verify-prompt line anymore — the solve is
	// captured over the bridge with no stdin read).
	p := &scriptPrompter{secrets: []string{"hunter2", "mailbox-pass"}}

	var out bytes.Buffer
	if err := authAdd(ctx, st, ks, dialer, p, "hv@proton.test", &out); err != nil {
		t.Fatalf("authAdd with completed human verification: %v", err)
	}
	if _, err := st.GetMailboxByAddress(ctx, "hv@proton.test"); err != nil {
		t.Fatalf("expected an active mailbox after a completed HV add, got %v", err)
	}
	// LoginWithHV must have been retried with the CAPTURED token, not the challenge
	// token Login reported.
	if len(fake.HVTokens) != 1 || fake.HVTokens[0] != "captured-tok" {
		t.Errorf("LoginWithHV got %v, want [captured-tok] (the captured payload token)", fake.HVTokens)
	}
}

// TestAuthAdd_HumanVerification_CloseIsAtomic confirms that when the operator
// closes the verification window, authAdd surfaces the error AND leaves no
// half-written mailbox row behind (SPEC-0007 "adds are atomic"). The close happens
// before any row is inserted, so this also guards that ordering.
func TestAuthAdd_HumanVerification_CloseIsAtomic(t *testing.T) {
	stubVerifyCapture(t, captureResult{token: "", method: ""})
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)

	fake := proton.NewFake()
	fake.UserID = "proton-user-hv"
	fake.HVChallenge = &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "hv-tok"}

	dialer := &fakeDialer{client: fake}
	// password only; the window closes before any solve.
	p := &scriptPrompter{secrets: []string{"hunter2"}}

	var out bytes.Buffer
	err := authAdd(ctx, st, ks, dialer, p, "hv@proton.test", &out)
	if err == nil || !strings.Contains(err.Error(), "closed before it was solved") {
		t.Fatalf("expected window-closed error from authAdd, got %v", err)
	}
	if _, gerr := st.GetMailboxByAddress(ctx, "hv@proton.test"); gerr == nil {
		t.Error("a mailbox row was left behind after the closed HV add")
	} else if !errors.Is(gerr, store.ErrMailboxNotFound) {
		t.Fatalf("unexpected lookup error: %v", gerr)
	}
}
