package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"strings"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/keychain"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/store"
)

// stubBrowser replaces openBrowser with a no-op for the duration of a test so
// the CAPTCHA solver never launches a real browser and never auto-captures a
// token (the manual/timeout path is then exercised).
func stubBrowser(t *testing.T) {
	t.Helper()
	orig := openBrowser
	openBrowser = func(string) error { return nil }
	t.Cleanup(func() { openBrowser = orig })
}

// browserAutoSolves stubs openBrowser to POST a solved token straight to the
// loopback /token route, simulating the operator solving the CAPTCHA and the
// wrapper page's postMessage auto-capture firing. Because it POSTs before
// returning, the token is buffered on tokenCh before solveCaptchaHV's select
// runs — the deterministic stand-in for the browser auto path.
func browserAutoSolves(t *testing.T, token string) {
	t.Helper()
	orig := openBrowser
	openBrowser = func(url string) error {
		resp, err := http.PostForm(url+"token", neturl.Values{"token": {token}})
		if err != nil {
			t.Errorf("simulated browser POST: %v", err)
			return nil
		}
		_ = resp.Body.Close()
		return nil
	}
	t.Cleanup(func() { openBrowser = orig })
}

// shortHVTimeout shrinks the auto-capture wait so the manual/timeout fallback is
// reached quickly in tests.
func shortHVTimeout(t *testing.T) {
	t.Helper()
	orig := hvCaptchaTimeout
	hvCaptchaTimeout = 10 * time.Millisecond
	t.Cleanup(func() { hvCaptchaTimeout = orig })
}

// --- loopback handler (httptest) --------------------------------------------

func TestCaptchaHandler_ServesWrapperAndCaptcha(t *testing.T) {
	tokenCh := make(chan string, 1)
	srv := httptest.NewServer(newCaptchaHandler([]byte("<html><head></head><body>challenge</body></html>"), tokenCh))
	t.Cleanup(srv.Close)

	// Root serves the wrapper page that iframes /captcha.
	root := httpGet(t, srv.URL+"/")
	if !strings.Contains(root, `src="/captcha"`) {
		t.Errorf("wrapper page does not iframe /captcha:\n%s", root)
	}
	if !strings.Contains(root, "addEventListener('message'") {
		t.Errorf("wrapper page missing postMessage listener")
	}
	// The token is POSTed (not put in the query string).
	if !strings.Contains(root, "method: 'POST'") {
		t.Errorf("wrapper page does not POST the token")
	}

	// /captcha serves Proton's bytes with an injected <base href>.
	cap := httpGet(t, srv.URL+"/captcha")
	if !strings.Contains(cap, "challenge") {
		t.Errorf("captcha page missing upstream bytes: %s", cap)
	}
	if !strings.Contains(cap, `<base href="`+captchaBaseHost+`">`) {
		t.Errorf("captcha page missing injected base href: %s", cap)
	}
}

func TestCaptchaHandler_CapturesPostedToken(t *testing.T) {
	tokenCh := make(chan string, 1)
	srv := httptest.NewServer(newCaptchaHandler(nil, tokenCh))
	t.Cleanup(srv.Close)

	resp, err := http.PostForm(srv.URL+"/token", neturl.Values{"token": {"solved-abc123"}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(strings.ToLower(string(body)), "close this tab") {
		t.Errorf("token page missing close-tab guidance: %s", body)
	}
	select {
	case got := <-tokenCh:
		if got != "solved-abc123" {
			t.Errorf("captured token = %q, want solved-abc123", got)
		}
	default:
		t.Fatal("token was not delivered on the channel")
	}
}

func TestCaptchaHandler_UnknownPath404(t *testing.T) {
	srv := httptest.NewServer(newCaptchaHandler(nil, make(chan string, 1)))
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/nope")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func httpGet(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return string(b)
}

// --- injectBaseHref / containsFold ------------------------------------------

func TestInjectBaseHref(t *testing.T) {
	got := string(injectBaseHref([]byte("<html><head><title>x</title></head></html>"), "https://mail.proton.me/"))
	if !strings.Contains(got, `<head><base href="https://mail.proton.me/"><title>`) {
		t.Errorf("base not spliced inside head: %s", got)
	}
	// Case-insensitive tag match.
	got = string(injectBaseHref([]byte("<HTML><HEAD>x</HEAD>"), "https://h/"))
	if !strings.Contains(got, `<HEAD><base href="https://h/">x`) {
		t.Errorf("base not spliced after uppercase head: %s", got)
	}
	// No <head>: prepend.
	got = string(injectBaseHref([]byte("<div>x</div>"), "https://h/"))
	if !strings.HasPrefix(got, `<base href="https://h/"><div>`) {
		t.Errorf("base not prepended: %s", got)
	}
	// A multi-byte rune before <head> must not corrupt the splice: the output
	// stays valid UTF-8 and preserves both the rune and the spliced tag.
	got = string(injectBaseHref([]byte("<!--éé--><head>x</head>"), "https://h/"))
	if !strings.Contains(got, "éé") || !strings.Contains(got, `<head><base href="https://h/">x`) {
		t.Errorf("multi-byte rune corrupted splice: %s", got)
	}
}

func TestContainsFold(t *testing.T) {
	if !containsFold([]string{"email", "CAPTCHA"}, "captcha") {
		t.Error("containsFold should match case-insensitively")
	}
	if containsFold([]string{"email", "sms"}, "captcha") {
		t.Error("containsFold matched a missing method")
	}
}

// --- solveCaptchaHV ---------------------------------------------------------

func TestSolveCaptchaHV_UnsupportedMethod(t *testing.T) {
	stubBrowser(t)
	fake := proton.NewFake()
	hv := &proton.HVRequiredError{Methods: []string{"email", "sms"}}
	_, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv,
		&bytes.Buffer{}, &scriptPrompter{})
	if err == nil || !strings.Contains(err.Error(), "email") || !strings.Contains(err.Error(), "captcha is supported") {
		t.Fatalf("expected unsupported-method error naming offered methods, got %v", err)
	}
	if len(fake.CaptchaTokens) != 0 {
		t.Errorf("captcha fetched for unsupported method: %v", fake.CaptchaTokens)
	}
}

// TestSolveCaptchaHV_AutoCaptureDoesNotReadStdin is the regression test for the
// leaked-stdin-reader BLOCKER: on the browser auto-capture path, solveCaptchaHV
// must NOT read the prompter at all, so the caller's next prompt (TOTP /
// passphrase) owns stdin cleanly. It drives the auto path and then asserts (a)
// no queued line was consumed and (b) the following prompt receives its own
// input. A concurrent stdin reader would consume the queued line and fail this.
func TestSolveCaptchaHV_AutoCaptureDoesNotReadStdin(t *testing.T) {
	browserAutoSolves(t, "auto-token")
	fake := proton.NewFake()
	fake.UserID = "u1"
	fake.CaptchaHTML = []byte("<html><head></head><body>c</body></html>")
	fake.HVToken = "auto-token"
	fake.TwoFA = proton.TwoFATOTP

	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}
	// A single line queued for the NEXT prompt (the TOTP code). If solveCaptchaHV
	// read stdin it would steal this.
	p := &scriptPrompter{lines: []string{"NEXT-PROMPT-INPUT"}}

	var out bytes.Buffer
	status, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv, &out, p)
	if err != nil {
		t.Fatalf("solveCaptchaHV: %v", err)
	}
	if status.TwoFA != proton.TwoFATOTP {
		t.Errorf("status.TwoFA = %v, want TOTP (HV passed, 2FA still due)", status.TwoFA)
	}
	if len(fake.CaptchaTokens) != 1 || fake.CaptchaTokens[0] != "chal" {
		t.Errorf("Captcha called with %v, want [chal]", fake.CaptchaTokens)
	}
	if len(fake.HVTokens) != 1 || fake.HVTokens[0] != "auto-token" {
		t.Errorf("LoginWithHV called with %v, want [auto-token]", fake.HVTokens)
	}
	// The queued line was NOT consumed by the CAPTCHA solve...
	if len(p.lines) != 1 {
		t.Fatalf("solveCaptchaHV read stdin on the auto path; remaining lines %v", p.lines)
	}
	// ...and the following prompt receives its own input.
	if got, _ := p.line("next: "); got != "NEXT-PROMPT-INPUT" {
		t.Errorf("following prompt got %q, want NEXT-PROMPT-INPUT", got)
	}
	if !strings.Contains(out.String(), "http://127.0.0.1:") {
		t.Errorf("operator output missing loopback URL: %s", out.String())
	}
}

// TestSolveCaptchaHV_ManualPasteOnTimeout exercises the fallback: when auto
// capture never fires, a single foreground read of the pasted token drives the
// retry.
func TestSolveCaptchaHV_ManualPasteOnTimeout(t *testing.T) {
	stubBrowser(t)
	shortHVTimeout(t)
	fake := proton.NewFake()
	fake.UserID = "u1"
	fake.CaptchaHTML = []byte("<html><head></head><body>c</body></html>")
	fake.HVToken = "pasted-tok"

	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}
	p := &scriptPrompter{lines: []string{"pasted-tok"}}

	if _, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv,
		&bytes.Buffer{}, p); err != nil {
		t.Fatalf("solveCaptchaHV: %v", err)
	}
	if len(fake.HVTokens) != 1 || fake.HVTokens[0] != "pasted-tok" {
		t.Errorf("LoginWithHV tokens = %v, want [pasted-tok]", fake.HVTokens)
	}
}

// TestSolveCaptchaHV_TimeoutEmptyPasteAborts confirms an empty paste at the
// fallback prompt aborts with a clear rerun message rather than hanging.
func TestSolveCaptchaHV_TimeoutEmptyPasteAborts(t *testing.T) {
	stubBrowser(t)
	shortHVTimeout(t)
	fake := proton.NewFake()
	fake.CaptchaHTML = []byte("<html></html>")

	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}
	p := &scriptPrompter{lines: []string{"   "}} // whitespace-only == empty

	_, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv,
		&bytes.Buffer{}, p)
	if err == nil || !strings.Contains(err.Error(), "no verification token") {
		t.Fatalf("expected empty-token abort, got %v", err)
	}
	if len(fake.HVTokens) != 0 {
		t.Errorf("LoginWithHV should not run on empty paste: %v", fake.HVTokens)
	}
}

func TestSolveCaptchaHV_RejectedTokenReported(t *testing.T) {
	browserAutoSolves(t, "wrong-token")
	fake := proton.NewFake()
	fake.CaptchaHTML = []byte("<html></html>")
	fake.HVToken = "good-token"
	fake.HVChallenge = &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "again"}

	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "tok"}
	_, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv,
		&bytes.Buffer{}, &scriptPrompter{})
	if err == nil || !strings.Contains(err.Error(), "rejected or expired") {
		t.Fatalf("expected rejected-token error, got %v", err)
	}
}

// --- full sequence: Login → HV → CAPTCHA → LoginWithHV → TOTP → Unlock -------

// TestAuthAdd_HumanVerificationThenTOTP drives the whole HV→2FA→unlock sequence
// on the browser auto-capture path. It doubles as the end-to-end guard for the
// stdin-race BLOCKER: the ONLY queued line is the TOTP code, and it is consumed
// by interactiveAuth's TOTP prompt AFTER solveCaptchaHV returns. If solveCaptchaHV
// read stdin during the CAPTCHA solve it would steal "654321" as the HV token
// (which fake.HVToken would then reject), failing this test.
func TestAuthAdd_HumanVerificationThenTOTP(t *testing.T) {
	browserAutoSolves(t, "solved-tok")
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)

	fake := proton.NewFake()
	fake.UserID = "proton-user-hv"
	fake.Token = "rt-hv"
	fake.HVChallenge = &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "hv-tok"}
	fake.CaptchaHTML = []byte("<html><head></head><body>captcha</body></html>")
	fake.HVToken = "solved-tok"
	fake.TwoFA = proton.TwoFATOTP // reported by LoginWithHV once HV is passed
	fake.TOTPCode = "654321"
	fake.Passphrase = "mailbox-pass"

	dialer := &fakeDialer{client: fake}
	// secrets: password, then passphrase. lines: ONLY the TOTP code — the CAPTCHA
	// token comes from the (simulated) browser, never from stdin.
	p := &scriptPrompter{
		secrets: []string{"hunter2", "mailbox-pass"},
		lines:   []string{"654321"},
	}

	var out bytes.Buffer
	if err := authAdd(ctx, st, ks, dialer, p, "hv@proton.test", &out); err != nil {
		t.Fatalf("authAdd with HV: %v", err)
	}

	if len(fake.CaptchaTokens) != 1 || fake.CaptchaTokens[0] != "hv-tok" {
		t.Errorf("Captcha tokens = %v, want [hv-tok]", fake.CaptchaTokens)
	}
	if len(fake.HVTokens) != 1 || fake.HVTokens[0] != "solved-tok" {
		t.Errorf("HV tokens = %v, want [solved-tok]", fake.HVTokens)
	}
	if len(fake.TOTPSubmitted) != 1 || fake.TOTPSubmitted[0] != "654321" {
		t.Errorf("TOTP submitted = %v, want [654321]", fake.TOTPSubmitted)
	}
	m, err := st.GetMailboxByAddress(ctx, "hv@proton.test")
	if err != nil {
		t.Fatalf("mailbox not created: %v", err)
	}
	if m.State != store.MailboxStateActive {
		t.Errorf("state = %q, want active", m.State)
	}
	if m.ProtonUserID == nil || *m.ProtonUserID != "proton-user-hv" {
		t.Errorf("proton_user_id = %v, want proton-user-hv", m.ProtonUserID)
	}
	if got, _ := ks.Get(m.ID, keychain.RefreshToken); got != "rt-hv" {
		t.Errorf("stored refresh token = %q, want rt-hv", got)
	}
	if got, _ := ks.Get(m.ID, keychain.MailboxPassphrase); got != "mailbox-pass" {
		t.Errorf("stored passphrase = %q, want mailbox-pass", got)
	}
	for _, secret := range []string{"hunter2", "rt-hv", "mailbox-pass"} {
		if strings.Contains(out.String(), secret) {
			t.Errorf("secret %q leaked to output: %q", secret, out.String())
		}
	}
}
