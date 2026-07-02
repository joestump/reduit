// Package cli — human-verification (CAPTCHA) solver seam for `reduit auth`.
//
// When Proton raises its anti-abuse wall (code 9001) during login it demands
// human verification before it will run the 2FA/password exchange. go-proton-api
// cannot solve the challenge itself; it can only report it (an *HVRequiredError
// carrying the offered Methods and the challenge Token) and retry the login once
// we hand the SAME challenge back (the HV plumbing in proton/{client,gpa_client,
// errors}.go and auth.go's interactiveAuth).
//
// The solve mechanism mirrors Proton Bridge's actual flow (internal/hv/hv.go):
// there is NO token to capture from a browser. We open Proton's own verification
// page — https://verify.proton.me/?methods=<methods>&token=<token> — in the
// operator's normal system browser. The operator solves the CAPTCHA there, which
// VERIFIES THE TOKEN SERVER-SIDE, and reduit then retries the login passing back
// the same {Methods, Token} it already had (proton.Client.LoginWithHV →
// NewClientWithLoginWithHVToken). No postMessage, no token capture, no embedding,
// no CSP problem — the earlier loopback-iframe, native-webview, and chromedp
// approaches were all solving a problem that does not exist.
//
// Governing: SPEC-0007 (auth flow, "Human verification / CAPTCHA is requested"),
// ADR-0001 (proton wrapper).
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"runtime"
	"strings"

	"github.com/joestump/reduit/internal/proton"
)

// verifyBaseURL is Proton's hosted human-verification page. It is the same URL
// Proton Bridge opens: the operator solves the challenge there (verifying the
// token server-side) and reduit retries the login with the same challenge.
const verifyBaseURL = "https://verify.proton.me/"

// openBrowser opens url in the operator's default system browser. It is a var so
// tests can stub it (no browser is launched under test). Best-effort: a failure
// is non-fatal because the URL is also printed for copy/paste.
var openBrowser = func(url string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd, args = "open", []string{url}
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default: // linux and other unix
		cmd, args = "xdg-open", []string{url}
	}
	return exec.Command(cmd, args...).Start()
}

// solveCaptchaHV drives Proton's human-verification flow after Login returned an
// *HVRequiredError, then retries the login with the SAME challenge. It opens
// Proton's verify page in the system browser, waits for the operator to complete
// the challenge there (which verifies the token server-side), and retries
// LoginWithHV. On success it returns the AuthStatus of the retried login (which
// may itself report a 2FA challenge), so interactiveAuth falls straight through
// to the TOTP + passphrase steps. password stays live for the retry; the caller
// zeroes it. It never logs the password (only LoginWithHV receives it).
//
// If the retry still reports human verification (the operator did not actually
// complete it, or Proton did not register it), the operator gets ONE more
// attempt before a clear give-up error.
//
// Governing: SPEC-0007 ("Human verification / CAPTCHA is requested").
func solveCaptchaHV(ctx context.Context, client proton.Client, address string, password []byte, hv *proton.HVRequiredError, out io.Writer, p prompter) (proton.AuthStatus, error) {
	// The operator gets an initial attempt plus one retry: verification not
	// registering on the first try is common (a closed tab, a missed step), so a
	// single re-prompt saves a full command rerun before we give up.
	const maxAttempts = 2
	for attempt := 1; ; attempt++ {
		if err := promptVerification(ctx, verifyURL(hv), out, p, attempt); err != nil {
			return proton.AuthStatus{}, err
		}

		status, err := client.LoginWithHV(ctx, address, password, hv)
		if err == nil {
			return status, nil
		}
		fresh, ok := proton.AsHVRequired(err)
		if !ok {
			return proton.AuthStatus{}, fmt.Errorf("login failed after human verification: %w", err)
		}
		// Still an HV challenge: the verification did not register. Proton
		// issues a FRESH token with each 9001, so the retry must solve and
		// present the new challenge — re-solving the old (consumed) one would
		// be futile.
		if attempt >= maxAttempts {
			return proton.AuthStatus{}, fmt.Errorf("human verification did not register after %d attempts; rerun 'reduit auth add' and complete the verification in your browser before pressing Enter", maxAttempts)
		}
		hv = fresh
		fmt.Fprintln(out, "\nThat verification didn't register with Proton — let's try once more.")
	}
}

// promptVerification opens (best-effort) the verify page, prints the URL for
// copy/paste, and blocks on a SINGLE foreground prompt until the operator
// confirms. It reads on the calling goroutine — no background stdin read — so it
// cannot race another prompt (an earlier concurrent-read design deadlocked). A
// "cancel" answer, or a cancelled context, aborts cleanly.
func promptVerification(ctx context.Context, verifyURL string, out io.Writer, p prompter, attempt int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if attempt == 1 {
		fmt.Fprintln(out, "\nProton requires human verification. Opening the verification page")
		fmt.Fprintln(out, "in your browser — solve the challenge there, then return here.")
	}
	fmt.Fprintf(out, "\nIf it didn't open, paste this into your browser:\n  %s\n\n", verifyURL)

	// Best-effort launch; the printed URL is the fallback when it fails or there
	// is no browser (headless host).
	_ = openBrowser(verifyURL)

	answer, err := p.line("Press Enter once you've completed the verification in your browser (or type 'cancel'): ")
	if err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(answer), "cancel") {
		return errors.New("human verification cancelled")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

// verifyURL builds Proton's hosted verification URL exactly as Proton Bridge does
// (internal/hv/hv.go): the offered methods joined with commas, and the challenge
// token, appended as query parameters. All offered methods are passed through
// unfiltered — the verify page lets the operator pick captcha/email/sms as
// offered — matching Bridge rather than forcing captcha-only. Each method and the
// token are query-escaped defensively (Proton's method identifiers are known-safe
// lowercase words, but the token is an opaque server value).
func verifyURL(hv *proton.HVRequiredError) string {
	methods := make([]string, len(hv.Methods))
	for i, m := range hv.Methods {
		methods[i] = url.QueryEscape(m)
	}
	return fmt.Sprintf("%s?methods=%s&token=%s",
		verifyBaseURL, strings.Join(methods, ","), url.QueryEscape(hv.Token))
}
