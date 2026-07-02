// Package cli — human-verification (CAPTCHA) solver seam for `reduit auth`.
//
// When Proton raises its anti-abuse wall (code 9001) during login it demands
// human verification before it will run the 2FA/password exchange. go-proton-api
// cannot solve the challenge itself; it can only report it (an *HVRequiredError
// carrying the offered Methods and the challenge Token) and retry the login once
// we hand back a solved token (the HV plumbing in proton/{client,gpa_client,
// errors}.go and auth.go's interactiveAuth).
//
// The solve mechanism drives a controlled, headful Chrome (chromedp) to Proton's
// own verification page — https://verify.proton.me/?methods=<methods>&token=<token>
// — TOP-LEVEL (its CSP forbids a loopback iframe). On a completed solve Verify.tsx
// broadcasts a HUMAN_VERIFICATION_SUCCESS message carrying a NEW solved token, and
// we receive it through Proton's native-app bridge (window.AndroidInterface) — see
// captcha_browser.go. That CAPTURED token, not the URL challenge token, is what we
// retry the login with: there is no server-side binding to the URL token, so
// re-presenting the challenge always scores 12087. Capturing the payload token is
// the fix for that persistent failure.
//
// Governing: SPEC-0007 (auth flow, "Human verification / CAPTCHA is requested"),
// ADR-0021 (controlled-browser human verification), ADR-0001 (proton wrapper).
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/joestump/reduit/internal/proton"
)

// verifyBaseURL is Proton's hosted human-verification page. We render it top-level
// in a controlled Chrome and receive the solved token over the native-app bridge.
const verifyBaseURL = "https://verify.proton.me/"

// solveCaptchaHV drives Proton's human-verification flow after Login returned an
// *HVRequiredError, then retries the login with the CAPTURED token. It opens
// Proton's verify page in a controlled headful Chrome, waits for the operator to
// complete the challenge there (which broadcasts a fresh solved token over the
// native-app bridge), and retries LoginWithHV with that captured token and its
// method. On success it returns the AuthStatus of the retried login (which may
// itself report a 2FA challenge), so interactiveAuth falls straight through to the
// TOTP + passphrase steps. password stays live for the retry; the caller zeroes it
// and it is never handed to the browser layer.
//
// Two retryable outcomes are handled inside the loop (SPEC-0007 scenario
// "Verification not completed before retry"):
//
//   - Another 9001 (challenge re-issued): the captured token was rejected as an HV
//     challenge again. Adopt the FRESH challenge and re-open the window.
//   - 12087 ErrHVValidationFailed (solved but scored failed/expired/consumed): the
//     captured token is dead, so a NEW Login is issued to mint a fresh challenge,
//     and the operator solves again.
//
// Governing: SPEC-0007 ("Human verification / CAPTCHA is requested"), ADR-0021.
func solveCaptchaHV(ctx context.Context, client proton.Client, address string, password []byte, hv *proton.HVRequiredError, out io.Writer) (proton.AuthStatus, error) {
	// The operator gets an initial attempt plus two retries: a re-issued challenge
	// (9001) or a failed validation (12087, common on a first solve) shouldn't cost
	// a full command rerun before we give up.
	const maxAttempts = 3
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return proton.AuthStatus{}, err
		}

		token, method, err := runVerifyCapture(ctx, verifyURL(hv), out)
		if err != nil {
			return proton.AuthStatus{}, err
		}
		if token == "" {
			// The window was closed (or timed out) before a solved token arrived.
			return proton.AuthStatus{}, errors.New("verification window closed before it was solved; rerun 'reduit auth add' and complete the verification in the Chrome window")
		}

		// Retry with the CAPTURED payload token and method — NOT the URL challenge
		// token. This is the fix for the persistent 12087: the payload token is the
		// server-verified one, the URL token is not bound server-side.
		captured := &proton.HVRequiredError{Methods: capturedMethods(method), Token: token}
		status, err := client.LoginWithHV(ctx, address, password, captured)
		if err == nil {
			return status, nil
		}

		switch {
		case errorIsHVRequired(err, &hv):
			// Still an HV challenge: Proton re-issued a FRESH token (adopted into
			// hv by errorIsHVRequired). Re-open the window on the fresh challenge.
			if attempt >= maxAttempts {
				return proton.AuthStatus{}, fmt.Errorf("human verification did not register after %d attempts; rerun 'reduit auth add' and complete the verification in the Chrome window", maxAttempts)
			}
			fmt.Fprintln(out, "\nThat verification didn't register with Proton — opening a fresh challenge to try once more.")

		case errors.Is(err, proton.ErrHVValidationFailed):
			// Solved but rejected (12087). The token is dead; only a brand-new Login
			// yields a fresh challenge to solve.
			if attempt >= maxAttempts {
				return proton.AuthStatus{}, fmt.Errorf("human verification failed validation after %d attempts; wait a minute and rerun 'reduit auth add' (Proton scored the solves as failed)", maxAttempts)
			}
			fmt.Fprintln(out, "\nProton rejected that verification — requesting a fresh challenge to try again.")
			freshStatus, lerr := client.Login(ctx, address, password)
			if lerr == nil {
				// The fresh login sailed through with no challenge at all.
				return freshStatus, nil
			}
			if !errorIsHVRequired(lerr, &hv) {
				return proton.AuthStatus{}, fmt.Errorf("login failed requesting a fresh verification challenge: %w", lerr)
			}

		default:
			return proton.AuthStatus{}, fmt.Errorf("login failed after human verification: %w", err)
		}
	}
}

// capturedMethods normalizes the method reported in the success payload into the
// Methods slice LoginWithHV expects. Proton's payload carries the single solved
// method (e.g. "captcha"); an empty value falls back to "captcha", the only method
// reduit's controlled browser can complete.
func capturedMethods(method string) []string {
	if strings.TrimSpace(method) == "" {
		return []string{"captcha"}
	}
	return []string{method}
}

// errorIsHVRequired reports whether err is an *HVRequiredError and, when it is,
// stores the FRESH challenge into *hv so the caller re-opens the window on the
// re-issued token rather than the consumed one.
func errorIsHVRequired(err error, hv **proton.HVRequiredError) bool {
	fresh, ok := proton.AsHVRequired(err)
	if ok {
		*hv = fresh
	}
	return ok
}

// verifyURL builds Proton's hosted verification URL: the offered methods joined
// with commas, and the challenge token, appended as query parameters. All offered
// methods are passed through unfiltered — the verify page lets the operator pick
// captcha/email/sms as offered. Each method and the token are query-escaped
// defensively (Proton's method identifiers are known-safe lowercase words, but the
// token is an opaque server value).
func verifyURL(hv *proton.HVRequiredError) string {
	methods := make([]string, len(hv.Methods))
	for i, m := range hv.Methods {
		methods[i] = url.QueryEscape(m)
	}
	return fmt.Sprintf("%s?methods=%s&token=%s",
		verifyBaseURL, strings.Join(methods, ","), url.QueryEscape(hv.Token))
}
