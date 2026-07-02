// Controlled-browser CAPTCHA solver (ADR-0021). It drives a headful, throwaway-
// profile Chrome/Chromium over the Chrome DevTools Protocol (chromedp — pure Go,
// no CGO) to render Proton's server-rendered captcha wrapper and capture the
// solved token. It is compiled into the DEFAULT build with no build tag: chromedp
// links no C, so store/sync/mcp/serve stay cross-compilable and CGO_ENABLED=0
// builds. A host without Chrome is handled at RUNTIME (a clear "Chrome required /
// use auth import" error), not excluded at build time.
//
// Why a controlled browser and not the native webview it replaced: the wrapper is
// an authenticated API endpoint (`{host}/core/v4/captcha?Token=…&ForceWebMessaging=1`)
// that Proton rejects unless the request carries an acceptable `x-pm-appversion`.
// A plain OS webview shares a persistent Proton session and offers no request-
// header injection, cookie isolation, or CSP control, so it lands on the
// authenticated mail SPA instead of the challenge. CDP gives us all three: a
// fresh user-data-dir, `Network.setExtraHTTPHeaders` to inject the app-version,
// and `Page.setBypassCSP` (ADR-0021 "Proven facts").
//
// Token capture: the wrapper (and its captcha asset iframe) postMessage the solved
// token. We inject a message listener into every document via
// `Page.addScriptToEvaluateOnNewDocument` and expose a `Runtime.addBinding`
// callback (`reduitToken`); the listener forwards a real token to the binding,
// which arrives here as a `Runtime.bindingCalled` event. The solve is heavily
// instrumented to stderr (console messages, browser log entries, failed loads,
// and every non-token postMessage) so the operator's first live run yields
// diagnostics if the message shape differs from what we expect.
//
// Governing: ADR-0021 (controlled-browser human verification), SPEC-0007 (auth
// flow, "Human verification / CAPTCHA is requested"), ADR-0001 (proton wrapper).
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/chromedp/cdproto/log"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"

	"github.com/joestump/reduit/internal/proton"
)

const (
	// captchaBindingName is the JS global (window.reduitToken) that the injected
	// listener calls with a solved token; a Runtime.bindingCalled event carrying
	// this name delivers the token to Go.
	captchaBindingName = "reduitToken"

	// captchaSolveTimeout bounds an interactive solve so a walked-away operator
	// (or a wrapper that never posts a token) does not block the CLI forever.
	captchaSolveTimeout = 5 * time.Minute
)

// errChromeRequired is returned when no Chrome/Chromium binary can be launched
// on this host. It steers a headless operator to the handoff/import path rather
// than leaving them with a raw exec error (ADR-0021 "Headless via handoff").
var errChromeRequired = errors.New(
	"no Google Chrome/Chromium found to solve the Proton CAPTCHA on this host; " +
		"install it, or provision this host with `reduit auth import` from a desktop `reduit auth handoff`")

// captchaListenerJS is injected into every document (top wrapper and its captcha
// asset iframe) BEFORE the frame's own scripts run. It forwards ONLY a real
// solved token to the bound Go callback and logs everything else, so the first
// live run tells us the actual postMessage shape if it differs from what we
// expect. Capture is defensive because Proton's exact message shape is
// unconfirmed without a live solve: accept an object payload with a string
// `token`, or a JSON string that parses to one, and ignore all other chatter
// (ADR-0021 "capture DEFENSIVELY").
const captchaListenerJS = `
window.addEventListener('message', function (e) {
  try {
    var d = e.data;
    var t = (d && typeof d === 'object' && typeof d.token === 'string')
      ? d.token
      : (typeof d === 'string'
          ? (function () { try { return JSON.parse(d).token || ''; } catch (_) { return ''; } })()
          : '');
    if (t && window.reduitToken) {
      window.reduitToken(t);
    } else {
      console.log('reduit-msg', JSON.stringify(d));
    }
  } catch (err) {
    console.log('reduit-msg-err', String(err));
  }
});
`

// solveCaptchaHV drives an interactive CAPTCHA solve after Login returned an
// *HVRequiredError, then retries the login with the solved token. On success it
// returns the AuthStatus of the retried login (which may itself report a 2FA
// challenge), so interactiveAuth falls straight through to the TOTP + passphrase
// steps. password stays live for the retry; the caller zeroes it. It never logs
// the password (only LoginWithHV receives it).
//
// Governing: ADR-0021, SPEC-0007 ("Human verification / CAPTCHA is requested").
func solveCaptchaHV(ctx context.Context, client proton.Client, address string, password []byte, hv *proton.HVRequiredError, out io.Writer, _ prompter) (proton.AuthStatus, error) {
	if !containsFold(hv.Methods, "captcha") {
		// Proton offered only methods we can't solve yet (email/sms). Follow-up:
		// email/SMS HV support is not yet implemented.
		return proton.AuthStatus{}, fmt.Errorf(
			"proton requires human verification by a method reduit cannot solve yet (offered: %s); only captcha is supported — try again later or from a less flagged network",
			strings.Join(hv.Methods, ", "))
	}

	wrapperURL := captchaWrapperURL(client.Host(), hv.Token)

	fmt.Fprintln(out, "\nProton requires a CAPTCHA. A Chrome window will open —")
	fmt.Fprintln(out, "solve it there and login continues automatically once it's solved.")

	token, err := runCaptchaBrowser(ctx, wrapperURL, client.AppVersion())
	if err != nil {
		return proton.AuthStatus{}, err
	}
	if token == "" {
		return proton.AuthStatus{}, fmt.Errorf("CAPTCHA window closed without solving; rerun 'reduit auth add' and complete the verification")
	}

	status, err := client.LoginWithHV(ctx, address, password, token)
	if err != nil {
		if _, ok := proton.AsHVRequired(err); ok {
			return proton.AuthStatus{}, fmt.Errorf("the verification token was rejected or expired; rerun the command and solve the CAPTCHA again")
		}
		return proton.AuthStatus{}, fmt.Errorf("login failed after human verification: %w", err)
	}
	return status, nil
}

// runCaptchaBrowser is the seam interactiveAuth's solve step calls. It points at
// the real chromedp solver in production; tests swap it to exercise the
// solve→LoginWithHV→2FA→unlock flow (and the closed/timeout branch) without
// launching a real browser (ADR-0021: the live solve is the operator's, so unit
// tests cover only the orchestration around it).
var runCaptchaBrowser = runChromedpCaptcha

// captchaWrapperURL builds Proton's server-rendered captcha wrapper URL from the
// client's API host and the HV token. host already carries the "/api" suffix
// (gpa.DefaultHostURL); ForceWebMessaging=1 makes the wrapper postMessage the
// solved token, which the injected listener forwards to the reduitToken binding
// (ADR-0021 "Proven facts").
func captchaWrapperURL(host, hvToken string) string {
	return strings.TrimRight(host, "/") + "/core/v4/captcha?Token=" + url.QueryEscape(hvToken) + "&ForceWebMessaging=1"
}

// runChromedpCaptcha launches a headful, throwaway-profile Chrome at wrapperURL
// with the x-pm-appversion header injected, waits for the solved token to arrive
// over the reduitToken binding, and returns it. It returns "" with no error only
// on the closed/timeout path (handled by the caller); errChromeRequired when no
// Chrome can be launched; ctx.Err() on cancellation.
func runChromedpCaptcha(ctx context.Context, wrapperURL, appVersion string) (string, error) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})).With("component", "captcha")

	// Headful over a throwaway profile. DefaultExecAllocatorOptions creates and
	// cleans up a temp user-data-dir (no cookie/session sharing — the isolation
	// the native webview lacked); we override Headless so the operator can solve.
	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", false))
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, allocOpts...)
	defer cancelAlloc()

	taskCtx, cancelTask := chromedp.NewContext(allocCtx,
		chromedp.WithErrorf(func(f string, a ...any) { logger.Debug("chromedp: " + fmt.Sprintf(f, a...)) }))
	defer cancelTask()

	runCtx, cancelRun := context.WithTimeout(taskCtx, captchaSolveTimeout)
	defer cancelRun()

	// Start the browser/target first: ListenTarget needs an attached target, and
	// a missing-Chrome failure surfaces here as the clear errChromeRequired.
	if err := chromedp.Run(runCtx); err != nil {
		if isChromeNotFound(err) {
			return "", errChromeRequired
		}
		return "", fmt.Errorf("launch captcha browser: %w", err)
	}

	tokenCh := make(chan string, 1)
	chromedp.ListenTarget(runCtx, func(ev any) {
		switch e := ev.(type) {
		case *runtime.EventBindingCalled:
			if e.Name == captchaBindingName && e.Payload != "" {
				select {
				case tokenCh <- e.Payload:
				default:
				}
			}
		case *runtime.EventConsoleAPICalled:
			// Includes our reduit-msg / reduit-msg-err lines and any page logs.
			logger.Debug("console", "type", string(e.Type), "args", consoleArgs(e.Args))
		case *log.EventEntryAdded:
			if e.Entry != nil {
				logger.Debug("browser-log", "level", string(e.Entry.Level), "text", e.Entry.Text, "url", e.Entry.URL)
			}
		case *network.EventLoadingFailed:
			logger.Debug("network-failed", "type", string(e.Type), "error", e.ErrorText, "blocked", string(e.BlockedReason))
		}
	})

	// Enable the diagnostic domains, inject the app-version header + message
	// listener, bypass CSP, register the token binding, then navigate.
	err := chromedp.Run(runCtx,
		runtime.Enable(),
		network.Enable(),
		log.Enable(),
		network.SetExtraHTTPHeaders(network.Headers{"x-pm-appversion": appVersion}),
		page.SetBypassCSP(true),
		runtime.AddBinding(captchaBindingName),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(captchaListenerJS).Do(ctx)
			return err
		}),
		chromedp.Navigate(wrapperURL),
	)
	if err != nil {
		if isChromeNotFound(err) {
			return "", errChromeRequired
		}
		return "", fmt.Errorf("load captcha wrapper: %w", err)
	}
	logger.Info("captcha window open; awaiting solve", "url", wrapperURL, "app_version", appVersion)

	select {
	case tok := <-tokenCh:
		logger.Info("captcha solved; retrying login")
		return tok, nil
	case <-runCtx.Done():
		// Parent cancellation (Ctrl-C) → surface it. Otherwise the operator closed
		// the window (Chrome exits, cancelling the context) or the timeout fired;
		// both are the caller's "closed without solving" path.
		if pErr := ctx.Err(); pErr != nil {
			return "", pErr
		}
		return "", errors.New("CAPTCHA window closed or timed out before a token arrived; rerun 'reduit auth add' and solve the verification")
	}
}

// consoleArgs renders a console.* call's arguments for the log line. Primitive
// and JSON values arrive as RemoteObject.Value (raw JSON); objects without a
// serialized value fall back to their Description.
func consoleArgs(args []*runtime.RemoteObject) string {
	parts := make([]string, 0, len(args))
	for _, a := range args {
		if a == nil {
			continue
		}
		if len(a.Value) > 0 {
			parts = append(parts, string(a.Value))
		} else if a.Description != "" {
			parts = append(parts, a.Description)
		}
	}
	return strings.Join(parts, " ")
}

// isChromeNotFound reports whether err is a browser-launch failure caused by no
// Chrome/Chromium binary being present, so the caller can return the actionable
// errChromeRequired instead of a raw exec error (ADR-0021).
func isChromeNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, exec.ErrNotFound) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "executable file not found") ||
		strings.Contains(s, "no such file") ||
		(strings.Contains(s, "chrome") && strings.Contains(s, "not found"))
}

// containsFold reports whether xs contains target, case-insensitively. Proton's
// method names are lowercase ("captcha") but we compare defensively.
func containsFold(xs []string, target string) bool {
	for _, x := range xs {
		if strings.EqualFold(strings.TrimSpace(x), target) {
			return true
		}
	}
	return false
}
