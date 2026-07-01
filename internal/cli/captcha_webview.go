//go:build webview

// Desktop CAPTCHA solver: a native OS webview (WebKit on macOS, WebKitGTK on
// Linux, WebView2 on Windows) that renders Proton's CAPTCHA and captures the
// solved token. This is the ADR-0021 replacement for the #126 loopback iframe,
// which was blocked by Proton's `frame-ancestors` CSP. This file links CGO and
// is compiled ONLY under `-tags webview`; the default/headless build uses
// captcha_nowebview.go and stays pure-Go (ADR-0021: CGO is contained behind the
// build tag so store/sync/mcp/serve remain cross-compilable).
//
// Why a top-level navigation (not an iframe): Proton's captcha assets set a
// `frame-ancestors` CSP that permits embedding only from a proton.me origin, so
// the widget renders only as a top-level page (or inside proton.me). We navigate
// the webview's top-level frame directly at the captcha asset URL; the solved
// token is delivered by `window.postMessage`, which we intercept with an
// injected listener and hand back over a bound Go callback.
//
// Governing: ADR-0021 (native-webview human verification), SPEC-0007 (auth
// flow), ADR-0001 (proton wrapper).
package cli

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"runtime"
	"strings"

	webview "github.com/webview/webview_go"

	"github.com/joestump/reduit/internal/proton"
)

// captchaAssetBase constructs the fallback captcha asset URL when it cannot be
// parsed out of the challenge HTML. A live 9001 serves the widget from
// `https://mail.proton.me/captcha/v1/assets/?purpose=login&token=<hvToken>`
// (ADR-0021 "Proven facts"). A var seam keeps the constructor testable without a
// live host.
var captchaAssetBase = "https://mail.proton.me/captcha/v1/assets/"

// assetURLRe finds Proton's captcha asset URL inside the challenge HTML that
// client.Captcha returns. Proton's page references its own
// `…/captcha/v1/assets/?…` endpoint; we navigate the webview there top-level so
// the `frame-ancestors` CSP is satisfied. The class is deliberately broad
// (anything up to a quote/whitespace) so a query-string change upstream does not
// break the match.
var assetURLRe = regexp.MustCompile(`https?://[^"'\s>]*captcha/v1/assets/[^"'\s>]*`)

// captchaAssetURL returns the URL to render in the webview: the asset URL parsed
// from Proton's challenge HTML when present, otherwise one constructed from the
// HV token (ADR-0021). The parsed form is preferred because it carries whatever
// query parameters Proton minted for this challenge verbatim.
func captchaAssetURL(html []byte, hvToken string) string {
	if m := assetURLRe.Find(html); m != nil {
		return string(m)
	}
	return captchaAssetBase + "?purpose=login&token=" + url.QueryEscape(hvToken)
}

// webviewCaptchaJS is injected before Proton's page scripts run (webview Init
// guarantees execution before window.onload). It listens for the solved-token
// postMessage and forwards ONLY a real token to the bound Go callback. Capture
// is defensive because Proton's exact message shape is unconfirmed without a
// live solve: we accept an object payload with a string `token`, or a JSON
// string that parses to one, and ignore everything else — the observed
// {"type":"pm_height",…} / {"type":"PassClientScriptReady"} chatter and any
// unknown messages (ADR-0021 "capture DEFENSIVELY").
const webviewCaptchaJS = `
window.addEventListener('message', function (e) {
  var d = e.data;
  var t = (d && typeof d === 'object' && typeof d.token === 'string')
    ? d.token
    : (typeof d === 'string'
        ? (function () { try { var o = JSON.parse(d); return (o && o.token) || ''; } catch (_) { return ''; } })()
        : '');
  if (t) { window.__reduitToken(t); }
});
`

// solveCaptchaHV drives an interactive CAPTCHA solve after Login returned an
// *HVRequiredError, then retries the login with the solved token. On success it
// returns the AuthStatus of the retried login (which may itself report a 2FA
// challenge), so interactiveAuth falls straight through to the TOTP + passphrase
// steps. password stays live for the retry; the caller zeroes it. This is the
// desktop (webview) implementation; captcha_nowebview.go is the headless stub.
//
// Governing: ADR-0021, SPEC-0007 ("Human verification / CAPTCHA is requested").
func solveCaptchaHV(ctx context.Context, client proton.Client, address string, password []byte, hv *proton.HVRequiredError, out io.Writer, _ prompter) (proton.AuthStatus, error) {
	if !containsFold(hv.Methods, "captcha") {
		// Proton offered only methods we can't solve yet (email/sms). Follow-up:
		// email/SMS HV support is not yet implemented (#126 note).
		return proton.AuthStatus{}, fmt.Errorf(
			"proton requires human verification by a method reduit cannot solve yet (offered: %s); only captcha is supported — try again later or from a less flagged network",
			strings.Join(hv.Methods, ", "))
	}

	html, err := client.Captcha(ctx, hv.Token)
	if err != nil {
		return proton.AuthStatus{}, fmt.Errorf("fetch captcha challenge: %w", err)
	}
	assetURL := captchaAssetURL(html, hv.Token)

	fmt.Fprintln(out, "\nProton requires a CAPTCHA. A verification window will open —")
	fmt.Fprintln(out, "solve it there and login continues automatically once it's solved.")

	token, err := runWebviewCaptcha(ctx, assetURL)
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

// runWebviewCaptcha opens the native webview at assetURL, injects the token
// listener, and blocks until either the solved token arrives (the bound callback
// terminates the loop) or the operator closes the window (Run returns with no
// token). It returns the captured token, or "" when the window was closed
// unsolved. ctx cancellation terminates the window and surfaces ctx.Err().
//
// The webview must own the main OS thread on macOS (Cocoa requirement), so this
// locks the goroutine to its thread for the duration of Run (ADR-0021).
func runWebviewCaptcha(ctx context.Context, assetURL string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("reduit — Proton CAPTCHA")
	w.SetSize(500, 650, webview.HintNone)

	// token is written by the bound callback and read after Run returns. Both
	// happen on this locked OS thread (the callback runs inside Run's event loop,
	// the read strictly after Run returns), so no synchronization is needed.
	var token string
	if err := w.Bind("__reduitToken", func(tok string) {
		if token == "" {
			token = tok
		}
		w.Terminate() // stop the loop; Run returns and we retry the login.
	}); err != nil {
		return "", fmt.Errorf("bind webview token callback: %w", err)
	}

	// Cancel the window if ctx is done (e.g. Ctrl-C). Terminate is documented safe
	// to call from a background thread. The stop channel unblocks this goroutine
	// once Run returns normally so it never leaks.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			w.Terminate()
		case <-stop:
		}
	}()

	w.Init(webviewCaptchaJS)
	w.Navigate(assetURL)
	w.Run()

	// Join the watcher BEFORE the deferred w.Destroy() runs: close(stop) releases
	// it if it was still parked, and <-done guarantees any ctx-triggered
	// w.Terminate() has fully returned first. Otherwise a Ctrl-C landing in the
	// instant Run() returns could race Terminate against Destroy on the same
	// webview_t (use-after-free).
	close(stop)
	<-done

	if err := ctx.Err(); err != nil {
		return "", err
	}
	return token, nil
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
