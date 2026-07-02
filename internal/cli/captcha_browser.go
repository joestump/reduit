// Controlled-browser human-verification capture (ADR-0021). It drives a headful,
// throwaway-profile Chrome/Chromium over the Chrome DevTools Protocol (chromedp —
// pure Go, no CGO) to render Proton's own verification page top-level and receive
// the solved token through Proton's NATIVE-APP bridge channel. It is compiled into
// the DEFAULT build with no build tag: chromedp links no C, so store/sync/mcp/serve
// stay cross-compilable and CGO_ENABLED=0 builds. A host without Chrome is handled
// at RUNTIME (a clear "Chrome required / use auth import" error), not excluded at
// build time.
//
// Why the native-app bridge and not a postMessage listener: on solve,
// verify.proton.me's Verify.tsx broadcasts a HUMAN_VERIFICATION_SUCCESS message
// whose payload carries a NEW solved token (NOT the URL challenge token — there is
// no server-side binding to the URL token, which is why re-presenting the challenge
// always scores 12087). WebClients' broadcast.getClient() dispatches that message
// over `window.AndroidInterface.dispatch(JSON.stringify(message))` when
// AndroidInterface is defined, and only falls back to `window.parent.postMessage`
// on the web. verify.proton.me's CSP (`frame-ancestors …proton.me`) forbids a
// loopback iframe, so postMessage-to-parent is unavailable to us anyway. We render
// the page TOP-LEVEL and, BEFORE its scripts run, define window.AndroidInterface so
// getClient() picks the 'android' client and hands us the solved payload directly.
//
// Token capture: Page.addScriptToEvaluateOnNewDocument installs an AndroidInterface
// whose dispatch() forwards the (already JSON-stringified) message to a
// Runtime.addBinding callback (`reduitToken`); the message arrives here as a
// Runtime.bindingCalled event, is JSON-decoded, and — when it is a
// HUMAN_VERIFICATION_SUCCESS with a non-empty payload token — delivered on a
// buffered channel. Every other broadcast type (NOTIFICATION/RESIZE/LOADED/CLOSE/
// ERROR) is logged to stderr for diagnostics, and CLOSE is treated as the operator
// closing the flow.
//
// Governing: ADR-0021 (controlled-browser human verification), SPEC-0007 (auth
// flow, "Human verification / CAPTCHA is requested"), ADR-0001 (proton wrapper).
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/chromedp/cdproto/log"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

const (
	// verifyBindingName is the JS global (window.reduitToken) that the injected
	// AndroidInterface.dispatch calls with each broadcast message; a
	// Runtime.bindingCalled event carrying this name delivers the raw message
	// string to Go.
	verifyBindingName = "reduitToken"

	// verifySolveTimeout bounds an interactive solve so a walked-away operator (or
	// a page that never broadcasts a success) does not block the CLI forever.
	verifySolveTimeout = 5 * time.Minute

	// hvSuccessType is the broadcast message type Verify.tsx emits on a completed
	// solve; its payload carries the NEW solved token we retry the login with.
	hvSuccessType = "HUMAN_VERIFICATION_SUCCESS"
	// hvCloseType is the broadcast message type emitted when the operator dismisses
	// the verification UI; we treat it as an operator-closed abort.
	hvCloseType = "CLOSE"
)

// errChromeRequired is returned when no Chrome/Chromium binary can be launched on
// this host. It steers a headless operator to the handoff/import path rather than
// leaving them with a raw exec error (ADR-0021 "Headless via handoff").
var errChromeRequired = errors.New(
	"no Google Chrome/Chromium found to solve the Proton verification on this host; " +
		"install Google Chrome/Chromium, or provision this host via `reduit auth import` " +
		"from a desktop `reduit auth handoff`")

// verifyBridgeJS is injected into every document at verify.proton.me BEFORE the
// page's own scripts run. It defines window.AndroidInterface so WebClients'
// broadcast.getClient() selects the 'android' native-app client and routes every
// broadcast — crucially the HUMAN_VERIFICATION_SUCCESS message with the solved
// token — through dispatch(). dispatch forwards the already-JSON-stringified
// message verbatim to the bound Go callback (ADR-0021 "native-app bridge").
const verifyBridgeJS = `window.AndroidInterface = { dispatch: function(s) { try { window.reduitToken(String(s)); } catch (e) {} } };`

// hvBroadcast is the shape of a WebClients broadcast message as delivered over the
// native-app bridge (broadcast.ts serializes it with JSON.stringify). Only the
// success payload's Token/Type are load-bearing; other types are logged.
type hvBroadcast struct {
	Type    string `json:"type"`
	Payload struct {
		Token string `json:"token"`
		Type  string `json:"type"`
	} `json:"payload"`
}

// runVerifyCapture is the seam solveCaptchaHV's solve step calls. It points at the
// real chromedp bridge capture in production; tests swap it to exercise the
// solve→LoginWithHV→2FA→unlock flow (and the closed/timeout/chrome-missing
// branches) without launching a real browser. It returns the CAPTURED token and
// its method type (from the HUMAN_VERIFICATION_SUCCESS payload — NOT the URL
// challenge token), which the caller retries the login with.
var runVerifyCapture = runChromedpVerify

// runChromedpVerify launches a headful, throwaway-profile Chrome at verifyURL,
// installs the AndroidInterface bridge before the page loads, and waits for the
// HUMAN_VERIFICATION_SUCCESS broadcast. It returns the payload's token and type on
// success; ("", "", nil) on the operator-closed / timeout path (handled by the
// caller); errChromeRequired when no Chrome can be launched; ctx.Err() on parent
// cancellation. It never receives or logs the password.
func runChromedpVerify(ctx context.Context, verifyURL string, out io.Writer) (token, method string, err error) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})).With("component", "verify")

	fmt.Fprintln(out, "\nA Chrome window will open — solve the verification there;")
	fmt.Fprintln(out, "login continues automatically once it's solved.")

	// Headful over a throwaway profile. DefaultExecAllocatorOptions creates and
	// cleans up a temp user-data-dir (no cookie/session sharing); we override
	// Headless so the operator can solve. Cancels are LIFO (deferred in reverse
	// order) so the browser is torn down cleanly on every path.
	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", false))
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, allocOpts...)
	defer cancelAlloc()

	taskCtx, cancelTask := chromedp.NewContext(allocCtx,
		chromedp.WithErrorf(func(f string, a ...any) { logger.Debug("chromedp: " + fmt.Sprintf(f, a...)) }))
	defer cancelTask()

	runCtx, cancelRun := context.WithTimeout(taskCtx, verifySolveTimeout)
	defer cancelRun()

	// Start the browser/target first: ListenTarget needs an attached target, and a
	// missing-Chrome failure surfaces here as the clear errChromeRequired.
	if rerr := chromedp.Run(runCtx); rerr != nil {
		if isChromeNotFound(rerr) {
			return "", "", errChromeRequired
		}
		return "", "", fmt.Errorf("launch verification browser: %w", rerr)
	}

	// resultCh carries the first captured success; closedCh signals an operator
	// CLOSE broadcast. Both are buffered size 1 so the listener never blocks.
	type capture struct{ token, method string }
	resultCh := make(chan capture, 1)
	closedCh := make(chan struct{}, 1)
	chromedp.ListenTarget(runCtx, func(ev any) {
		switch e := ev.(type) {
		case *runtime.EventBindingCalled:
			if e.Name != verifyBindingName {
				return
			}
			// chromedp delivers the binding arg as a Go string already (the JS
			// String(s) we passed). Verify.tsx stringified the whole message, so
			// e.Payload IS the message JSON — unmarshal it directly.
			var msg hvBroadcast
			if derr := json.Unmarshal([]byte(e.Payload), &msg); derr != nil {
				logger.Debug("bridge: undecodable message", "raw", e.Payload, "err", derr)
				return
			}
			switch msg.Type {
			case hvSuccessType:
				if msg.Payload.Token == "" {
					logger.Debug("bridge: success without token", "raw", e.Payload)
					return
				}
				select {
				case resultCh <- capture{token: msg.Payload.Token, method: msg.Payload.Type}:
				default: // first success wins; ignore any repeat
				}
			case hvCloseType:
				select {
				case closedCh <- struct{}{}:
				default:
				}
			default:
				// NOTIFICATION / RESIZE / LOADED / ERROR and anything else: keep it
				// for diagnostics on the operator's first live run.
				logger.Debug("bridge: message", "type", msg.Type)
			}
		case *runtime.EventConsoleAPICalled:
			logger.Debug("console", "type", string(e.Type), "args", consoleArgs(e.Args))
		case *log.EventEntryAdded:
			if e.Entry != nil {
				logger.Debug("browser-log", "level", string(e.Entry.Level), "text", e.Entry.Text, "url", e.Entry.URL)
			}
		case *network.EventLoadingFailed:
			logger.Debug("network-failed", "type", string(e.Type), "error", e.ErrorText, "blocked", string(e.BlockedReason))
		}
	})

	// Enable the diagnostic domains, register the token binding, install the
	// AndroidInterface bridge so it runs before the page's own scripts, then
	// navigate top-level to the verify page.
	if rerr := chromedp.Run(runCtx,
		runtime.Enable(),
		network.Enable(),
		log.Enable(),
		runtime.AddBinding(verifyBindingName),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(verifyBridgeJS).Do(ctx)
			return err
		}),
		chromedp.Navigate(verifyURL),
	); rerr != nil {
		if isChromeNotFound(rerr) {
			return "", "", errChromeRequired
		}
		return "", "", fmt.Errorf("load verification page: %w", rerr)
	}
	logger.Info("verification window open; awaiting solve", "url", verifyURL)

	select {
	case c := <-resultCh:
		logger.Info("verification solved; retrying login", "method", c.method)
		return c.token, c.method, nil
	case <-closedCh:
		// Operator dismissed the verification UI (Proton's own CLOSE broadcast).
		return "", "", nil
	case <-runCtx.Done():
		// Parent cancellation (Ctrl-C) → surface it. Otherwise the operator closed
		// the window (Chrome exits, cancelling the context) or the 5-min timeout
		// fired; both are the caller's "closed without solving" path.
		if pErr := ctx.Err(); pErr != nil {
			return "", "", pErr
		}
		return "", "", nil
	}
}

// consoleArgs renders a console.* call's arguments for the log line. Primitive and
// JSON values arrive as RemoteObject.Value (raw JSON); objects without a serialized
// value fall back to their Description.
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
