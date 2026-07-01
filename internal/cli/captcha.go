// Package cli — CAPTCHA / human-verification solver for `reduit auth`.
//
// When Proton raises its anti-abuse wall (code 9001) during login it demands
// human verification before it will run the 2FA/password exchange. go-proton-api
// cannot solve the CAPTCHA itself; it can only fetch the challenge HTML and
// retry the login once we hand back a solved token. This file bridges that gap:
// it stands up a loopback web server that re-serves Proton's CAPTCHA page from
// our own origin (so Proton's X-Frame-Options can't block the iframe), opens the
// operator's browser to it, listens for the solved token the CAPTCHA
// postMessages back, and retries the login. A manual paste path is always
// available as a fallback because the exact postMessage shape is the one thing
// we cannot verify without a live solve.
//
// Governing: SPEC-0007 (auth flow, "Human verification / CAPTCHA is requested"),
// ADR-0001 (proton wrapper).
package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/joestump/reduit/internal/proton"
)

// captchaBaseHost is injected as <base href> into Proton's CAPTCHA HTML so its
// relative assets (scripts, images) resolve against Proton's origin even though
// we serve the page bytes from our loopback origin. A var seam keeps tests from
// depending on a live Proton host.
var captchaBaseHost = "https://mail.proton.me/"

// hvCaptchaTimeout bounds how long solveCaptchaHV waits for a solved token
// before giving up and telling the operator to rerun. A var so tests shorten it.
var hvCaptchaTimeout = 5 * time.Minute

// openBrowser opens url in the operator's default browser. It is a var seam so
// tests never launch a browser, and it is best-effort: on failure (or an
// unsupported platform) the caller falls back to printing the URL, which is
// always done regardless.
var openBrowser = func(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "linux":
		return exec.Command("xdg-open", url).Start()
	default:
		return fmt.Errorf("no browser opener for platform %q", runtime.GOOS)
	}
}

// solveCaptchaHV drives an interactive CAPTCHA solve after Login returned an
// *HVRequiredError, and retries the login with the solved token. On success it
// returns the AuthStatus of the retried login (which may itself report a 2FA
// challenge), so interactiveAuth can fall straight through to the TOTP +
// passphrase steps. password stays live for the retry; the caller zeroes it.
func solveCaptchaHV(ctx context.Context, client proton.Client, address string, password []byte, hv *proton.HVRequiredError, out io.Writer, p prompter) (proton.AuthStatus, error) {
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

	tokenCh := make(chan string, 1)
	srv, url, err := startCaptchaServer(html, tokenCh)
	if err != nil {
		return proton.AuthStatus{}, err
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	fmt.Fprintln(out, "\nProton requires a CAPTCHA to continue.")
	if berr := openBrowser(url); berr != nil {
		fmt.Fprintln(out, "Could not open a browser automatically.")
	}
	fmt.Fprintf(out, "If your browser didn't open, visit:\n  %s\n", url)
	fmt.Fprintln(out, "Solve the CAPTCHA there; login continues automatically once it's solved.")

	// Wait for the browser to auto-capture the solved token. This wait
	// deliberately does NOT read stdin. A background stdin reader would still be
	// parked in a blocking read when this function returns on the auto path, and
	// would then race — and steal input from — interactiveAuth's very next
	// prompt (the TOTP code or the mailbox passphrase). Keeping stdin untouched
	// here guarantees exactly one reader of the terminal at a time: the manual
	// fallback below runs strictly sequentially, only after this wait gives up.
	timer := time.NewTimer(hvCaptchaTimeout)
	defer timer.Stop()

	var token string
	select {
	case token = <-tokenCh:
	case <-ctx.Done():
		return proton.AuthStatus{}, ctx.Err()
	case <-timer.C:
		// Auto-capture never fired (e.g. an unexpected postMessage shape). Fall
		// back to a SINGLE foreground read of the token the browser shows in its
		// copy box. This is the only stdin read on this path, and it completes
		// before control returns to the next prompt, so nothing races stdin.
		fmt.Fprintln(out, "\nThe CAPTCHA did not continue automatically.")
		line, perr := p.line("Paste the token shown in your browser (or press Enter to abort): ")
		if perr != nil {
			return proton.AuthStatus{}, perr
		}
		token = strings.TrimSpace(line)
		if token == "" {
			return proton.AuthStatus{}, fmt.Errorf("no verification token provided; rerun the command and solve the CAPTCHA again")
		}
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

// startCaptchaServer binds a loopback listener on a random port and serves the
// CAPTCHA wrapper/challenge/token routes. It returns the server (for Shutdown),
// the operator-facing root URL, and any bind error.
func startCaptchaServer(html []byte, tokenCh chan<- string) (*http.Server, string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("start loopback server: %w", err)
	}
	srv := &http.Server{Handler: newCaptchaHandler(html, tokenCh)}
	go func() { _ = srv.Serve(ln) }()
	return srv, fmt.Sprintf("http://%s/", ln.Addr().String()), nil
}

// newCaptchaHandler builds the loopback mux. It is factored out of
// startCaptchaServer so the routes are testable with httptest without binding a
// socket or opening a browser.
//
//	/         → wrapper page: iframes /captcha, listens for the solved token via
//	            postMessage, POSTs it to /token, and always displays it for a
//	            manual copy fallback.
//	/captcha  → Proton's CAPTCHA bytes with an injected <base href> so its
//	            relative assets resolve. Served from our origin so Proton's
//	            X-Frame-Options can't block the same-origin iframe.
//	/token    → captures the token onto tokenCh (non-blocking) and tells the
//	            operator they can close the tab.
func newCaptchaHandler(html []byte, tokenCh chan<- string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/captcha", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(injectBaseHref(html, captchaBaseHost))
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// The token arrives in the POST body (not the query string) so it never
		// lands in an access log or the browser history.
		_ = r.ParseForm()
		if tok := strings.TrimSpace(r.PostForm.Get("token")); tok != "" {
			// Non-blocking: the buffered channel takes the first token; later
			// duplicate messages are dropped rather than blocking the handler.
			select {
			case tokenCh <- tok:
			default:
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, captchaDonePage)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, captchaWrapperPage)
	})

	return mux
}

// injectBaseHref inserts a <base href="host"> so the CAPTCHA's relative asset
// URLs resolve against Proton's origin. It splices the tag just inside <head>
// when present, otherwise prepends it. The offset is computed on the ORIGINAL
// bytes (not a lower-cased copy) so a non-ASCII byte before <head> cannot shift
// the splice point and cut a multi-byte rune in half.
func injectBaseHref(html []byte, host string) []byte {
	base := fmt.Sprintf("<base href=%q>", host)
	s := string(html)
	if i := indexHeadOpen(s); i >= 0 {
		at := i + len("<head>")
		return []byte(s[:at] + base + s[at:])
	}
	return []byte(base + s)
}

// indexHeadOpen returns the byte offset of the first "<head>" tag in s,
// case-insensitively, or -1. It scans the original bytes so the returned offset
// is always a valid index into s (the tag is ASCII, so any match is on a rune
// boundary). strings.EqualFold on a mid-rune byte slice never panics — it simply
// fails to match — so the scan is safe on arbitrary input.
func indexHeadOpen(s string) int {
	const tag = "<head>"
	for i := 0; i+len(tag) <= len(s); i++ {
		if strings.EqualFold(s[i:i+len(tag)], tag) {
			return i
		}
	}
	return -1
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

// captchaWrapperPage iframes the CAPTCHA and captures the solved token.
//
// The postMessage capture is deliberately permissive because Proton's exact
// message shape can only be confirmed by a live solve: Proton posts messages
// like {type:'pm_captcha', token:'…'} for the solved token and
// {type:'pm_captcha', height:N} for layout. We accept ANY message whose data
// carries a non-empty string `token` (object form, or a JSON string), ignore
// height/load/unknown messages, log everything to a visible panel for
// diagnosis, and ALWAYS surface the captured token in a copy box so the
// operator can paste it manually if the auto-continue fetch does not fire.
const captchaWrapperPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>reduit — Proton CAPTCHA</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; margin: 2rem auto; max-width: 640px; padding: 0 1rem; color: #222; }
  h1 { font-size: 1.25rem; }
  iframe { border: 1px solid #ccc; border-radius: 6px; width: 100%; height: 600px; }
  #reduit-token-box { display: none; margin-top: 1rem; padding: .75rem 1rem; background: #f4f6f8; border-radius: 6px; }
  #reduit-token { font-family: ui-monospace, monospace; word-break: break-all; user-select: all; }
  #reduit-status { margin-top: 1rem; font-weight: 600; }
  #reduit-log { margin-top: 1rem; font-size: .75rem; color: #888; white-space: pre-wrap; max-height: 8rem; overflow: auto; }
</style>
</head>
<body>
<h1>Complete the Proton CAPTCHA</h1>
<p>Solve the challenge below. Login continues in your terminal automatically once it's solved.</p>
<iframe src="/captcha" title="Proton CAPTCHA"></iframe>
<div id="reduit-status"></div>
<div id="reduit-token-box">
  <p>Verification token — copy this into your terminal if login didn't continue automatically:</p>
  <div id="reduit-token"></div>
</div>
<div id="reduit-log"></div>
<script>
(function () {
  var sent = false;
  function log(m) {
    var el = document.getElementById('reduit-log');
    el.textContent += m + "\n";
  }
  function status(m) { document.getElementById('reduit-status').textContent = m; }
  function showToken(t) {
    document.getElementById('reduit-token').textContent = t;
    document.getElementById('reduit-token-box').style.display = 'block';
  }
  // Extract a non-empty string token from a message payload, tolerating both
  // object payloads and JSON-string payloads. Returns "" when there is none.
  function extractToken(data) {
    if (data == null) return "";
    if (typeof data === "string") {
      try { var o = JSON.parse(data); if (o && typeof o.token === "string") return o.token; }
      catch (e) { /* not JSON; not a token message */ }
      return "";
    }
    if (typeof data === "object" && typeof data.token === "string") return data.token;
    return "";
  }
  window.addEventListener('message', function (ev) {
    var token = extractToken(ev.data);
    if (token) {
      showToken(token);
      status('CAPTCHA solved — you can close this tab.');
      if (!sent) {
        sent = true;
        fetch('/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'token=' + encodeURIComponent(token)
        }).catch(function () {});
      }
      return;
    }
    // Not a token message (height update, load ping, or unknown): log it so a
    // failed live solve can be diagnosed, and keep listening.
    try { log('message: ' + JSON.stringify(ev.data)); }
    catch (e) { log('message: [unserializable payload]'); }
  });
})();
</script>
</body>
</html>`

// captchaDonePage is shown after /token captures the token.
const captchaDonePage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>reduit</title>
<style>body{font-family:-apple-system,system-ui,sans-serif;margin:3rem auto;max-width:480px;text-align:center;color:#222}</style>
</head><body>
<h1>Verification received</h1>
<p>You can close this tab and return to your terminal.</p>
</body></html>`
