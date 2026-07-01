//go:build !webview

// Non-desktop (default/headless) CAPTCHA path. This build links no webview and
// stays pure-Go / CGO_ENABLED=0 (ADR-0021: the server/headless binary —
// store/sync/mcp/serve — must remain cross-compilable). It therefore cannot
// present Proton's CAPTCHA at all, so it fails the human-verification step with
// clear, actionable guidance instead of the old (CSP-blocked, non-working)
// loopback solver.
package cli

import (
	"context"
	"errors"
	"io"

	"github.com/joestump/reduit/internal/proton"
)

// errHVRequiresDesktop tells a headless operator how to get past Proton's 9001
// wall: either rebuild the desktop (webview) variant and run `auth add` where a
// display exists, or provision this host by importing a session handed off from
// a desktop (ADR-0021 "Desktop bootstrap" / "Headless via handoff").
var errHVRequiresDesktop = errors.New(
	"human verification (CAPTCHA) requires the desktop build; rebuild with `-tags webview` and run `reduit auth add` on a desktop, " +
		"or provision this host with `reduit auth import` from a desktop `reduit auth handoff`")

// solveCaptchaHV is the non-webview build's CAPTCHA entry. It matches the
// webview build's signature (so interactiveAuth compiles either way) but cannot
// solve the challenge on a headless host; it returns errHVRequiresDesktop. The
// unused parameters mirror the webview solver's inputs (ADR-0021).
func solveCaptchaHV(_ context.Context, _ proton.Client, _ string, _ []byte, _ *proton.HVRequiredError, _ io.Writer, _ prompter) (proton.AuthStatus, error) {
	return proton.AuthStatus{}, errHVRequiresDesktop
}
