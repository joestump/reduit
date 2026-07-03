// Package cli — human-verification (CAPTCHA) handling for `reduit auth`.
//
// reduit AVOIDS Proton's human-verification wall rather than solving it. Proton
// challenges the WEB client family ("web-mail@…") with a 9001 CAPTCHA on every
// fresh login, but waves the BRIDGE client family through with none. reduit
// therefore identifies as a Proton Bridge client by default (proton.DefaultApp
// Version, "macos-bridge@3.21.2"), so a normal login never sees an HV challenge.
//
// There is deliberately NO in-app CAPTCHA solver: every attempted solve path was
// falsified live (loopback iframe blocked by verify.proton.me's CSP frame-ancestors;
// a native webview whose persistent session dropped into the mail SPA; a chromedp
// verify-page capture over the native-app bridge that Proton never actually needed;
// and a press-Enter/same-token verify flow that scored 12087 because the solved
// token is not the URL token). The Bridge app-version is the real fix, so the
// solver machinery is gone.
//
// If Proton STILL returns a 9001 it means a NON-Bridge app-version was configured
// (proton.app_version / REDUIT_PROTON_APP_VERSION, or the "auto" web-client
// detection). On that path reduit returns a clear, actionable error pointing the
// operator back at the app-version knob — it does not render, embed, or capture a
// challenge.
//
// Governing: SPEC-0007 (auth flow, "Human verification / CAPTCHA is requested"),
// ADR-0021 (avoid HV via the Bridge app-version), ADR-0001 (proton wrapper).
package cli

import (
	"fmt"
	"strings"

	"github.com/joestump/reduit/internal/proton"
)

// humanVerificationError turns Proton's 9001 human-verification challenge into a
// clear, actionable error. Reaching this means a non-Bridge app-version is
// configured — the default Bridge app-version (proton.DefaultAppVersion) is waved
// through with no challenge — so the remedy is to unset or override the app-version
// rather than to solve a CAPTCHA in-app. reduit does not render, embed, or capture
// the challenge (ADR-0021, SPEC-0007). The offered methods are appended for
// diagnostics; the challenge token is never echoed.
func humanVerificationError(hv *proton.HVRequiredError) error {
	msg := "proton requires human verification (CAPTCHA). reduit avoids this by " +
		"identifying as a Proton Bridge client, which is the default; this challenge " +
		"means a non-Bridge app-version is configured. Unset proton.app_version / " +
		"REDUIT_PROTON_APP_VERSION (or set a Bridge value like " + proton.DefaultAppVersion +
		") and retry"
	if len(hv.Methods) > 0 {
		return fmt.Errorf("%s (offered methods: %s)", msg, strings.Join(hv.Methods, ", "))
	}
	return fmt.Errorf("%s", msg)
}
