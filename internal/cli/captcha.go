// Package cli — CAPTCHA / human-verification solver seam for `reduit auth`.
//
// When Proton raises its anti-abuse wall (code 9001) during login it demands
// human verification before it will run the 2FA/password exchange. go-proton-api
// cannot solve the CAPTCHA itself; it can only report the challenge (an
// *HVRequiredError carrying the HV token) and retry the login once we hand back
// a solved token (the HV plumbing in proton/{client,gpa_client,errors}.go and
// auth.go's interactiveAuth).
//
// The solve mechanism (ADR-0021) drives a controlled Chrome/Chromium over the
// Chrome DevTools Protocol via chromedp (captcha_chromedp.go): a headful,
// throwaway-profile browser loads Proton's server-rendered captcha wrapper with
// the x-pm-appversion header injected, and a CDP binding captures the solved
// token the wrapper postMessages. chromedp is pure Go, so the solver lives in
// the DEFAULT build with no build tag and no CGO — a headless host merely hits a
// clear "Chrome required / use auth import" error at runtime rather than being
// excluded at build time.
//
// This replaced two earlier approaches, both of which failed against a live
// account: the #126 loopback iframe (its 127.0.0.1 re-serve origin is blocked by
// Proton's frame-ancestors CSP) and the #130 native OS webview (it shares a
// persistent Proton session with no cookie isolation, header injection, or CSP
// control, so it lands on the authenticated mail SPA instead of the captcha).
// The controlled browser gives us a fresh profile, request-header injection, and
// CSP control — the three things the webview lacked (ADR-0021).
//
// Governing: ADR-0021 (controlled-browser human verification), SPEC-0007 (auth
// flow, "Human verification / CAPTCHA is requested"), ADR-0001 (proton wrapper).
package cli
