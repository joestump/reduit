// Package cli — CAPTCHA / human-verification solver seam for `reduit auth`.
//
// When Proton raises its anti-abuse wall (code 9001) during login it demands
// human verification before it will run the 2FA/password exchange. go-proton-api
// cannot solve the CAPTCHA itself; it can only fetch the challenge HTML and
// retry the login once we hand back a solved token (the HV plumbing in
// proton/{client,gpa_client,errors}.go and auth.go's interactiveAuth).
//
// The *solve mechanism* is build-tag selected (ADR-0021): the desktop build
// (`//go:build webview`, captcha_webview.go) renders Proton's CAPTCHA in a
// native OS webview and captures the postMessage token; the default/headless
// build (`//go:build !webview`, captcha_nowebview.go) cannot present a CAPTCHA
// and returns a clear "use the desktop build / auth import" error. Both expose
// the same `solveCaptchaHV` entry that interactiveAuth calls, so the login/HV
// plumbing is identical either way.
//
// The prior #126 loopback iframe solver was removed here: its 127.0.0.1 re-serve
// origin is blocked by Proton's `frame-ancestors` CSP and never worked against a
// real account (ADR-0021, "Loopback iframe / reverse proxy" — rejected).
//
// Governing: ADR-0021 (native-webview human verification), SPEC-0007 (auth
// flow, "Human verification / CAPTCHA is requested"), ADR-0001 (proton wrapper).
package cli
