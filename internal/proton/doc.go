// Governing: ADR-0001 (go-proton-api as Proton client).
//
// Package proton is Reduit's only entry point to the Proton Mail API. It
// wraps github.com/ProtonMail/go-proton-api so that the rest of the
// codebase imports a small, stable interface (proton.Client) and never
// the upstream package directly. This boundary lets us:
//
//   - Swap or fork the upstream library without scattering changes
//     across Reduit (ADR-0001 explicitly anticipates a fork-and-rebase
//     workaround if upstream stalls).
//   - Plug Reduit's *slog.Logger into resty's Logger interface via a
//     thin adapter (see logger.go).
//   - Persist refresh tokens through a callback the composition root
//     wires into the account service, without internal/proton needing
//     to know anything about accounts.
//
// # Pinned upstream version
//
// Reduit pins github.com/ProtonMail/go-proton-api to:
//
//	v0.4.1-0.20260424150947-6bf7f5a61eb8
//
// This is manually pinned to the tip-of-master commit current as of
// 2026-04-24, chosen so the rest of the Proton dependency cluster
// (gluon, gopenpgp, the Proton-resty fork, etc.) resolves to a
// mutually compatible set. Upstream's most recent stable tag is
// v0.4.0; the pseudo-version above satisfies the issue requirement of
// "v0.4.0 or later" and is the version transitively required by the
// rest of the Proton stack we depend on. When bumping, update this
// comment, regenerate go.sum, and re-run the package tests.
//
// # Resty replace directive
//
// The pinned go-proton-api consumes a Proton-forked resty
// (github.com/ProtonMail/resty/v2) instead of upstream
// github.com/go-resty/resty/v2. Go's module system does not propagate
// `replace` directives from sub-dependencies, so Reduit's root go.mod
// declares the same replace:
//
//	replace github.com/go-resty/resty/v2 =>
//	    github.com/ProtonMail/resty/v2 v2.0.0-20250929142426-e3dc6308c80b
//
// Drop or update this replace whenever the go-proton-api pin changes.
// If a future release of go-proton-api re-adopts upstream resty (or
// pins a tagged Proton-resty release that publishes Stream APIs),
// remove the directive at the same time.
//
// # Public surface
//
// Only the symbols documented in client.go and manager.go are part of
// Reduit's stable Proton surface. Everything else in this package is an
// implementation detail. The canonical entry points are:
//
//   - Manager.NewClient — wrap a known UID/access/refresh tuple.
//   - Manager.NewClientWithLogin — run the SRP login flow.
//   - Manager.WithAccount — hydrate a Client from an AccountSnapshot
//     (the account service satisfies AccountSnapshot once issue #10
//     lands; until then internal/proton compiles standalone).
package proton
