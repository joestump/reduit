// Security response headers + trusted-proxy client-IP derivation for
// the admin-UI control plane.
//
// securityHeaders wraps the whole mux so every admin-UI response
// (pages, fragments, 302s, error pages) carries the baseline browser
// hardening headers. The CSP is deliberately permissive about the
// jsdelivr CDN because base.html loads Tailwind 4 (browser-build mode),
// DaisyUI, and HTMX from cdn.jsdelivr.net at runtime; tightening that
// (moving the asset pipeline off the CDN) is tracked separately as a
// P3 issue and is explicitly out of scope here.
//
// clientIP derives the real client address from X-Forwarded-For /
// X-Real-IP, but ONLY when the immediate TCP peer (r.RemoteAddr) is a
// configured trusted proxy. Reduit runs behind a TLS-terminating
// reverse proxy (tls.disabled = true) per ADR-0011, so r.RemoteAddr is
// the proxy's address and the real client is in the forwarded header.
// We never trust the header from an untrusted peer -- an attacker who
// can reach the listener directly could otherwise spoof their logged
// source IP.
//
// Governing: ADR-0011 (reverse-proxy fronting), ADR-0009 (TLS
// frontend); issue #11.

package server

import (
	"net"
	"net/http"
	"strings"
)

// contentSecurityPolicy is the CSP applied to every admin-UI response.
//
// The directives intentionally allow https://cdn.jsdelivr.net for
// scripts and styles because base.html pulls Tailwind 4 (browser
// build), DaisyUI, and HTMX from that CDN at runtime (see base.html's
// header comment). The in-browser Tailwind compiler needs
// 'unsafe-inline' (it injects a <style> element) and 'unsafe-eval'
// (it evaluates generated CSS-in-JS); DaisyUI ships as a stylesheet
// and the page carries an inline <style> block plus inline SVG, so
// style-src also needs 'unsafe-inline'. HTMX uses inline `hx-*`
// attributes (not inline <script>), which are not constrained by
// script-src, so no script hash dance is required.
//
// font-src / style-src also allow https://rsms.me for the Inter web
// font (base.html links rsms.me/inter/inter.css, which in turn pulls
// font files from the same origin). img-src allows data: for any
// inline data-URI imagery and 'self' for /favicon.svg.
//
// frame-ancestors 'none' is the CSP-level twin of X-Frame-Options:
// DENY -- modern browsers honour the former; the header is kept for
// older agents. base-uri 'self' and form-action 'self' keep a CDN
// compromise from repointing relative URLs or exfiltrating form posts
// off-origin.
//
// Moving the asset pipeline off the CDN (which would let this collapse
// to 'self') is a separate P3 issue and deliberately NOT done here.
//
// Governing: SPEC-0005 design "Content security and CSRF"; ADR-0005
// (Tailwind/DaisyUI/HTMX via CDN in the pre-alpha MVP).
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; " +
	"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://rsms.me; " +
	"font-src 'self' https://rsms.me; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"base-uri 'self'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'"

// hstsHeader is the Strict-Transport-Security value. Two years with
// includeSubDomains is the modern baseline. preload is intentionally
// omitted: an operator who runs Reduit on a subdomain shared with
// other services should opt into the HSTS preload list deliberately,
// not have Reduit force it. The header is harmless over plain HTTP
// (the reverse proxy terminates TLS; browsers ignore HSTS received
// over http://) and the public-facing surface is always HTTPS per
// ADR-0011.
const hstsHeader = "max-age=63072000; includeSubDomains"

// securityHeaders wraps next so every response carries the baseline
// browser-hardening headers. Set on the way IN (before next writes the
// body) because once a handler calls WriteHeader the header map is
// frozen; setting them here guarantees they ride on 200s, 302s, and
// http.Error 4xx/5xx responses alike.
//
// Governing: SPEC-0005 design "Content security and CSRF"; issue #11.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("Strict-Transport-Security", hstsHeader)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// Referrer-Policy keeps the full admin-UI URL (which can carry
		// account IDs in the path) from leaking to the jsdelivr CDN or
		// any off-origin navigation.
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// clientIP returns the real client IP for r, consulting
// X-Forwarded-For / X-Real-IP ONLY when the immediate peer
// (r.RemoteAddr) is one of the configured trusted proxies. For any
// untrusted peer the header is ignored and the peer address is
// returned verbatim -- never trust a forwarded header from a host you
// did not put in front of yourself.
//
// trustedProxies is the parsed set of trusted proxy addresses (IPs and
// CIDR ranges). When empty, no proxy is trusted and r.RemoteAddr is
// always returned -- the safe default for a directly-exposed listener.
//
// X-Forwarded-For is read RIGHT-TO-LEFT. The header is an append-only
// chain ("client, proxy1, proxy2, ..."); the rightmost entry is the
// address the closest proxy observed, and each entry to the left was
// supplied by a less-trusted hop. We walk from the right, skipping
// entries that are themselves trusted proxies, and return the first
// UNTRUSTED address -- that is the real client. Taking the LEFTMOST
// entry instead would be forgeable: a client can prepend an arbitrary
// "X-Forwarded-For: 1.2.3.4" that a standards-conformant proxy
// (Caddy/Traefik/nginx default) APPENDS its own peer to rather than
// stripping, leaving the attacker's value leftmost. Right-to-left with
// a trusted-hop skip cannot be fooled that way: a forged leftmost entry
// is never reached because the real (untrusted) client address is found
// first from the right.
//
// If every XFF entry is trusted (all hops internal, no client entry
// recorded) we fall back to X-Real-IP, then to the peer address.
//
// Governing: ADR-0011 (reverse-proxy fronting), ADR-0009 (TLS
// frontend).
func clientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	remote := r.RemoteAddr
	peerHost := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		peerHost = h
	}

	if !peerTrusted(peerHost, trustedProxies) {
		return remote
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		// Walk right-to-left, returning the first untrusted address.
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if ip == "" {
				continue
			}
			if !peerTrusted(ip, trustedProxies) {
				return ip
			}
		}
		// All entries were trusted proxies -- fall through to X-Real-IP.
	}
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		return xrip
	}
	// Trusted peer but no usable forwarded header -- fall back to the peer.
	return remote
}

// ClientIPForTest exposes clientIP (with on-the-fly trusted-proxy
// parsing) to the package's external test suite. Production callers use
// s.clientIP, which holds the proxies parsed once at construction.
// Production code MUST NOT call this.
func ClientIPForTest(r *http.Request, trustedSpecs []string) string {
	nets, _ := parseTrustedProxies(trustedSpecs)
	return clientIP(r, nets)
}

// peerTrusted reports whether peerHost (a bare IP string) falls within
// any of the trusted-proxy ranges.
func peerTrusted(peerHost string, trustedProxies []*net.IPNet) bool {
	if len(trustedProxies) == 0 {
		return false
	}
	ip := net.ParseIP(peerHost)
	if ip == nil {
		return false
	}
	for _, n := range trustedProxies {
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// parseTrustedProxies converts a list of operator-supplied trusted-
// proxy specifiers (bare IPs like "10.0.0.5" or CIDR ranges like
// "10.0.0.0/8") into *net.IPNet ranges. A bare IP becomes a /32 (v4)
// or /128 (v6). Unparseable entries are skipped and returned in the
// second slice so the caller can warn the operator at boot rather than
// silently dropping a misconfigured proxy address.
//
// Governing: ADR-0011 (reverse-proxy fronting); issue #11.
func parseTrustedProxies(specs []string) (nets []*net.IPNet, invalid []string) {
	for _, raw := range specs {
		spec := strings.TrimSpace(raw)
		if spec == "" {
			continue
		}
		if !strings.Contains(spec, "/") {
			// Bare IP -- promote to a single-host CIDR.
			if ip := net.ParseIP(spec); ip != nil {
				if ip.To4() != nil {
					spec += "/32"
				} else {
					spec += "/128"
				}
			} else {
				invalid = append(invalid, raw)
				continue
			}
		}
		_, n, err := net.ParseCIDR(spec)
		if err != nil {
			invalid = append(invalid, raw)
			continue
		}
		nets = append(nets, n)
	}
	return nets, invalid
}
