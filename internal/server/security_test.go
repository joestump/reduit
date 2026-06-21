// Tests for the security-header middleware and the trusted-proxy
// client-IP derivation.
//
// Governing: SPEC-0005 design "Content security and CSRF" (headers),
// ADR-0011 (reverse-proxy fronting), ADR-0009 (TLS frontend); issue #11.

package server_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/joestump/reduit/internal/server"
)

// TestSecurityHeaders_PresentOnEveryResponse asserts the baseline
// browser-hardening headers ride on admin-UI responses, including
// allowlisted routes (/healthz) and gate-issued 302s (an unauth GET to
// a protected route). Governing: SPEC-0005 REQ "Content security and
// CSRF".
func TestSecurityHeaders_PresentOnEveryResponse(t *testing.T) {
	t.Parallel()
	baseURL, _, _ := newTestServer(t, nil)
	c := newClient(t)

	// /healthz: allowlisted 200. /accounts: unauth => gate 302. Both
	// must carry the headers.
	for _, path := range []string{"/healthz", "/accounts"} {
		resp, err := c.Get(baseURL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()

		h := resp.Header
		checks := map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
		}
		for k, want := range checks {
			if got := h.Get(k); got != want {
				t.Errorf("%s: header %s = %q, want %q", path, k, got, want)
			}
		}
		if csp := h.Get("Content-Security-Policy"); csp == "" {
			t.Errorf("%s: missing Content-Security-Policy", path)
		} else {
			// The CSP is same-origin-only now that the frontend assets are
			// embedded and served from /static/vendor (ADR-0005): it MUST
			// carry frame-ancestors 'none' and MUST NOT allowlist any of
			// the formerly-trusted CDN hosts.
			if !containsAll(csp, "default-src 'self'", "frame-ancestors 'none'") {
				t.Errorf("%s: CSP missing required directive: %q", path, csp)
			}
			for _, banned := range []string{"cdn.jsdelivr.net", "rsms.me", "unsafe-eval"} {
				if containsAll(csp, banned) {
					t.Errorf("%s: CSP must not contain %q after asset vendoring: %q", path, banned, csp)
				}
			}
		}
		if hsts := h.Get("Strict-Transport-Security"); hsts == "" {
			t.Errorf("%s: missing Strict-Transport-Security", path)
		}
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// TestClientIP_TrustedProxyUsesXFF asserts that the X-Forwarded-For
// header is honoured only when the immediate peer is a trusted proxy,
// and is read right-to-left (skipping trusted hops) so a forged leftmost
// entry cannot win. Governing: ADR-0011 (reverse-proxy fronting),
// ADR-0009 (TLS frontend).
func TestClientIP_TrustedProxyUsesXFF(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		trusted  []string
		remote   string
		xff      string
		xrealip  string
		wantHost string // substring the result must contain
	}{
		{
			name:     "trusted proxy: XFF used",
			trusted:  []string{"10.0.0.1"},
			remote:   "10.0.0.1:5555",
			xff:      "203.0.113.7",
			wantHost: "203.0.113.7",
		},
		{
			name:     "trusted proxy CIDR: XFF used",
			trusted:  []string{"10.0.0.0/8"},
			remote:   "10.4.5.6:5555",
			xff:      "203.0.113.9, 10.4.5.6",
			wantHost: "203.0.113.9",
		},
		{
			name:     "untrusted peer: XFF ignored, RemoteAddr used",
			trusted:  []string{"10.0.0.1"},
			remote:   "198.51.100.2:4444",
			xff:      "203.0.113.7",
			wantHost: "198.51.100.2",
		},
		{
			name:     "no trusted proxies configured: XFF ignored",
			trusted:  nil,
			remote:   "10.0.0.1:5555",
			xff:      "203.0.113.7",
			wantHost: "10.0.0.1",
		},
		{
			name:     "trusted proxy, no XFF, X-Real-IP fallback",
			trusted:  []string{"10.0.0.1"},
			remote:   "10.0.0.1:5555",
			xrealip:  "203.0.113.55",
			wantHost: "203.0.113.55",
		},
		{
			// The attacker prepends a forged leftmost entry; the trusted
			// proxy appends its own peer (the real client) to the right.
			// Right-to-left parsing must return the real client, NOT the
			// forged 1.2.3.4. This is the core finding-#2 regression guard.
			name:     "forged leftmost XFF ignored, real client used",
			trusted:  []string{"10.0.0.1"},
			remote:   "10.0.0.1:5555",
			xff:      "1.2.3.4, 198.51.100.9",
			wantHost: "198.51.100.9",
		},
		{
			// Two trusted hops in front plus the real client at the left
			// of the appended chain: walk right past both trusted hops,
			// return the first untrusted (the client).
			name:     "multi-hop trusted chain returns first untrusted from right",
			trusted:  []string{"10.0.0.0/8"},
			remote:   "10.0.0.1:5555",
			xff:      "203.0.113.20, 10.1.1.1, 10.0.0.1",
			wantHost: "203.0.113.20",
		},
		{
			// Every XFF entry is a trusted proxy (no client entry
			// recorded) -- fall back to X-Real-IP.
			name:     "all-trusted XFF falls back to X-Real-IP",
			trusted:  []string{"10.0.0.0/8"},
			remote:   "10.0.0.1:5555",
			xff:      "10.1.1.1, 10.0.0.1",
			xrealip:  "203.0.113.77",
			wantHost: "203.0.113.77",
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
			req.RemoteAddr = tc.remote
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.xrealip != "" {
				req.Header.Set("X-Real-IP", tc.xrealip)
			}
			got := server.ClientIPForTest(req, tc.trusted)
			if !contains(got, tc.wantHost) {
				t.Errorf("clientIP = %q, want to contain %q", got, tc.wantHost)
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
