//go:build webview

package cli

import (
	"strings"
	"testing"
)

// TestCaptchaAssetURL_ParsedFromHTML confirms the asset URL is lifted verbatim
// out of Proton's challenge HTML (query string preserved) when present — the
// preferred source (ADR-0021), since it carries whatever parameters Proton
// minted for this challenge.
func TestCaptchaAssetURL_ParsedFromHTML(t *testing.T) {
	html := []byte(`<html><body><iframe src="https://mail.proton.me/captcha/v1/assets/?purpose=login&token=ABC123"></iframe></body></html>`)
	got := captchaAssetURL(html, "unused-fallback")
	want := "https://mail.proton.me/captcha/v1/assets/?purpose=login&token=ABC123"
	if got != want {
		t.Errorf("captchaAssetURL parsed = %q, want %q", got, want)
	}
}

// TestCaptchaAssetURL_FallbackConstructed confirms that when the HTML carries no
// asset URL, one is constructed from the HV token with the token URL-escaped
// (ADR-0021 fallback).
func TestCaptchaAssetURL_FallbackConstructed(t *testing.T) {
	got := captchaAssetURL([]byte("<html>no asset here</html>"), "tok/with+special")
	if !strings.HasPrefix(got, captchaAssetBase+"?purpose=login&token=") {
		t.Errorf("fallback URL = %q, want prefix %q?purpose=login&token=", got, captchaAssetBase)
	}
	if strings.Contains(got, "tok/with+special") {
		t.Errorf("fallback URL did not escape the token: %q", got)
	}
	if !strings.Contains(got, "tok%2Fwith%2Bspecial") {
		t.Errorf("fallback URL missing escaped token: %q", got)
	}
}

// TestContainsFold covers the method-set guard used before attempting a solve.
func TestContainsFold(t *testing.T) {
	if !containsFold([]string{"email", "CAPTCHA"}, "captcha") {
		t.Error("containsFold should match case-insensitively")
	}
	if containsFold([]string{"email", "sms"}, "captcha") {
		t.Error("containsFold matched a missing method")
	}
}
