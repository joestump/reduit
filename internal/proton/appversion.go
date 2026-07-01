package proton

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Proton validates the x-pm-appversion header and rejects unacceptable values
// (codes 5001/5003). The accepted format for the web client is
// "web-mail@<version>", where <version> is Proton's currently-published web
// release. Proton exposes that release at a public manifest:
//
//	GET https://mail.proton.me/assets/version.json
//	{ "branch": "proton-mail@5.0.121.4", "version": "5.0.121.4" }
//
// Note the manifest's "branch" uses a "proton-mail@" prefix that Proton itself
// REJECTS as an app-version ("proton" is not a valid platform); only the bare
// ".version" reformatted as "web-mail@<version>" is accepted. A too-old
// version (e.g. web-mail@5.0.0) is also rejected, so pinning a stale constant
// eventually breaks — hence auto-detection.
const (
	// versionURL is Proton's published web-mail version manifest.
	versionURL = "https://mail.proton.me/assets/version.json"

	// FallbackAppVersion is returned by DetectAppVersion when the live
	// manifest cannot be fetched or parsed (offline, timeout, bad payload). It
	// is a recently-verified-accepted value so an offline run still presents a
	// header Proton will take; callers pair it with the returned error to
	// log-and-continue rather than fail auth.
	FallbackAppVersion = "web-mail@5.0.121.4"

	// detectTimeout bounds the manifest fetch so a slow or unreachable network
	// never blocks startup for long; on expiry the caller gets the fallback.
	detectTimeout = 3 * time.Second

	// versionBodyLimit caps the manifest body we read. The real payload is a
	// few hundred bytes; the limit guards against a misbehaving endpoint.
	versionBodyLimit = 64 << 10
)

// DetectAppVersion fetches Proton's currently-published web-mail version and
// returns it as the accepted x-pm-appversion string "web-mail@<version>". On
// any error (offline, timeout, non-200, malformed/empty payload) it returns
// FallbackAppVersion together with the error, so callers can log the failure
// and continue with a header Proton will still accept rather than blocking on
// the fetch. The returned string is therefore never empty.
func DetectAppVersion(ctx context.Context) (string, error) {
	return detectAppVersion(ctx, versionURL)
}

// detectAppVersion is the URL-injectable core of DetectAppVersion, letting
// tests point it at an httptest server without touching the live endpoint.
func detectAppVersion(ctx context.Context, url string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, detectTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return FallbackAppVersion, fmt.Errorf("proton: build app-version request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return FallbackAppVersion, fmt.Errorf("proton: fetch app version: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return FallbackAppVersion, fmt.Errorf("proton: fetch app version: unexpected status %s", resp.Status)
	}

	var payload struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, versionBodyLimit)).Decode(&payload); err != nil {
		return FallbackAppVersion, fmt.Errorf("proton: decode app version: %w", err)
	}
	version := strings.TrimSpace(payload.Version)
	if version == "" {
		return FallbackAppVersion, errors.New("proton: app-version manifest missing version field")
	}
	return "web-mail@" + version, nil
}
