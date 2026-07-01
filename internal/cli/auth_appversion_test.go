package cli

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/joestump/reduit/internal/config"
)

// discardLogger is a logger that drops output; protonConfig only logs
// diagnostics, never secrets, so tests don't need to inspect it.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// withDetectStub swaps the detectAppVersion seam for the duration of a test and
// returns a pointer to the call counter so callers can assert whether the
// network fetch was attempted.
func withDetectStub(t *testing.T, ret string, err error) *int {
	t.Helper()
	calls := 0
	orig := detectAppVersion
	detectAppVersion = func(context.Context) (string, error) {
		calls++
		return ret, err
	}
	t.Cleanup(func() { detectAppVersion = orig })
	return &calls
}

func TestProtonConfig_ExplicitValueSkipsDetect(t *testing.T) {
	calls := withDetectStub(t, "web-mail@0.0.0", nil)

	cfg := config.Defaults()
	cfg.Proton.AppVersion = "web-mail@9.9.9"

	got := protonConfig(context.Background(), cfg, discardLogger())
	if got.AppVersion != "web-mail@9.9.9" {
		t.Errorf("AppVersion = %q, want the explicit %q", got.AppVersion, "web-mail@9.9.9")
	}
	if *calls != 0 {
		t.Errorf("detectAppVersion called %d times, want 0 for an explicit value", *calls)
	}
}

func TestProtonConfig_UnsetTriggersDetect(t *testing.T) {
	calls := withDetectStub(t, "web-mail@5.0.121.4", nil)

	cfg := config.Defaults() // AppVersion defaults to "" -> auto-detect
	if cfg.Proton.AppVersion != "" {
		t.Fatalf("precondition: default AppVersion = %q, want empty", cfg.Proton.AppVersion)
	}

	got := protonConfig(context.Background(), cfg, discardLogger())
	if got.AppVersion != "web-mail@5.0.121.4" {
		t.Errorf("AppVersion = %q, want the detected %q", got.AppVersion, "web-mail@5.0.121.4")
	}
	if *calls != 1 {
		t.Errorf("detectAppVersion called %d times, want 1", *calls)
	}
}

func TestProtonConfig_AutoSentinelTriggersDetect(t *testing.T) {
	calls := withDetectStub(t, "web-mail@5.0.121.4", nil)

	cfg := config.Defaults()
	cfg.Proton.AppVersion = "AUTO" // case-insensitive sentinel

	got := protonConfig(context.Background(), cfg, discardLogger())
	if got.AppVersion != "web-mail@5.0.121.4" {
		t.Errorf("AppVersion = %q, want the detected %q", got.AppVersion, "web-mail@5.0.121.4")
	}
	if *calls != 1 {
		t.Errorf("detectAppVersion called %d times, want 1", *calls)
	}
}

func TestProtonConfig_DetectErrorUsesFallback(t *testing.T) {
	// On a detect error the seam still returns a usable fallback string; auth
	// must proceed with it rather than an empty header.
	calls := withDetectStub(t, "web-mail@5.0.121.4", errors.New("offline"))

	cfg := config.Defaults()

	got := protonConfig(context.Background(), cfg, discardLogger())
	if got.AppVersion != "web-mail@5.0.121.4" {
		t.Errorf("AppVersion = %q, want the fallback %q", got.AppVersion, "web-mail@5.0.121.4")
	}
	if *calls != 1 {
		t.Errorf("detectAppVersion called %d times, want 1", *calls)
	}
}
