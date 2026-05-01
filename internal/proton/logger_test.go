// Governing: ADR-0001 (go-proton-api as Proton client).

package proton

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/go-resty/resty/v2"
)

// newRestyLogger must return something that satisfies resty.Logger.
// This is a static guarantee but worth pinning so a future signature
// change surfaces here.
func TestSlogAdapter_SatisfiesRestyLogger(t *testing.T) {
	t.Parallel()
	var _ resty.Logger = newRestyLogger(slog.Default())
}

func TestSlogAdapter_DebugGatedAtInfoLevel(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	adapter := newRestyLogger(log)

	adapter.Debugf("debug-only %s", "payload")

	if buf.Len() != 0 {
		t.Fatalf("expected empty buffer at info level, got %q", buf.String())
	}
}

func TestSlogAdapter_DebugEmittedAtDebugLevel(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	adapter := newRestyLogger(log)

	adapter.Debugf("debug %s=%d", "k", 7)

	out := buf.String()
	if !strings.Contains(out, "debug k=7") {
		t.Fatalf("expected formatted debug payload in buffer, got %q", out)
	}
	if !strings.Contains(out, "level=DEBUG") {
		t.Fatalf("expected DEBUG level marker, got %q", out)
	}
	if !strings.Contains(out, "source=resty") {
		t.Fatalf("expected source=resty attribute, got %q", out)
	}
}

func TestSlogAdapter_WarnAlwaysEmittedAtInfoLevel(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	adapter := newRestyLogger(log)

	adapter.Warnf("retry-after %ds", 5)

	out := buf.String()
	if !strings.Contains(out, "retry-after 5s") {
		t.Fatalf("expected formatted warn payload, got %q", out)
	}
	if !strings.Contains(out, "level=WARN") {
		t.Fatalf("expected WARN level marker, got %q", out)
	}
}

func TestSlogAdapter_ErrorAlwaysEmitted(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	// Even at WARN level, Error should still pass.
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	}))
	adapter := newRestyLogger(log)

	adapter.Errorf("boom: %v", "unauthorized")

	out := buf.String()
	if !strings.Contains(out, "boom: unauthorized") {
		t.Fatalf("expected formatted error payload, got %q", out)
	}
	if !strings.Contains(out, "level=ERROR") {
		t.Fatalf("expected ERROR level marker, got %q", out)
	}
}

func TestSlogAdapter_NilLoggerSafe(t *testing.T) {
	t.Parallel()
	// newRestyLogger(nil) should not panic and should accept calls.
	adapter := newRestyLogger(nil)
	adapter.Debugf("x %d", 1)
	adapter.Warnf("x %d", 2)
	adapter.Errorf("x %d", 3)
}
