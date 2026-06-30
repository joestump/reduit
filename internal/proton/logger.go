package proton

import (
	"context"
	"fmt"
	"log/slog"
)

// slogLogger adapts a *slog.Logger to go-proton-api's resty.Logger interface
// (Errorf/Warnf/Debugf). ADR-0001 calls out exactly this ~10-line shim as the
// price of go-proton-api logging through resty.Logger rather than slog directly.
//
// go-proton-api logs request/response diagnostics here, never reduit secrets;
// the password, TOTP, passphrase, and refresh token are passed to the API as
// values and are not formatted into these log lines (SPEC-0007 REQ "No Secret
// Leakage"). A nil *slog.Logger yields a no-op logger.
type slogLogger struct {
	log *slog.Logger
}

func newSlogLogger(log *slog.Logger) slogLogger {
	if log == nil {
		log = slog.New(slog.NewTextHandler(noopWriter{}, nil))
	}
	return slogLogger{log: log}
}

func (l slogLogger) Errorf(format string, v ...any) {
	l.log.LogAttrs(context.Background(), slog.LevelError, fmt.Sprintf(format, v...))
}

func (l slogLogger) Warnf(format string, v ...any) {
	l.log.LogAttrs(context.Background(), slog.LevelWarn, fmt.Sprintf(format, v...))
}

func (l slogLogger) Debugf(format string, v ...any) {
	l.log.LogAttrs(context.Background(), slog.LevelDebug, fmt.Sprintf(format, v...))
}

// noopWriter discards output for the nil-logger fallback.
type noopWriter struct{}

func (noopWriter) Write(p []byte) (int, error) { return len(p), nil }
