// Governing: ADR-0001 (go-proton-api as Proton client).

package proton

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/go-resty/resty/v2"
)

// slogRestyAdapter satisfies resty.Logger by routing Debugf/Warnf/Errorf
// into a *slog.Logger. The mapping is:
//
//	Debugf -> slog.Debug
//	Warnf  -> slog.Warn
//	Errorf -> slog.Error
//
// Debugf calls are gated on Enabled(slog.LevelDebug) so the format
// expansion is skipped entirely when the slog handler is configured at
// info-or-higher — that's the common production path where resty's
// debug payload would otherwise leak HTTP bodies into structured logs.
//
// The adapter never panics on a nil underlying logger: nil is replaced
// by a no-op handler at the Manager constructor (see resolveOptions).
type slogRestyAdapter struct {
	log *slog.Logger
}

// newRestyLogger wraps a *slog.Logger as a resty.Logger. The returned
// value is safe for concurrent use (slog.Logger is concurrency-safe).
func newRestyLogger(l *slog.Logger) resty.Logger {
	if l == nil {
		l = slog.New(slog.NewTextHandler(discardWriter{}, nil))
	}
	return &slogRestyAdapter{log: l}
}

// Errorf records an error-level event. We do not gate on Enabled here —
// errors are cheap and the logger should always see them.
func (a *slogRestyAdapter) Errorf(format string, v ...any) {
	a.log.LogAttrs(context.Background(), slog.LevelError,
		fmt.Sprintf(format, v...),
		slog.String("source", "resty"),
	)
}

// Warnf records a warn-level event.
func (a *slogRestyAdapter) Warnf(format string, v ...any) {
	a.log.LogAttrs(context.Background(), slog.LevelWarn,
		fmt.Sprintf(format, v...),
		slog.String("source", "resty"),
	)
}

// Debugf records a debug-level event, but only if the underlying
// handler has debug enabled. The Enabled() gate avoids the cost of
// fmt.Sprintf on hot paths when nobody is listening.
func (a *slogRestyAdapter) Debugf(format string, v ...any) {
	if !a.log.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	a.log.LogAttrs(context.Background(), slog.LevelDebug,
		fmt.Sprintf(format, v...),
		slog.String("source", "resty"),
	)
}
