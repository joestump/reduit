// Package tlsloader provides a hot-reloading TLS certificate loader.
// On startup it reads cert + key from disk into a *tls.Certificate and
// stores them behind an atomic.Pointer. The Watch goroutine subscribes
// to fsnotify events on both files (and their parent directories,
// since certbot atomically renames the file) and refreshes the pointer
// when the underlying files change. New TLS handshakes pick up the
// rotated cert; existing handshakes continue with whatever cert they
// negotiated under.
//
// Governing: ADR-0009 (TLS via on-disk cert files with hot-reload).
package tlsloader

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Loader holds a *tls.Certificate behind an atomic pointer and exposes
// GetCertificate (the callback the tls.Config wires up). Reload reads
// the certs from disk and atomically swaps the pointer.
type Loader struct {
	certPath string
	keyPath  string
	current  atomic.Pointer[tls.Certificate]
	logger   *slog.Logger
}

// New parses the cert+key from disk and returns a Loader holding the
// initial certificate. New errors out if the cert and key do not match
// or either is unparseable.
func New(certPath, keyPath string, logger *slog.Logger) (*Loader, error) {
	if certPath == "" || keyPath == "" {
		return nil, errors.New("tlsloader: cert_path and key_path are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	l := &Loader{certPath: certPath, keyPath: keyPath, logger: logger}
	if err := l.reload(); err != nil {
		return nil, fmt.Errorf("tlsloader: initial load: %w", err)
	}
	return l, nil
}

// GetCertificate is the tls.Config.GetCertificate callback. It returns
// the currently-loaded certificate. The signature matches stdlib so
// callers can do `tlsCfg.GetCertificate = loader.GetCertificate`.
func (l *Loader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := l.current.Load()
	if cert == nil {
		return nil, errors.New("tlsloader: no certificate loaded")
	}
	return cert, nil
}

// Current returns a snapshot pointer to the loaded cert. Callers that
// just want the cert (e.g., for diagnostics) should prefer
// GetCertificate, which matches the tls.Config callback shape.
func (l *Loader) Current() *tls.Certificate { return l.current.Load() }

// Watch starts a goroutine that watches cert+key files (and their
// parent directories) and reloads on change. It blocks until ctx is
// canceled, then cleans up.
//
// The watcher uses parent-directory watches because certbot's atomic
// rename pattern (`mv newfile fullchain.pem`) does not fire a WRITE
// event on the existing inode — the inode is replaced.
func (l *Loader) Watch(ctx context.Context) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("tlsloader: new watcher: %w", err)
	}
	defer w.Close()

	dirs := dedupe(filepath.Dir(l.certPath), filepath.Dir(l.keyPath))
	for _, d := range dirs {
		if err := w.Add(d); err != nil {
			return fmt.Errorf("tlsloader: add watcher %s: %w", d, err)
		}
	}

	// Debounce coalesces a burst of events (cert + key written in
	// quick succession) into a single reload.
	var debounce *time.Timer

	for {
		select {
		case <-ctx.Done():
			return nil

		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			if !relevant(ev, l.certPath, l.keyPath) {
				continue
			}
			if debounce != nil {
				debounce.Stop()
			}
			debounce = time.AfterFunc(250*time.Millisecond, func() {
				if err := l.reload(); err != nil {
					l.logger.Error("tls reload failed; keeping previous cert",
						slog.String("error", err.Error()))
					return
				}
				l.logger.Info("tls cert reloaded",
					slog.String("cert_path", l.certPath))
			})

		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			l.logger.Warn("tls watcher error",
				slog.String("error", err.Error()))
		}
	}
}

// reload reads cert+key from disk, parses them, validates they match,
// and atomically swaps the held pointer. On any failure the previous
// cert is kept and an error is returned (callers should log and
// continue serving with the older cert rather than crash).
func (l *Loader) reload() error {
	cert, err := tls.LoadX509KeyPair(l.certPath, l.keyPath)
	if err != nil {
		return err
	}
	l.current.Store(&cert)
	return nil
}

// relevant reports whether an fsnotify event concerns one of the
// cert/key files. Parent-directory watches fire for sibling files
// too; we filter to just the ones we care about.
func relevant(ev fsnotify.Event, certPath, keyPath string) bool {
	// Compare against absolute paths if we can; fsnotify reports the
	// event Name as the path passed to Add() joined with the file.
	matches := func(target string) bool {
		return ev.Name == target ||
			filepath.Base(ev.Name) == filepath.Base(target)
	}
	if !(matches(certPath) || matches(keyPath)) {
		return false
	}
	// We care about creates, writes, and chmods (atomic rename appears
	// as a CREATE on the new inode in the parent dir).
	return ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Chmod) != 0
}

func dedupe(values ...string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
