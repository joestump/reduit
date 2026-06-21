// Governing: SPEC-0002 REQ "Panic Isolation" (worker crash emits an
//             admin notification so the operator is actively told),
//             SPEC-0002 REQ "Backoff on Failure" (permanent-error
//             auto-revert emits an admin notification).

package sync

import (
	"context"

	"github.com/joestump/reduit/internal/notify"
)

// Notifier is the slice of notify.Service the sync worker needs: append
// one admin notification for an account. notify.Service satisfies it
// naturally (via the embedded notify.Recorder); tests pass a recording
// stub that captures every call without a database.
//
// Kept as a one-method interface so the worker depends only on the verb
// it uses, mirroring how Publisher narrows pubsub.Bus. nil is replaced
// with nopNotifier at construction so emit sites never nil-check.
//
// Governing: SPEC-0002 REQ "Panic Isolation", REQ "Backoff on Failure".
type Notifier interface {
	Record(ctx context.Context, accountID string, kind notify.Kind, message, detail string) (*notify.Notification, error)
}

// nopNotifier is the zero-value notifier: every Record call is dropped.
// Used when the supervisor was constructed without a Notifier (unit
// tests, or any deployment that has not wired the admin-notification
// surface) so emit sites can call Record unconditionally.
type nopNotifier struct{}

func (nopNotifier) Record(context.Context, string, notify.Kind, string, string) (*notify.Notification, error) {
	return nil, nil
}
