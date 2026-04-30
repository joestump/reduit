// Package pubsub provides an in-process bounded-buffer fan-out bus
// used to notify IMAP IDLE sessions of state changes published by
// sync workers.
//
// Topics are keyed by an opaque string. The expected key shape from
// callers is "<account_id>:<mailbox_id>", but the bus does not parse
// or interpret keys — construction is the caller's responsibility.
//
// Publish is non-blocking: when a subscriber's bounded buffer is
// full, the OLDEST queued event is dropped to make room for the new
// one. Subscribers that fall behind therefore lose history rather
// than block publishers; the IMAP-correct fallback is for the client
// to RESYNC on reconnect.
//
// Governing: SPEC-0002 REQ "IMAP Update Notification",
//
//	SPEC-0003 REQ "IDLE Support With Live Updates".
package pubsub
