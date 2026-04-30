// Governing: SPEC-0002 REQ "IMAP Update Notification",
//             SPEC-0003 REQ "IDLE Support With Live Updates".

package pubsub

import (
	"sync"
)

// DefaultBufferSize is the per-subscriber channel capacity used when
// Subscribe is called without an explicit size. SPEC-0002 design.md
// fixes this at 64 events; on overflow the oldest event is dropped.
const DefaultBufferSize = 64

// Kind enumerates the kinds of state change a sync worker can
// publish to IMAP IDLE sessions.
//
// Governing: SPEC-0002 REQ "IMAP Update Notification" (EXISTS,
// EXPUNGE, FETCH scenarios).
type Kind int

const (
	// KindUnknown is the zero value; reserved so that an
	// uninitialized Update is detectable by callers.
	KindUnknown Kind = iota
	// MessageAdded indicates a new message arrived in the
	// mailbox (IDLE will emit EXISTS).
	MessageAdded
	// MessageRemoved indicates a message was expunged from the
	// mailbox (IDLE will emit EXPUNGE).
	MessageRemoved
	// MessageFlagChanged indicates flags on an existing message
	// changed (IDLE will emit FETCH with the new flags).
	MessageFlagChanged
)

// String returns a stable, human-readable label for k. Useful for
// log lines and tests; not part of any wire protocol.
func (k Kind) String() string {
	switch k {
	case MessageAdded:
		return "MessageAdded"
	case MessageRemoved:
		return "MessageRemoved"
	case MessageFlagChanged:
		return "MessageFlagChanged"
	default:
		return "Unknown"
	}
}

// Update is a single notification published by a sync worker after
// a batch of Proton events has been committed locally.
//
// Flags is optional and is only meaningful for MessageFlagChanged;
// callers MAY leave it nil for other kinds.
type Update struct {
	Kind      Kind
	MessageID string
	Flags     []string
}

// subscriber is the per-Subscribe handle held inside the bus. The
// channel is closed by unsubscribe; the once guard makes the
// returned unsubscribe func idempotent.
type subscriber struct {
	ch   chan Update
	once sync.Once
}

// Bus is an in-process fan-out for sync→IDLE notifications. The
// zero value is not usable; construct via New.
//
// A Bus is safe for concurrent use by N publishers and M
// subscribers across any number of keys.
type Bus struct {
	mu     sync.RWMutex
	subs   map[string]map[*subscriber]struct{}
	closed bool
}

// New constructs an empty Bus.
func New() *Bus {
	return &Bus{
		subs: make(map[string]map[*subscriber]struct{}),
	}
}

// Subscribe registers a new subscriber for key and returns a
// receive-only channel plus an unsubscribe func. The channel has
// capacity bufSize; pass <= 0 to use DefaultBufferSize.
//
// The unsubscribe func is idempotent: calling it more than once is
// safe. It removes the subscriber from the bus AND closes the
// channel, so a ranging consumer goroutine will exit cleanly. After
// the bus is closed via Close, Subscribe still returns a usable
// (but already-closed) channel so callers do not need to special-
// case the shutdown race; the unsubscribe func remains a safe no-op.
func (b *Bus) Subscribe(key string, bufSize int) (<-chan Update, func()) {
	if bufSize <= 0 {
		bufSize = DefaultBufferSize
	}
	s := &subscriber{ch: make(chan Update, bufSize)}

	b.mu.Lock()
	if b.closed {
		// Bus is shut down; hand back a closed channel so
		// receivers terminate immediately.
		b.mu.Unlock()
		s.once.Do(func() { close(s.ch) })
		return s.ch, func() {}
	}
	set, ok := b.subs[key]
	if !ok {
		set = make(map[*subscriber]struct{})
		b.subs[key] = set
	}
	set[s] = struct{}{}
	b.mu.Unlock()

	unsub := func() {
		b.mu.Lock()
		if set, ok := b.subs[key]; ok {
			if _, present := set[s]; present {
				delete(set, s)
				if len(set) == 0 {
					delete(b.subs, key)
				}
			}
		}
		b.mu.Unlock()
		// Close exactly once; safe even if the bus already
		// removed us during Close().
		s.once.Do(func() { close(s.ch) })
	}
	return s.ch, unsub
}

// Publish fans u out to every subscriber on key. Delivery is
// non-blocking: when a subscriber's buffer is full, the oldest
// queued event is discarded to make room for u (drop-oldest).
// Publishing to a key with no subscribers is a no-op.
//
// Drop-oldest is inherently lossy. The IMAP-correct fallback is for
// the client to RESYNC on reconnect; see SPEC-0002 design.md
// "Pubsub for IMAP IDLE".
func (b *Bus) Publish(key string, u Update) {
	b.mu.RLock()
	set, ok := b.subs[key]
	if !ok || len(set) == 0 {
		b.mu.RUnlock()
		return
	}
	// Snapshot under the read lock so we can release it before
	// touching subscriber channels. Subscribers' channels are
	// owned by the subscriber struct and remain valid until the
	// matching unsubscribe Close()s them; even if a concurrent
	// unsubscribe runs, sending to a closed channel would panic
	// — we therefore keep the read lock across the sends to
	// serialize against unsubscribe's write lock.
	for s := range set {
		deliver(s.ch, u)
	}
	b.mu.RUnlock()
}

// deliver implements drop-oldest: if ch is full, discard the head
// element and re-attempt the send. The retry loop tolerates the
// race where another goroutine drains the buffer between the full
// observation and the discard: in that case the discard select
// falls through and we simply retry the send.
func deliver(ch chan Update, u Update) {
	for {
		select {
		case ch <- u:
			return
		default:
			select {
			case <-ch:
				// Dropped oldest; loop and retry send.
			default:
				// Raced with a reader who already
				// drained; loop and retry send.
			}
		}
	}
}

// Close unsubscribes every subscriber and marks the bus shut down.
// After Close returns, Publish is a no-op and Subscribe returns an
// already-closed channel. Close is idempotent.
func (b *Bus) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	subs := b.subs
	b.subs = make(map[string]map[*subscriber]struct{})
	b.mu.Unlock()

	for _, set := range subs {
		for s := range set {
			s.once.Do(func() { close(s.ch) })
		}
	}
}
