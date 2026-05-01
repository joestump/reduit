package pubsub

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// TestMain verifies that no goroutines leak across the test binary.
// Per acceptance criterion: "Closing a subscription does not leak
// goroutines (verified by goleak in tests)".
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// TestSubscribePublishRoundTrip is the simplest possible round-trip:
// one subscriber, one publish, one receive.
func TestSubscribePublishRoundTrip(t *testing.T) {
	t.Parallel()
	bus := New()
	defer bus.Close()

	ch, unsub := bus.Subscribe("acct-1:inbox", 0)
	defer unsub()

	want := Update{Kind: MessageAdded, MessageID: "msg-1"}
	bus.Publish("acct-1:inbox", want)

	select {
	case got := <-ch:
		if got.Kind != want.Kind || got.MessageID != want.MessageID {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for update")
	}
}

// TestMultipleSubscribersFanOut confirms every subscriber on a key
// receives every published event.
func TestMultipleSubscribersFanOut(t *testing.T) {
	t.Parallel()
	bus := New()
	defer bus.Close()

	const n = 3
	chs := make([]<-chan Update, n)
	unsubs := make([]func(), n)
	for i := 0; i < n; i++ {
		chs[i], unsubs[i] = bus.Subscribe("acct-1:inbox", 0)
	}
	defer func() {
		for _, u := range unsubs {
			u()
		}
	}()

	want := Update{Kind: MessageRemoved, MessageID: "msg-42"}
	bus.Publish("acct-1:inbox", want)

	for i, ch := range chs {
		select {
		case got := <-ch:
			if got.Kind != want.Kind || got.MessageID != want.MessageID {
				t.Fatalf("subscriber %d: got %+v, want %+v", i, got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d: timeout", i)
		}
	}
}

// TestPublishToUnsubscribedKey ensures publishing to a key with no
// subscribers is a silent no-op (no panic, no error).
func TestPublishToUnsubscribedKey(t *testing.T) {
	t.Parallel()
	bus := New()
	defer bus.Close()

	// Should not panic, hang, or produce side effects.
	bus.Publish("nobody-here", Update{Kind: MessageAdded, MessageID: "x"})

	// Subscribe to a different key, publish to ours, ensure the
	// other subscriber sees nothing.
	ch, unsub := bus.Subscribe("other", 0)
	defer unsub()
	bus.Publish("nobody-here", Update{Kind: MessageAdded, MessageID: "y"})

	select {
	case got := <-ch:
		t.Fatalf("unexpected delivery: %+v", got)
	case <-time.After(50 * time.Millisecond):
		// expected
	}
}

// TestUnsubscribeClosesChannel verifies the channel returned by
// Subscribe is closed when unsubscribe is called.
func TestUnsubscribeClosesChannel(t *testing.T) {
	t.Parallel()
	bus := New()
	defer bus.Close()

	ch, unsub := bus.Subscribe("k", 0)
	unsub()

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected channel closed, got value")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for channel close")
	}
}

// TestUnsubscribeIdempotent verifies calling unsubscribe twice is
// safe (no double-close panic).
func TestUnsubscribeIdempotent(t *testing.T) {
	t.Parallel()
	bus := New()
	defer bus.Close()

	_, unsub := bus.Subscribe("k", 0)
	unsub()
	// Must not panic.
	unsub()
	unsub()
}

// TestDropOldestOnOverflow fills a subscriber's buffer to capacity
// (default 64), publishes more, and verifies the OLDEST events were
// discarded — i.e. the buffer holds the most recent N events.
func TestDropOldestOnOverflow(t *testing.T) {
	t.Parallel()
	bus := New()
	defer bus.Close()

	const cap = DefaultBufferSize
	const overflow = 10
	const total = cap + overflow

	ch, unsub := bus.Subscribe("k", 0) // default buf
	defer unsub()

	for i := 0; i < total; i++ {
		bus.Publish("k", Update{Kind: MessageAdded, MessageID: fmt.Sprintf("msg-%d", i)})
	}

	// Drain. Because every Publish call drops-oldest when full,
	// the buffer at the end holds the LAST `cap` events
	// published — IDs `[overflow .. total-1]`.
	var got []string
	for i := 0; i < cap; i++ {
		select {
		case u := <-ch:
			got = append(got, u.MessageID)
		case <-time.After(time.Second):
			t.Fatalf("timeout draining at i=%d (got %d events)", i, len(got))
		}
	}

	if len(got) != cap {
		t.Fatalf("expected %d events, got %d", cap, len(got))
	}
	for i := 0; i < cap; i++ {
		want := fmt.Sprintf("msg-%d", i+overflow)
		if got[i] != want {
			t.Fatalf("event %d: got %q, want %q (drop-oldest violated)", i, got[i], want)
		}
	}

	// No more events should remain.
	select {
	case extra := <-ch:
		t.Fatalf("unexpected extra event: %+v", extra)
	case <-time.After(50 * time.Millisecond):
		// expected: buffer is empty
	}
}

// TestConfigurableBufferSize verifies bufSize is respected.
func TestConfigurableBufferSize(t *testing.T) {
	t.Parallel()
	bus := New()
	defer bus.Close()

	const sz = 4
	ch, unsub := bus.Subscribe("k", sz)
	defer unsub()

	// Push 2*sz; first sz get dropped.
	for i := 0; i < 2*sz; i++ {
		bus.Publish("k", Update{Kind: MessageAdded, MessageID: fmt.Sprintf("m%d", i)})
	}

	for i := 0; i < sz; i++ {
		select {
		case u := <-ch:
			want := fmt.Sprintf("m%d", i+sz)
			if u.MessageID != want {
				t.Fatalf("position %d: got %q want %q", i, u.MessageID, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timeout at %d", i)
		}
	}
}

// TestConcurrentPublishersAndSubscribers stresses the bus with
// multiple goroutines publishing and subscribing concurrently.
// Designed to surface races under `go test -race`. We assert no
// panic, no deadlock, and that every subscriber observes a
// non-decreasing prefix of the global publish order — but because
// drops can happen we only assert a weaker invariant: the count of
// events received is in [0, totalPublished].
func TestConcurrentPublishersAndSubscribers(t *testing.T) {
	t.Parallel()
	bus := New()
	defer bus.Close()

	const (
		numKeys        = 4
		pubsPerKey     = 4
		subsPerKey     = 3
		eventsPerPub   = 500
		subBuf         = 32
		drainGracePeri = 200 * time.Millisecond
	)

	// Start subscribers first so they don't miss everything.
	type subResult struct {
		key    string
		count  int64
		closed bool
	}
	var (
		subWG   sync.WaitGroup
		results = make(chan subResult, numKeys*subsPerKey)
		unsubs  []func()
		unsubMu sync.Mutex
	)
	addUnsub := func(u func()) {
		unsubMu.Lock()
		unsubs = append(unsubs, u)
		unsubMu.Unlock()
	}

	for k := 0; k < numKeys; k++ {
		key := fmt.Sprintf("acct-%d:inbox", k)
		for s := 0; s < subsPerKey; s++ {
			ch, unsub := bus.Subscribe(key, subBuf)
			addUnsub(unsub)
			subWG.Add(1)
			go func(key string, ch <-chan Update) {
				defer subWG.Done()
				var n int64
				for range ch {
					n++
				}
				results <- subResult{key: key, count: n, closed: true}
			}(key, ch)
		}
	}

	var pubWG sync.WaitGroup
	var totalPublished atomic.Int64
	for k := 0; k < numKeys; k++ {
		key := fmt.Sprintf("acct-%d:inbox", k)
		for p := 0; p < pubsPerKey; p++ {
			pubWG.Add(1)
			go func(key string, pid int) {
				defer pubWG.Done()
				for i := 0; i < eventsPerPub; i++ {
					bus.Publish(key, Update{
						Kind:      MessageAdded,
						MessageID: fmt.Sprintf("%s-p%d-i%d", key, pid, i),
					})
					totalPublished.Add(1)
				}
			}(key, p)
		}
	}
	pubWG.Wait()

	// Give subscribers a moment to drain before we close them.
	time.Sleep(drainGracePeri)

	// Tear down via unsubs (this also closes channels, ending
	// the subscriber goroutines).
	for _, u := range unsubs {
		u()
	}
	subWG.Wait()
	close(results)

	var totalReceived int64
	var subs int
	for r := range results {
		if !r.closed {
			t.Errorf("subscriber for %s did not see channel close", r.key)
		}
		totalReceived += r.count
		subs++
	}
	if subs != numKeys*subsPerKey {
		t.Fatalf("expected %d subscriber results, got %d", numKeys*subsPerKey, subs)
	}
	// Sanity: with subBuf=32 and bursts of pubsPerKey*eventsPerPub
	// per key, we expect drops, so received ≤ published. But we
	// should see at least *some* events (well above 0).
	tp := totalPublished.Load()
	if totalReceived <= 0 {
		t.Fatalf("expected >0 events received, got %d (published=%d)", totalReceived, tp)
	}
	if totalReceived > tp*int64(subsPerKey) {
		t.Fatalf("received %d > max possible %d", totalReceived, tp*int64(subsPerKey))
	}
}

// TestCloseUnsubscribesEverything verifies bus.Close closes every
// subscriber's channel.
func TestCloseUnsubscribesEverything(t *testing.T) {
	t.Parallel()
	bus := New()

	ch1, _ := bus.Subscribe("k1", 0)
	ch2, _ := bus.Subscribe("k2", 0)
	ch3, _ := bus.Subscribe("k1", 0)

	bus.Close()

	for i, ch := range []<-chan Update{ch1, ch2, ch3} {
		select {
		case _, ok := <-ch:
			if ok {
				t.Fatalf("ch%d: expected closed, got value", i)
			}
		case <-time.After(time.Second):
			t.Fatalf("ch%d: timeout waiting for close", i)
		}
	}

	// Idempotent.
	bus.Close()

	// Subscribe after Close returns an already-closed channel.
	ch4, unsub := bus.Subscribe("k1", 0)
	defer unsub()
	select {
	case _, ok := <-ch4:
		if ok {
			t.Fatal("post-close Subscribe channel must be closed")
		}
	case <-time.After(time.Second):
		t.Fatal("post-close Subscribe channel not closed")
	}

	// Publish post-close is a no-op.
	bus.Publish("k1", Update{Kind: MessageAdded, MessageID: "x"})
}

// TestKindString smoke-checks the Kind.String() helper used by
// loggers.
func TestKindString(t *testing.T) {
	t.Parallel()
	cases := map[Kind]string{
		MessageAdded:       "MessageAdded",
		MessageRemoved:     "MessageRemoved",
		MessageFlagChanged: "MessageFlagChanged",
		KindUnknown:        "Unknown",
		Kind(99):           "Unknown",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("Kind(%d).String()=%q, want %q", k, got, want)
		}
	}
}
