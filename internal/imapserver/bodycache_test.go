// Tests for the per-account decrypted-body LRU cache + Proton body-fetch
// limiter (#32). They cover, per the issue's acceptance criteria:
//
//   - a cache hit avoids a second Proton fetch (asserted via the fake
//     client's recorded fetch count through the real session path);
//   - eviction by size and by TTL;
//   - the limiter bounds concurrency;
//   - the whole thing is race-clean under `go test -race`.
//
// Governing: SPEC-0003 design "Performance considerations" — per-account
// decrypted-body LRU (32 MiB / 5min TTL) + bounded fetch.

package imapserver

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"

	"github.com/joestump/reduit/internal/mailbox"
)

// TestBodyCacheGetPutHit asserts a stored body is returned on get and
// that a miss reports false.
func TestBodyCacheGetPutHit(t *testing.T) {
	t.Parallel()
	c := newBodyCache(1024, time.Minute)

	if _, ok := c.get("missing"); ok {
		t.Fatal("get on empty cache returned a hit")
	}

	c.put("a", []byte("hello"))
	got, ok := c.get("a")
	if !ok {
		t.Fatal("expected hit after put")
	}
	if string(got) != "hello" {
		t.Errorf("get = %q, want %q", got, "hello")
	}
	if c.len() != 1 || c.bytes() != 5 {
		t.Errorf("len=%d bytes=%d, want 1/5", c.len(), c.bytes())
	}
}

// TestBodyCacheEvictsBySize fills the cache past its byte budget and
// asserts the least-recently-used entries are evicted and the running
// total stays within budget.
func TestBodyCacheEvictsBySize(t *testing.T) {
	t.Parallel()
	// Budget holds at most two 10-byte bodies.
	c := newBodyCache(20, time.Minute)
	ten := []byte("0123456789")

	c.put("a", ten)
	c.put("b", ten)
	// Touch "a" so "b" becomes the coldest entry.
	if _, ok := c.get("a"); !ok {
		t.Fatal("a should still be cached")
	}
	// Inserting "c" must evict the LRU ("b"), not "a".
	c.put("c", ten)

	if c.bytes() > 20 {
		t.Errorf("curBytes=%d exceeds budget 20", c.bytes())
	}
	if _, ok := c.get("b"); ok {
		t.Error("b should have been evicted as least-recently-used")
	}
	if _, ok := c.get("a"); !ok {
		t.Error("a should have survived (recently used)")
	}
	if _, ok := c.get("c"); !ok {
		t.Error("c should be present (just inserted)")
	}
}

// TestBodyCacheOversizeNotCached asserts a body larger than the whole
// budget is declined (storing it would evict everything and still
// overflow) without disturbing existing entries.
func TestBodyCacheOversizeNotCached(t *testing.T) {
	t.Parallel()
	c := newBodyCache(20, time.Minute)
	c.put("small", []byte("0123456789"))
	c.put("huge", make([]byte, 64))

	if _, ok := c.get("huge"); ok {
		t.Error("oversize body should not be cached")
	}
	if _, ok := c.get("small"); !ok {
		t.Error("oversize put should not evict an existing in-budget entry")
	}
	if c.bytes() != 10 {
		t.Errorf("curBytes=%d, want 10", c.bytes())
	}
}

// TestBodyCacheEvictsByTTL asserts an entry past its TTL is treated as a
// miss and reclaimed on access. The clock is injected so the test does
// not sleep.
func TestBodyCacheEvictsByTTL(t *testing.T) {
	t.Parallel()
	c := newBodyCache(1024, 5*time.Minute)
	now := time.Unix(0, 0)
	c.now = func() time.Time { return now }

	c.put("a", []byte("hello"))
	if _, ok := c.get("a"); !ok {
		t.Fatal("fresh entry should hit")
	}

	// Advance past the TTL.
	now = now.Add(6 * time.Minute)
	if _, ok := c.get("a"); ok {
		t.Error("expired entry should be a miss")
	}
	if c.len() != 0 || c.bytes() != 0 {
		t.Errorf("expired entry not reclaimed: len=%d bytes=%d", c.len(), c.bytes())
	}
}

// TestBodyCacheRefreshUpdatesSize asserts re-putting a key adjusts the
// byte total by the delta rather than double-counting.
func TestBodyCacheRefreshUpdatesSize(t *testing.T) {
	t.Parallel()
	c := newBodyCache(1024, time.Minute)
	c.put("a", []byte("0123456789")) // 10
	c.put("a", []byte("xy"))         // 2

	if c.len() != 1 {
		t.Errorf("len=%d, want 1 after refresh", c.len())
	}
	if c.bytes() != 2 {
		t.Errorf("bytes=%d, want 2 after shrinking refresh", c.bytes())
	}
	got, _ := c.get("a")
	if string(got) != "xy" {
		t.Errorf("get=%q, want refreshed value", got)
	}
}

// TestFetchLimiterBoundsConcurrency launches many more fetchers than the
// limiter permits and asserts the observed peak concurrency never
// exceeds the configured ceiling.
func TestFetchLimiterBoundsConcurrency(t *testing.T) {
	t.Parallel()
	const limit = 3
	const goroutines = 50
	l := newFetchLimiter(limit)

	var inflight, peak int64
	var wg sync.WaitGroup
	done := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !l.acquire(done) {
				return
			}
			defer l.release()
			cur := atomic.AddInt64(&inflight, 1)
			for {
				p := atomic.LoadInt64(&peak)
				if cur <= p || atomic.CompareAndSwapInt64(&peak, p, cur) {
					break
				}
			}
			// Hold the slot briefly so contention actually develops.
			time.Sleep(time.Millisecond)
			atomic.AddInt64(&inflight, -1)
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&peak); got > limit {
		t.Errorf("peak concurrency %d exceeded limit %d", got, limit)
	}
}

// TestFetchLimiterAcquireCancels asserts acquire returns false once the
// done channel closes while every slot is held.
func TestFetchLimiterAcquireCancels(t *testing.T) {
	t.Parallel()
	l := newFetchLimiter(1)
	if !l.acquire(nil) {
		t.Fatal("first acquire should succeed")
	}
	done := make(chan struct{})
	close(done)
	if l.acquire(done) {
		t.Error("acquire on a saturated limiter with a closed done should fail")
		l.release()
	}
	l.release()
}

// TestSessionFetchBodyCacheHitAvoidsSecondFetch drives the real session
// body path twice for the same message and asserts Proton is hit exactly
// once — the second FETCH is served from the per-account cache.
//
// Governing: SPEC-0003 design "Performance considerations".
func TestSessionFetchBodyCacheHitAvoidsSecondFetch(t *testing.T) {
	t.Parallel()
	mboxes, _, acct := newMailboxStack(t)
	ctx := context.Background()

	fp := &fakeProton{body: []byte(sampleRFC822)}
	sess := newAuthedSession(t, mboxes, fp, acct)

	m := &mailbox.MessageInMailbox{UID: 1, ProtonMessageID: "proton-cache-1"}
	full := []*imap.FetchItemBodySection{{}}

	for i := 0; i < 3; i++ {
		got, err := sess.bodySectionsForMessage(ctx, acct, m, full)
		if err != nil {
			t.Fatalf("fetch %d: %v", i, err)
		}
		if string(got[0]) != sampleRFC822 {
			t.Fatalf("fetch %d body mismatch", i)
		}
	}

	fp.mu.Lock()
	n := len(fp.bodyFetches)
	fp.mu.Unlock()
	if n != 1 {
		t.Errorf("Proton GetMessageRFC822 called %d times, want 1 (cache should serve repeats)", n)
	}
}

// TestSessionFetchBodyCacheIsPerAccount asserts one account's cached body
// is never served to another account even when the Proton message ID
// collides — the cache key is (account, message ID).
//
// Governing: SPEC-0003 REQ "Account Isolation in IMAP Operations".
func TestSessionFetchBodyCacheIsPerAccount(t *testing.T) {
	t.Parallel()
	mboxes, _, acctA := newMailboxStack(t)
	const acctB = "acct-other-cache"

	// Shared backend, two accounts, same Proton message ID, different
	// bodies. Each session must see only its own account's body.
	fp := &fakeProton{
		bodyByID: map[string][]byte{},
	}
	sessA := newAuthedSession(t, mboxes, fp, acctA)
	// Reuse the same Backend so both sessions share one accountBodyCaches.
	sessB := &session{
		backend:   sessA.backend,
		remote:    "127.0.0.1:0",
		rateKey:   "127.0.0.1",
		logger:    sessA.backend.logger,
		accountID: acctB,
	}

	fp.mu.Lock()
	fp.bodyByID["shared-id"] = []byte("body-for-A")
	fp.mu.Unlock()

	ctx := context.Background()
	m := &mailbox.MessageInMailbox{UID: 1, ProtonMessageID: "shared-id"}

	gotA, err := sessA.bodySectionsForMessage(ctx, acctA, m, []*imap.FetchItemBodySection{{}})
	if err != nil {
		t.Fatalf("A fetch: %v", err)
	}
	if string(gotA[0]) != "body-for-A" {
		t.Fatalf("A got %q", gotA[0])
	}

	// Now B fetches the same Proton ID; the cache must NOT serve A's body,
	// so Proton is consulted again (and we return a B-specific body).
	fp.mu.Lock()
	fp.bodyByID["shared-id"] = []byte("body-for-B")
	fp.mu.Unlock()

	gotB, err := sessB.bodySectionsForMessage(ctx, acctB, m, []*imap.FetchItemBodySection{{}})
	if err != nil {
		t.Fatalf("B fetch: %v", err)
	}
	if string(gotB[0]) != "body-for-B" {
		t.Errorf("account B got %q, want its own body (cache leaked across accounts)", gotB[0])
	}
}

// TestSessionFetchBodyConcurrentRaceClean hammers the body path from many
// goroutines across several messages on one account so `go test -race`
// can catch any unsynchronised access to the shared cache or limiter.
func TestSessionFetchBodyConcurrentRaceClean(t *testing.T) {
	t.Parallel()
	mboxes, _, acct := newMailboxStack(t)

	fp := &fakeProton{bodyByID: map[string][]byte{}}
	for i := 0; i < 8; i++ {
		fp.bodyByID[fmt.Sprintf("msg-%d", i)] = []byte(fmt.Sprintf("body-%d", i))
	}
	sess := newAuthedSession(t, mboxes, fp, acct)

	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			ctx := context.Background()
			id := fmt.Sprintf("msg-%d", g%8)
			m := &mailbox.MessageInMailbox{UID: uint32(g), ProtonMessageID: id}
			if _, err := sess.bodySectionsForMessage(ctx, acct, m, []*imap.FetchItemBodySection{{}}); err != nil {
				t.Errorf("g=%d: %v", g, err)
			}
		}(g)
	}
	wg.Wait()
}
