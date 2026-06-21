// Per-account decrypted-body LRU cache + per-account Proton body-fetch
// limiter for the FETCH BODY[] path.
//
// Every FETCH BODY[] requires a full Proton fetch + decrypt of the
// message's RFC822 (Reduit stores no bodies locally). Two pathologies
// follow from that:
//
//  1. A client that re-FETCHes the same message (Apple Mail commonly
//     re-fetches BODY[] right after BODY[HEADER]) pays the full
//     fetch+decrypt cost every time.
//  2. A bulk `FETCH 1:* BODY[]` fans out one Proton fetch per message,
//     all racing under a single 30s budget — Proton gets hammered and
//     the whole command can time out.
//
// This file adds the two structures the design prescribes:
//
//   - bodyCache: a per-account LRU keyed by Proton message ID, bounded
//     by total decrypted size (default 32 MiB) and per-entry TTL
//     (default 5 min). Decrypted bodies never change for a given Proton
//     message ID, so a cache hit is always correct.
//   - fetchLimiter: a per-account weighted semaphore bounding the number
//     of concurrent in-flight Proton body fetches so a huge FETCH 1:*
//     cannot stampede Proton.
//
// Both live on the Backend (shared across all of an account's sessions)
// and are partitioned by account, so one account's bulk fetch never
// evicts another account's cached bodies or consumes another account's
// fetch slots.
//
// Governing: SPEC-0003 design "Performance considerations" — "We cache
// decrypted bodies in a small per-account LRU (by Proton message ID,
// configurable size, default 32 MiB). LRU evicts on size or TTL (5min)."

package imapserver

import (
	"container/list"
	"sync"
	"time"
)

const (
	// bodyCacheMaxBytes is the default per-account decrypted-body budget.
	// Matches design.md ("default 32 MiB"). Total cached body bytes for
	// one account never exceed this; the LRU evicts the coldest entries
	// to make room.
	bodyCacheMaxBytes = 32 * 1024 * 1024
	// bodyCacheTTL is the default per-entry lifetime. Matches design.md
	// ("LRU evicts on size or TTL (5min)"). A message body is stable for
	// the life of the Proton message, so the TTL exists only to bound
	// staleness of the (account, message ID) keyspace and reclaim memory
	// for messages a client touched once and abandoned, not for
	// correctness.
	bodyCacheTTL = 5 * time.Minute
	// bodyFetchConcurrency is the default ceiling on concurrent in-flight
	// Proton body fetches per account. Picked so a bulk FETCH 1:* keeps a
	// few fetches in flight (hiding per-request latency) without opening a
	// connection per message. Bodies that hit the cache never consume a
	// slot.
	bodyFetchConcurrency = 4
)

// cacheEntry is one decrypted body held in the LRU. size is cached
// alongside the bytes so eviction accounting never re-measures len(raw)
// (and stays correct even if a future caller hands us a sub-slice).
type cacheEntry struct {
	key      string
	raw      []byte
	size     int
	storedAt time.Time
}

// bodyCache is a single account's decrypted-body LRU. It is bounded by
// total byte size (maxBytes) and per-entry TTL. Construct via
// newBodyCache; the zero value is not usable.
//
// Concurrency: FETCH is served by concurrent goroutines, so every
// method takes the mutex. The critical sections are O(1) amortised
// (map + list splice); only size-eviction loops, and only until the
// budget is satisfied.
type bodyCache struct {
	mu       sync.Mutex
	ll       *list.List               // front = most-recently-used
	items    map[string]*list.Element // key -> element holding *cacheEntry
	curBytes int
	maxBytes int
	ttl      time.Duration
	now      func() time.Time
}

func newBodyCache(maxBytes int, ttl time.Duration) *bodyCache {
	return &bodyCache{
		ll:       list.New(),
		items:    make(map[string]*list.Element),
		maxBytes: maxBytes,
		ttl:      ttl,
		now:      time.Now,
	}
}

// get returns the cached body for key and true on a live (non-expired)
// hit, promoting it to most-recently-used. On a miss — or an entry past
// its TTL, which is evicted in place — it returns nil, false.
func (c *bodyCache) get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	ent := el.Value.(*cacheEntry)
	if c.now().Sub(ent.storedAt) >= c.ttl {
		// Lazily evict on access so a body that aged out between fetch
		// and re-fetch is never served stale, and its bytes are
		// reclaimed without waiting for size pressure.
		c.removeElement(el)
		return nil, false
	}
	c.ll.MoveToFront(el)
	return ent.raw, true
}

// put stores (or refreshes) the body for key, then evicts least-recently
// -used entries until the account is back under its byte budget. A body
// larger than the whole budget is not cached (storing it would evict
// everything else and still overflow), but callers still receive the
// bytes — the cache simply declines to hold it.
func (c *bodyCache) put(key string, raw []byte) {
	size := len(raw)
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		// Refresh in place: adjust the running total by the size delta,
		// reset the TTL clock, and promote.
		ent := el.Value.(*cacheEntry)
		c.curBytes += size - ent.size
		ent.raw = raw
		ent.size = size
		ent.storedAt = c.now()
		c.ll.MoveToFront(el)
		c.evictToBudgetLocked()
		return
	}

	if size > c.maxBytes {
		// A single oversize body would evict the entire cache and still
		// not fit. Decline to cache it rather than thrash everything.
		return
	}

	ent := &cacheEntry{key: key, raw: raw, size: size, storedAt: c.now()}
	el := c.ll.PushFront(ent)
	c.items[key] = el
	c.curBytes += size
	c.evictToBudgetLocked()
}

// evictToBudgetLocked drops least-recently-used entries until curBytes
// is within maxBytes. Caller must hold c.mu.
func (c *bodyCache) evictToBudgetLocked() {
	for c.curBytes > c.maxBytes {
		back := c.ll.Back()
		if back == nil {
			return
		}
		c.removeElement(back)
	}
}

// removeElement unlinks an element from both the list and the map and
// debits its bytes. Caller must hold c.mu.
func (c *bodyCache) removeElement(el *list.Element) {
	ent := el.Value.(*cacheEntry)
	c.ll.Remove(el)
	delete(c.items, ent.key)
	c.curBytes -= ent.size
}

// len reports the number of live entries (test/diagnostic helper).
func (c *bodyCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// bytes reports the current total cached size (test/diagnostic helper).
func (c *bodyCache) bytes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.curBytes
}

// fetchLimiter is a counting semaphore that bounds concurrent in-flight
// Proton body fetches for one account. acquire blocks (respecting the
// caller's context) until a slot frees; release returns one. A buffered
// channel is the idiomatic Go bounded semaphore and gives us
// context-cancellable acquisition for free.
type fetchLimiter struct {
	slots chan struct{}
}

func newFetchLimiter(n int) *fetchLimiter {
	if n < 1 {
		n = 1
	}
	return &fetchLimiter{slots: make(chan struct{}, n)}
}

// acquire takes a slot, blocking until one is free or the context is
// done. It returns ctx.Err() on cancellation so a fetch waiting behind a
// saturated limiter honours the FETCH command's deadline instead of
// hanging past it.
func (l *fetchLimiter) acquire(done <-chan struct{}) bool {
	select {
	case l.slots <- struct{}{}:
		return true
	case <-done:
		return false
	}
}

// release returns a previously acquired slot. It must be called exactly
// once per successful acquire.
func (l *fetchLimiter) release() {
	select {
	case <-l.slots:
	default:
		// Unreachable if acquire/release are balanced; guarded so a
		// double-release can never panic on an empty channel.
	}
}

// accountBodyCaches owns the per-account bodyCache + fetchLimiter pair,
// lazily created on first use and shared across every session for that
// account. One instance lives on the Backend.
//
// Partitioning by account is a correctness property, not just tidiness:
// the cache key is the Proton message ID, which is only unique within an
// account, and per-account fetch limiting is what the spec asks for.
type accountBodyCaches struct {
	mu          sync.Mutex
	caches      map[string]*bodyCache
	limiters    map[string]*fetchLimiter
	maxBytes    int
	ttl         time.Duration
	concurrency int
}

func newAccountBodyCaches() *accountBodyCaches {
	return &accountBodyCaches{
		caches:      make(map[string]*bodyCache),
		limiters:    make(map[string]*fetchLimiter),
		maxBytes:    bodyCacheMaxBytes,
		ttl:         bodyCacheTTL,
		concurrency: bodyFetchConcurrency,
	}
}

// cacheFor returns the account's body cache, creating it on first use.
func (a *accountBodyCaches) cacheFor(accountID string) *bodyCache {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.caches[accountID]
	if !ok {
		c = newBodyCache(a.maxBytes, a.ttl)
		a.caches[accountID] = c
	}
	return c
}

// limiterFor returns the account's fetch limiter, creating it on first
// use.
func (a *accountBodyCaches) limiterFor(accountID string) *fetchLimiter {
	a.mu.Lock()
	defer a.mu.Unlock()
	l, ok := a.limiters[accountID]
	if !ok {
		l = newFetchLimiter(a.concurrency)
		a.limiters[accountID] = l
	}
	return l
}
