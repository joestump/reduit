package oidc

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestPreSessionStorePutTake exercises the happy path: a state put on
// /auth/login, paired with a freshly generated bind token, is
// consumable exactly once on /auth/callback when the same bind token
// is supplied.
func TestPreSessionStorePutTake(t *testing.T) {
	t.Parallel()
	s := NewPreSessionStore(0)
	bind, err := NewBindToken()
	if err != nil {
		t.Fatalf("NewBindToken: %v", err)
	}
	s.Put(PreSession{
		State:        "abc",
		Nonce:        "nnn",
		CodeVerifier: "vvv",
		ReturnTo:     "/accounts",
		BindToken:    bind,
	})
	got, err := s.Take("abc", bind)
	if err != nil {
		t.Fatalf("Take(abc): %v", err)
	}
	if got.Nonce != "nnn" || got.CodeVerifier != "vvv" || got.ReturnTo != "/accounts" {
		t.Fatalf("Take returned %+v", got)
	}
	if got.BindToken != bind {
		t.Fatalf("Take.BindToken = %q, want %q", got.BindToken, bind)
	}
	if got.CreatedAt.IsZero() || got.ExpiresAt.IsZero() {
		t.Fatalf("expected timestamps populated: %+v", got)
	}
	// Single-use semantics: a second Take fails (with the correct token).
	if _, err := s.Take("abc", bind); !errors.Is(err, ErrPreSessionNotFound) {
		t.Fatalf("expected ErrPreSessionNotFound on replay; got %v", err)
	}
}

// TestPreSessionStoreExpiry checks that a stored entry past its TTL
// is treated as missing and is dropped from the store on access.
func TestPreSessionStoreExpiry(t *testing.T) {
	t.Parallel()
	s := NewPreSessionStore(0)
	frozen := time.Now()
	s.now = func() time.Time { return frozen }
	bind, _ := NewBindToken()
	s.Put(PreSession{State: "old", BindToken: bind})
	// Advance the clock past TTL.
	s.now = func() time.Time { return frozen.Add(DefaultPreSessionTTL + time.Second) }
	if _, err := s.Take("old", bind); !errors.Is(err, ErrPreSessionNotFound) {
		t.Fatalf("expected ErrPreSessionNotFound on expired entry; got %v", err)
	}
}

func TestPreSessionStoreSweepExpired(t *testing.T) {
	t.Parallel()
	s := NewPreSessionStore(time.Minute)
	frozen := time.Now()
	s.now = func() time.Time { return frozen }
	s.Put(PreSession{State: "a"})
	s.Put(PreSession{State: "b"})
	if got := s.Len(); got != 2 {
		t.Fatalf("Len = %d, want 2", got)
	}
	s.now = func() time.Time { return frozen.Add(2 * time.Minute) }
	if n := s.SweepExpired(); n != 2 {
		t.Fatalf("SweepExpired = %d, want 2", n)
	}
	if got := s.Len(); got != 0 {
		t.Fatalf("Len after sweep = %d, want 0", got)
	}
}

// TestPreSessionStoreTakeWrongBindFails covers the RFC 9700 §4.5
// defence: an attacker who guesses (or steals) the state value but
// cannot replay the browser-bound cookie MUST NOT be able to consume
// the pre-session. The same error type is returned for "wrong bind"
// and "missing state" so the callback handler is not an oracle.
func TestPreSessionStoreTakeWrongBindFails(t *testing.T) {
	t.Parallel()
	s := NewPreSessionStore(0)
	good, _ := NewBindToken()
	bad, _ := NewBindToken()
	if good == bad {
		t.Fatalf("two NewBindToken calls returned identical values; entropy bug")
	}
	s.Put(PreSession{State: "x", BindToken: good})
	if _, err := s.Take("x", bad); !errors.Is(err, ErrPreSessionNotFound) {
		t.Fatalf("Take(state, wrong-bind) err = %v, want ErrPreSessionNotFound", err)
	}
	// Side effect: the state slot was consumed even on a bad bind, so
	// an attacker cannot probe the same slot repeatedly with different
	// guesses. The legitimate browser's subsequent attempt must also
	// fail.
	if _, err := s.Take("x", good); !errors.Is(err, ErrPreSessionNotFound) {
		t.Fatalf("Take(state, good-bind) after probe err = %v, want ErrPreSessionNotFound", err)
	}
}

// TestPreSessionStoreTakeEmptyBindFails: an empty bind token from the
// browser (cookie missing or stripped) MUST NOT match a stored
// PreSession even when the State matches.
func TestPreSessionStoreTakeEmptyBindFails(t *testing.T) {
	t.Parallel()
	s := NewPreSessionStore(0)
	good, _ := NewBindToken()
	s.Put(PreSession{State: "y", BindToken: good})
	if _, err := s.Take("y", ""); !errors.Is(err, ErrPreSessionNotFound) {
		t.Fatalf("Take(state, empty) err = %v, want ErrPreSessionNotFound", err)
	}
}

// TestPreSessionStoreTakeStoredEmptyBindRefused: a PreSession whose
// stored BindToken is empty (a programming bug — /auth/login is
// supposed to call NewBindToken first) MUST also be unconsumable, so
// the store refuses to be the layer that lets a misuse slip through.
func TestPreSessionStoreTakeStoredEmptyBindRefused(t *testing.T) {
	t.Parallel()
	s := NewPreSessionStore(0)
	s.Put(PreSession{State: "z", BindToken: ""})
	if _, err := s.Take("z", ""); !errors.Is(err, ErrPreSessionNotFound) {
		t.Fatalf("Take(state, empty) on empty-bind entry err = %v, want ErrPreSessionNotFound", err)
	}
}

// TestPreSessionStoreConcurrentTakesGoodToken hammers the store with
// many goroutines all calling Take with the same state AND the same
// matching bind token (the user-double-click scenario). Exactly one
// MUST succeed; the rest MUST receive ErrPreSessionNotFound. Run with
// -race to catch shared-state mutation bugs.
func TestPreSessionStoreConcurrentTakesGoodToken(t *testing.T) {
	t.Parallel()
	s := NewPreSessionStore(0)
	good, _ := NewBindToken()
	s.Put(PreSession{State: "race", BindToken: good})

	const N = 32
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		successN int
	)
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			if _, err := s.Take("race", good); err == nil {
				mu.Lock()
				successN++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successN != 1 {
		t.Fatalf("got %d successful Takes, want exactly 1", successN)
	}
}

// TestPreSessionStoreConcurrentTakesMixedTokens has the legitimate
// token contend with concurrent attacker probes carrying random bind
// tokens. The store's "delete-on-mismatch" rule means a probe that
// wins the race consumes the slot, after which the legitimate Take
// returns ErrPreSessionNotFound — that is the intentional anti-probe
// behaviour. The asserts:
//
//   - At most one Take succeeds total.
//   - If a Take succeeds, the bind token used was the good one.
//
// (We cannot assert "the good token always wins" because that would
// be a scheduling race the test could not control deterministically;
// the security argument for the anti-probe rule is that an attacker
// does NOT know the state value, which is a 32-byte CSPRNG draw.)
func TestPreSessionStoreConcurrentTakesMixedTokens(t *testing.T) {
	t.Parallel()
	s := NewPreSessionStore(0)
	good, _ := NewBindToken()
	s.Put(PreSession{State: "race-mixed", BindToken: good})

	const N = 32
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		winning  string
		winCount int
	)
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			var attempt string
			if i == N/2 {
				attempt = good
			} else {
				attempt, _ = NewBindToken()
			}
			if _, err := s.Take("race-mixed", attempt); err == nil {
				mu.Lock()
				winCount++
				winning = attempt
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if winCount > 1 {
		t.Fatalf("got %d successful Takes, want at most 1", winCount)
	}
	if winCount == 1 && winning != good {
		t.Fatalf("a Take succeeded with bind=%q; only the good token (%q) should ever succeed", winning, good)
	}
}

// TestBuildBindCookieAttributes verifies the cookie shape
// /auth/login is expected to set: __Host- name, Path=/, Secure,
// HttpOnly, SameSite=Lax. The browser enforces these for the
// __Host- prefix; if any drift, the cookie is silently dropped.
func TestBuildBindCookieAttributes(t *testing.T) {
	t.Parallel()
	c := BuildBindCookie("tok", false)
	if c.Name != BindCookieName {
		t.Errorf("Name = %q, want %q", c.Name, BindCookieName)
	}
	if !strings.HasPrefix(c.Name, "__Host-") {
		t.Errorf("cookie name lacks __Host- prefix: %q", c.Name)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want /", c.Path)
	}
	if !c.Secure {
		t.Errorf("Secure = false, want true (production)")
	}
	if !c.HttpOnly {
		t.Errorf("HttpOnly = false, want true")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	if c.MaxAge <= 0 {
		t.Errorf("MaxAge = %d, want positive", c.MaxAge)
	}
	// Insecure mode (httptest plain HTTP) clears Secure.
	if c2 := BuildBindCookie("tok", true); c2.Secure {
		t.Errorf("BuildBindCookie(insecure=true).Secure = true, want false")
	}
}

// TestReadBindCookieRoundTrip exercises ReadBindCookie against an
// http.Request carrying the cookie that BuildBindCookie produces.
func TestReadBindCookieRoundTrip(t *testing.T) {
	t.Parallel()
	tok, _ := NewBindToken()
	r := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	r.AddCookie(BuildBindCookie(tok, true))
	if got := ReadBindCookie(r); got != tok {
		t.Fatalf("ReadBindCookie = %q, want %q", got, tok)
	}
	bare := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	if got := ReadBindCookie(bare); got != "" {
		t.Fatalf("ReadBindCookie(no cookie) = %q, want \"\"", got)
	}
	if got := ReadBindCookie(nil); got != "" {
		t.Fatalf("ReadBindCookie(nil) = %q, want \"\"", got)
	}
}
