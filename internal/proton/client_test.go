// Governing: ADR-0001 (go-proton-api as Proton client).

package proton

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// newTestManager builds a Manager pointed at the given httptest server.
// All wrapper tests use this helper so the tests stay focused on the
// wrapper's behaviour, not the manager wiring.
func newTestManager(t *testing.T, srv *httptest.Server, opts ...Option) *Manager {
	t.Helper()
	all := append([]Option{
		WithHostURL(srv.URL),
		WithAppVersion("reduit-test/0.0.1"),
	}, opts...)
	m := NewManager(all...)
	t.Cleanup(m.Close)
	return m
}

func TestClient_AuthInfo_RoundTrip(t *testing.T) {
	t.Parallel()

	want := AuthInfo{
		Version:         4,
		Modulus:         "MODULUS",
		ServerEphemeral: "EPH",
		Salt:            "SALT",
		SRPSession:      "SRP",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/v4/info" {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		var body AuthInfoReq
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Username != "joe@example.com" {
			http.Error(w, "wrong username "+body.Username, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	}))
	t.Cleanup(srv.Close)

	m := newTestManager(t, srv)
	c := m.NewClient(context.Background(), "uid", "acc", "ref")

	got, err := c.AuthInfo(context.Background(), AuthInfoReq{Username: "joe@example.com"})
	if err != nil {
		t.Fatalf("AuthInfo: %v", err)
	}
	if got.Version != want.Version || got.Modulus != want.Modulus || got.SRPSession != want.SRPSession {
		t.Fatalf("AuthInfo mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}

func TestClient_GetEvent(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/core/v4/events/") {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "want GET", http.StatusMethodNotAllowed)
			return
		}
		// The upstream client unmarshals into a struct that embeds
		// Event and adds More. Returning EventID + More=false at the
		// top level satisfies both fields.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"EventID":"evt-2","More":0}`))
	}))
	t.Cleanup(srv.Close)

	m := newTestManager(t, srv)
	c := m.NewClient(context.Background(), "uid", "acc", "ref")

	events, more, err := c.GetEvent(context.Background(), "evt-1")
	if err != nil {
		t.Fatalf("GetEvent: %v", err)
	}
	if more {
		t.Fatalf("expected more=false, got true")
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].EventID != "evt-2" {
		t.Fatalf("expected event id evt-2, got %q", events[0].EventID)
	}
}

// TestClient_GetLatestEventID covers the production path of the new
// method clientImpl.GetLatestEventID added for SPEC-0002 REQ "Event
// Cursor Persistence" (first-boot bootstrap). Mirrors the shape of
// TestClient_GetEvent so the requireSession() guard, defer release(),
// and upstream forwarding all execute against an httptest backend.
//
// PR #41 hostile-review fix: the previous version of this PR
// exercised GetLatestEventID only via the in-package fakeProtonClient,
// leaving the production wrapper untested.
func TestClient_GetLatestEventID(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/core/v4/events/latest" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"EventID":"evt-latest"}`))
		case r.URL.Path == "/auth/v4" && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unexpected request "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	m := newTestManager(t, srv)
	c := m.NewClient(context.Background(), "uid", "acc", "ref")

	got, err := c.GetLatestEventID(context.Background())
	if err != nil {
		t.Fatalf("GetLatestEventID: %v", err)
	}
	if got != "evt-latest" {
		t.Errorf("EventID = %q, want evt-latest", got)
	}

	// Post-Logout path: a client whose session has been torn down
	// must reject the call rather than silently returning an empty
	// cursor (which would be indistinguishable from a real
	// "no events ever" answer).
	if err := c.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := c.GetLatestEventID(context.Background()); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("post-Logout GetLatestEventID error = %v, want ErrNotAuthenticated", err)
	}
}

func TestClient_ListMessages(t *testing.T) {
	t.Parallel()

	var calls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mail/v4/messages" {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		if got := r.Header.Get("X-HTTP-Method-Override"); got != "GET" {
			http.Error(w, "missing X-HTTP-Method-Override:GET (got "+got+")", http.StatusBadRequest)
			return
		}
		n := atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		switch n {
		case 1:
			// Count call.
			_, _ = w.Write([]byte(`{"Total":1}`))
		default:
			// Page call.
			_, _ = w.Write([]byte(`{"Messages":[{"ID":"m1","Subject":"hello"}],"Stale":0}`))
		}
	}))
	t.Cleanup(srv.Close)

	m := newTestManager(t, srv)
	c := m.NewClient(context.Background(), "uid", "acc", "ref")

	msgs, err := c.ListMessages(context.Background(), MessageFilter{})
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].ID != "m1" || msgs[0].Subject != "hello" {
		t.Fatalf("unexpected message: %+v", msgs[0])
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected 2 server calls (count + page), got %d", got)
	}
}

func TestClient_RefreshTokenCallback_FiresOn401(t *testing.T) {
	t.Parallel()

	const (
		uid       = "uid-abc"
		oldRef    = "old-refresh"
		newAcc    = "new-access"
		newRef    = "new-refresh"
		newUserID = "user-1"
	)

	var (
		messageCalls int32
		refreshCalls int32
		// refreshBody captures the most recent /auth/v4/refresh request
		// payload so we can assert on Concern 5 of the hostile review:
		// the upstream client must actually adopt the rotated refresh
		// token, not just fire a callback with the right string.
		refreshBodyMu sync.Mutex
		refreshBodies []string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/v4/refresh" && r.Method == http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			refreshBodyMu.Lock()
			refreshBodies = append(refreshBodies, string(body))
			refreshBodyMu.Unlock()
			n := atomic.AddInt32(&refreshCalls, 1)
			// Each rotation hands back a fresh refresh token so we
			// can assert the upstream client adopted the previous
			// one (i.e. the second refresh-body should carry newRef
			// not oldRef).
			ref := newRef
			if n > 1 {
				ref = newRef + "-2"
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"UserID":       newUserID,
				"UID":          uid,
				"AccessToken":  newAcc,
				"RefreshToken": ref,
				"Scope":        "self",
			})
		case strings.HasPrefix(r.URL.Path, "/mail/v4/messages/"):
			n := atomic.AddInt32(&messageCalls, 1)
			// Calls 1 and 3 simulate an expired access token; calls
			// 2 and 4 should carry the freshly rotated bearer.
			if n == 1 || n == 3 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"Code":401,"Error":"access token expired"}`))
				return
			}
			if got := r.Header.Get("Authorization"); got != "Bearer "+newAcc {
				http.Error(w, "wrong access token: "+got, http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Message":{"ID":"m1","Subject":"after refresh"}}`))
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	var (
		gotRefresh    atomic.Value // string
		callbackCalls int32
	)
	cb := func(_ context.Context, refresh string) error {
		atomic.AddInt32(&callbackCalls, 1)
		gotRefresh.Store(refresh)
		return nil
	}

	m := newTestManager(t, srv, WithRefreshTokenCallback(cb))
	c := m.NewClient(context.Background(), uid, "expired-access", oldRef)

	msg, err := c.GetMessage(context.Background(), "m1")
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if msg.ID != "m1" || msg.Subject != "after refresh" {
		t.Fatalf("unexpected message: %+v", msg)
	}

	if got := atomic.LoadInt32(&refreshCalls); got != 1 {
		t.Fatalf("expected exactly 1 refresh call, got %d", got)
	}
	if got := atomic.LoadInt32(&messageCalls); got != 2 {
		t.Fatalf("expected 2 message calls (401 + retry), got %d", got)
	}
	if got := atomic.LoadInt32(&callbackCalls); got != 1 {
		t.Fatalf("expected refresh-token callback fired once, got %d", got)
	}
	if v, _ := gotRefresh.Load().(string); v != newRef {
		t.Fatalf("expected callback to receive %q, got %q", newRef, v)
	}

	// Trigger a second 401 -> /auth/v4/refresh round-trip. If the
	// upstream client really adopted newRef the second refresh request
	// body must contain newRef (not oldRef). This catches the bug
	// where the callback fires with the right string but the upstream
	// client was silently still pinned to the old refresh token.
	if _, err := c.GetMessage(context.Background(), "m1"); err != nil {
		t.Fatalf("second GetMessage: %v", err)
	}
	refreshBodyMu.Lock()
	defer refreshBodyMu.Unlock()
	if len(refreshBodies) != 2 {
		t.Fatalf("expected 2 refresh bodies, got %d", len(refreshBodies))
	}
	if !strings.Contains(refreshBodies[1], newRef) {
		t.Fatalf("second refresh request must carry newRef=%q in body; got %q", newRef, refreshBodies[1])
	}
}

// TestManager_SetRefreshTokenCallback_LateBindingFires asserts the
// fix for hostile-review Blocker 2 of PR #37: a callback registered
// after NewManager (and after a Client has been minted) MUST still
// fire on the next refresh rotation. The previous implementation
// captured the callback at adopt time, so a later setter would be
// silently ignored. We now resolve the callback inside the handler
// closure — this test pins that contract.
func TestManager_SetRefreshTokenCallback_LateBindingFires(t *testing.T) {
	t.Parallel()

	const (
		uid    = "uid-late"
		oldRef = "old-refresh"
		newAcc = "new-access"
		newRef = "late-refresh"
	)

	var messageCalls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/v4/refresh" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"UserID":       "user-1",
				"UID":          uid,
				"AccessToken":  newAcc,
				"RefreshToken": newRef,
				"Scope":        "self",
			})
		case strings.HasPrefix(r.URL.Path, "/mail/v4/messages/"):
			n := atomic.AddInt32(&messageCalls, 1)
			if n == 1 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"Code":401,"Error":"access token expired"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Message":{"ID":"m1","Subject":"after refresh"}}`))
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	// Manager constructed WITHOUT WithRefreshTokenCallback — and a
	// Client minted before any callback is registered.
	m := newTestManager(t, srv)
	c := m.NewClient(context.Background(), uid, "expired-access", oldRef)

	// Now wire the callback after construction (after the Client
	// already has its auth handler installed).
	var (
		got           atomic.Value // string
		callbackCalls int32
	)
	m.SetRefreshTokenCallback(func(_ context.Context, refresh string) error {
		atomic.AddInt32(&callbackCalls, 1)
		got.Store(refresh)
		return nil
	})

	if _, err := c.GetMessage(context.Background(), "m1"); err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if n := atomic.LoadInt32(&callbackCalls); n != 1 {
		t.Fatalf("expected late-bound callback to fire exactly once, got %d", n)
	}
	if v, _ := got.Load().(string); v != newRef {
		t.Fatalf("expected late-bound callback to receive %q, got %q", newRef, v)
	}
}

func TestClient_RequireSession(t *testing.T) {
	t.Parallel()

	m := NewManager()
	t.Cleanup(m.Close)

	// A pre-auth client (no session) should reject session-bearing
	// methods with ErrNotAuthenticated. We hit a method that does
	// not need to talk to the network so we don't spin up a server.
	c := &clientImpl{mgr: m} // intentionally not adopted
	_, err := c.KeySalts(context.Background())
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("expected ErrNotAuthenticated, got %v", err)
	}
}

// TestClient_GetMessageRFC822_RequiresSession confirms the FETCH BODY[]
// retrieval path is gated behind an active session: a pre-auth client
// returns ErrNotAuthenticated before it ever reaches the keyring lookup.
//
// Governing: SPEC-0003 design "FETCH BODY[] on big messages".
func TestClient_GetMessageRFC822_RequiresSession(t *testing.T) {
	t.Parallel()

	m := NewManager()
	t.Cleanup(m.Close)
	c := &clientImpl{mgr: m} // intentionally not adopted
	if _, err := c.GetMessageRFC822(context.Background(), "msg-1"); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("pre-auth GetMessageRFC822 error = %v, want ErrNotAuthenticated", err)
	}
}

// TestClient_KeyRingFor covers the keyring-selection logic the FETCH
// BODY[] path relies on: exact AddressID match, single-keyring fallback
// for an unmatched/empty AddressID, ErrNotUnlocked when nothing is
// unlocked, and ErrNotUnlocked when a multi-address account cannot match
// the requested AddressID (picking arbitrarily would risk a decrypt
// failure).
//
// We use a non-nil sentinel *crypto.KeyRing pointer purely for identity
// comparison — keyRingFor never dereferences it.
func TestClient_KeyRingFor(t *testing.T) {
	t.Parallel()

	krA := &KeyRing{}
	krB := &KeyRing{}

	t.Run("not unlocked", func(t *testing.T) {
		t.Parallel()
		c := &clientImpl{}
		if _, err := c.keyRingFor("addr-1"); !errors.Is(err, ErrNotUnlocked) {
			t.Fatalf("err = %v, want ErrNotUnlocked", err)
		}
	})

	t.Run("exact match", func(t *testing.T) {
		t.Parallel()
		c := &clientImpl{addrKeyRings: map[string]*KeyRing{"addr-1": krA, "addr-2": krB}}
		got, err := c.keyRingFor("addr-2")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if got != krB {
			t.Fatalf("got keyring %p, want %p", got, krB)
		}
	})

	t.Run("single-keyring fallback on unmatched id", func(t *testing.T) {
		t.Parallel()
		c := &clientImpl{addrKeyRings: map[string]*KeyRing{"addr-1": krA}}
		got, err := c.keyRingFor("does-not-exist")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if got != krA {
			t.Fatalf("got keyring %p, want %p", got, krA)
		}
	})

	t.Run("multi-keyring unmatched id is not unlocked", func(t *testing.T) {
		t.Parallel()
		c := &clientImpl{addrKeyRings: map[string]*KeyRing{"addr-1": krA, "addr-2": krB}}
		if _, err := c.keyRingFor("addr-3"); !errors.Is(err, ErrNotUnlocked) {
			t.Fatalf("err = %v, want ErrNotUnlocked", err)
		}
	})
}

// fakeAccount is a minimal AccountSnapshot used to exercise WithAccount
// without dragging in the real account service (which lives behind the
// foundation work for issue #10 and is not yet on main).
type fakeAccount struct {
	uid, access, refresh string
}

func (f fakeAccount) UID() string          { return f.uid }
func (f fakeAccount) AccessToken() string  { return f.access }
func (f fakeAccount) RefreshToken() string { return f.refresh }

func TestManager_WithAccount_HydratesClient(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/core/v4/events/") {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		// Confirm the per-account access token actually rides the wire.
		if got := r.Header.Get("Authorization"); got != "Bearer acc-from-snapshot" {
			http.Error(w, "wrong access token: "+got, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"EventID":"evt-2","More":0}`))
	}))
	t.Cleanup(srv.Close)

	m := newTestManager(t, srv)
	snap := fakeAccount{
		uid:     "uid-from-snapshot",
		access:  "acc-from-snapshot",
		refresh: "ref-from-snapshot",
	}

	c, err := m.WithAccount(context.Background(), snap)
	if err != nil {
		t.Fatalf("WithAccount: %v", err)
	}
	if c == nil {
		t.Fatalf("WithAccount returned nil client")
	}

	events, _, err := c.GetEvent(context.Background(), "evt-1")
	if err != nil {
		t.Fatalf("GetEvent: %v", err)
	}
	if len(events) != 1 || events[0].EventID != "evt-2" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestManager_WithAccount_RejectsEmptySnapshot(t *testing.T) {
	t.Parallel()

	m := NewManager()
	t.Cleanup(m.Close)

	cases := map[string]AccountSnapshot{
		"nil":             nil,
		"missing uid":     fakeAccount{access: "a", refresh: "r"},
		"missing access":  fakeAccount{uid: "u", refresh: "r"},
		"missing refresh": fakeAccount{uid: "u", access: "a"},
	}
	for name, snap := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, err := m.WithAccount(context.Background(), snap)
			if !errors.Is(err, ErrNotAuthenticated) {
				t.Fatalf("expected ErrNotAuthenticated, got %v", err)
			}
			if c != nil {
				t.Fatalf("expected nil client, got %#v", c)
			}
		})
	}
}

func TestClient_LogoutIdempotent(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/v4" && r.Method == http.MethodDelete {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Code":1000}`))
			return
		}
		http.Error(w, "unexpected", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	m := newTestManager(t, srv)
	c := m.NewClient(context.Background(), "uid", "acc", "ref")

	if err := c.Logout(context.Background()); err != nil {
		t.Fatalf("first Logout: %v", err)
	}
	// Second call must be a no-op (no panic, no network).
	if err := c.Logout(context.Background()); err != nil {
		t.Fatalf("second Logout: %v", err)
	}
}

// TestClient_LogoutVsConcurrentReads_NoRace exercises the lifecycle
// RWMutex against `go test -race`: many ListMessages goroutines fire
// in parallel while a Logout races them. The contract is:
//
//   - No goroutine panics or trips the race detector.
//   - In-flight ListMessages calls observe a coherent state — either
//     the upstream client is alive (call succeeds) or the session was
//     already torn down (ErrNotAuthenticated).
//   - Once Logout returns, every subsequent call returns
//     ErrNotAuthenticated.
//
// Governing: hostile-review Blocker 3 of PR #37.
func TestClient_LogoutVsConcurrentReads_NoRace(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/v4" && r.Method == http.MethodDelete:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Code":1000}`))
		case r.URL.Path == "/mail/v4/messages":
			// Two-call dance: first GET-via-override returns the
			// message count, second returns the page.
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Query().Get("Page") == "" && r.URL.Query().Get("PageSize") == "" {
				_, _ = w.Write([]byte(`{"Total":1}`))
				return
			}
			_, _ = w.Write([]byte(`{"Messages":[{"ID":"m1","Subject":"x"}],"Stale":0}`))
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	m := newTestManager(t, srv)
	c := m.NewClient(context.Background(), "uid", "acc", "ref")

	const workers = 16
	var (
		wg    sync.WaitGroup
		ready sync.WaitGroup
		start = make(chan struct{})
	)
	wg.Add(workers)
	ready.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			ready.Done()
			<-start
			for range 40 {
				_, err := c.ListMessages(context.Background(), MessageFilter{})
				if err != nil && !errors.Is(err, ErrNotAuthenticated) {
					// Any non-authentication error means the
					// upstream call ran on a torn-down client
					// — that's the race we're trying to prevent.
					t.Errorf("unexpected ListMessages error: %v", err)
					return
				}
			}
		}()
	}
	ready.Wait()
	close(start)

	// Race the Logout against the in-flight readers.
	if err := c.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	wg.Wait()

	// Post-Logout, every call must be ErrNotAuthenticated.
	if _, err := c.ListMessages(context.Background(), MessageFilter{}); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("post-Logout ListMessages must return ErrNotAuthenticated, got %v", err)
	}
}

// TestManager_NewClientWithLogin_FailsIfInitialPersistFails asserts the
// fix for hostile-review Concern 4 of PR #37: when the persistence
// callback fails on the initial-token write, NewClientWithLogin must
// fail the login (not log-and-shrug). Otherwise the caller believes a
// session exists for which Reduit has no on-disk record.
func TestManager_NewClientWithLogin_FailsIfInitialPersistFails(t *testing.T) {
	// We cannot exercise the full SRP login against an httptest
	// server (the upstream client expects a Proton-shaped SRP
	// exchange). Drive the helper directly instead — that's where
	// the policy lives.
	t.Parallel()

	m := NewManager()
	t.Cleanup(m.Close)

	wantErr := errors.New("disk full")
	m.SetRefreshTokenCallback(func(_ context.Context, _ string) error {
		return wantErr
	})

	err := m.fireInitialRefreshCallback(context.Background(), "anything")
	if err == nil {
		t.Fatalf("expected non-nil error from fireInitialRefreshCallback")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped wantErr, got %v", err)
	}
}
