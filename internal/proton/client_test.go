// Governing: ADR-0001 (go-proton-api as Proton client).

package proton

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/v4/refresh" && r.Method == http.MethodPost:
			atomic.AddInt32(&refreshCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"UserID":       newUserID,
				"UID":          uid,
				"AccessToken":  newAcc,
				"RefreshToken": newRef,
				"Scope":        "self",
			})
		case strings.HasPrefix(r.URL.Path, "/mail/v4/messages/"):
			n := atomic.AddInt32(&messageCalls, 1)
			if n == 1 {
				// First call: simulate expired access token.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"Code":401,"Error":"access token expired"}`))
				return
			}
			// Subsequent call: must carry the new access token.
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
		"nil":            nil,
		"missing uid":    fakeAccount{access: "a", refresh: "r"},
		"missing access": fakeAccount{uid: "u", refresh: "r"},
		"missing refresh": fakeAccount{
			uid: "u", access: "a",
		},
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
