package oidc

import (
	"errors"
	"testing"
	"time"
)

// TestPreSessionStorePutTake exercises the happy path: a state put on
// /auth/login is consumable exactly once on /auth/callback.
func TestPreSessionStorePutTake(t *testing.T) {
	t.Parallel()
	s := NewPreSessionStore(0)
	s.Put(PreSession{
		State:        "abc",
		Nonce:        "nnn",
		CodeVerifier: "vvv",
		ReturnTo:     "/accounts",
	})
	got, err := s.Take("abc")
	if err != nil {
		t.Fatalf("Take(abc): %v", err)
	}
	if got.Nonce != "nnn" || got.CodeVerifier != "vvv" || got.ReturnTo != "/accounts" {
		t.Fatalf("Take returned %+v", got)
	}
	if got.CreatedAt.IsZero() || got.ExpiresAt.IsZero() {
		t.Fatalf("expected timestamps populated: %+v", got)
	}
	// Single-use semantics: a second Take fails.
	if _, err := s.Take("abc"); !errors.Is(err, ErrPreSessionNotFound) {
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
	s.Put(PreSession{State: "old"})
	// Advance the clock past TTL.
	s.now = func() time.Time { return frozen.Add(DefaultPreSessionTTL + time.Second) }
	if _, err := s.Take("old"); !errors.Is(err, ErrPreSessionNotFound) {
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
