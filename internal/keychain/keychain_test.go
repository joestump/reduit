package keychain

import (
	"errors"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

// These tests run hermetically against go-keyring's in-memory mock provider —
// keyring.MockInit() swaps the package-global provider for a map-backed store,
// so no real macOS Keychain, libsecret, or Credential Manager is touched and
// no OS unlock prompt fires. The mock is a process-global, so these tests do
// NOT call t.Parallel(); each test reinstalls the mock it needs.

const testMailboxID = "0190f3a1-7c2b-7e44-9b1a-2c3d4e5f6071" // a UUIDv7-shaped id

// TestSetGetRoundTrip covers the create-then-read path for both secret kinds
// and asserts the stored value comes back byte-for-byte.
func TestSetGetRoundTrip(t *testing.T) {
	keyring.MockInit()
	s := New()

	cases := map[Kind]string{
		RefreshToken:      "refresh-token-value-123",
		MailboxPassphrase: "correct horse battery staple",
	}
	for kind, want := range cases {
		if err := s.Set(testMailboxID, kind, want); err != nil {
			t.Fatalf("Set(%s): %v", kind, err)
		}
		got, err := s.Get(testMailboxID, kind)
		if err != nil {
			t.Fatalf("Get(%s): %v", kind, err)
		}
		if got != want {
			t.Errorf("Get(%s) = %q, want %q", kind, got, want)
		}
	}
}

// TestSetOverwrites confirms a second Set replaces the prior value rather than
// erroring — re-auth overwrites the keychain secrets (SPEC-0007 REQ "Re-Auth
// Flow").
func TestSetOverwrites(t *testing.T) {
	keyring.MockInit()
	s := New()

	if err := s.Set(testMailboxID, RefreshToken, "old"); err != nil {
		t.Fatalf("first Set: %v", err)
	}
	if err := s.Set(testMailboxID, RefreshToken, "new"); err != nil {
		t.Fatalf("second Set: %v", err)
	}
	got, err := s.Get(testMailboxID, RefreshToken)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "new" {
		t.Errorf("Get = %q, want %q", got, "new")
	}
}

// TestGetMissingReturnsNotFound asserts a never-written secret reports
// ErrNotFound (distinct from an unavailable keyring).
func TestGetMissingReturnsNotFound(t *testing.T) {
	keyring.MockInit()
	s := New()

	_, err := s.Get(testMailboxID, RefreshToken)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing = %v, want ErrNotFound", err)
	}
}

// TestDelete covers deleting an existing secret and the missing-key error.
func TestDelete(t *testing.T) {
	keyring.MockInit()
	s := New()

	if err := s.Set(testMailboxID, MailboxPassphrase, "secret"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Delete(testMailboxID, MailboxPassphrase); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(testMailboxID, MailboxPassphrase); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after Delete = %v, want ErrNotFound", err)
	}
	if err := s.Delete(testMailboxID, MailboxPassphrase); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete missing = %v, want ErrNotFound", err)
	}
}

// TestDeleteAll asserts every kind for a mailbox is removed, that another
// mailbox's secrets survive (per-mailbox isolation, ADR-0013), and that
// DeleteAll is idempotent on an already-clean mailbox (SPEC-0007 scenario
// "Secrets deleted on mailbox removal").
func TestDeleteAll(t *testing.T) {
	keyring.MockInit()
	s := New()

	const otherMailboxID = "0190f3a1-7c2b-7e44-9b1a-aaaabbbbcccc"
	for _, id := range []string{testMailboxID, otherMailboxID} {
		if err := s.Set(id, RefreshToken, "rt-"+id); err != nil {
			t.Fatalf("Set RefreshToken %s: %v", id, err)
		}
		if err := s.Set(id, MailboxPassphrase, "pp-"+id); err != nil {
			t.Fatalf("Set MailboxPassphrase %s: %v", id, err)
		}
	}

	if err := s.DeleteAll(testMailboxID); err != nil {
		t.Fatalf("DeleteAll: %v", err)
	}

	for _, kind := range allKinds {
		if _, err := s.Get(testMailboxID, kind); !errors.Is(err, ErrNotFound) {
			t.Errorf("after DeleteAll, Get(%s) = %v, want ErrNotFound", kind, err)
		}
	}
	// The other mailbox's secrets must be untouched.
	for _, kind := range allKinds {
		if _, err := s.Get(otherMailboxID, kind); err != nil {
			t.Errorf("other mailbox Get(%s) = %v, want survival", kind, err)
		}
	}
	// Idempotent: a second DeleteAll on the now-empty mailbox is fine.
	if err := s.DeleteAll(testMailboxID); err != nil {
		t.Errorf("idempotent DeleteAll: %v", err)
	}
}

// TestAccountKeyFormat pins the exact "mailbox/<id>/<kind>" layout from
// ADR-0013 — a regression here would silently orphan or mis-route every
// secret.
func TestAccountKeyFormat(t *testing.T) {
	cases := []struct {
		kind Kind
		want string
	}{
		{RefreshToken, "mailbox/" + testMailboxID + "/refresh_token"},
		{MailboxPassphrase, "mailbox/" + testMailboxID + "/mailbox_passphrase"},
	}
	for _, c := range cases {
		got, err := accountKey(testMailboxID, c.kind)
		if err != nil {
			t.Fatalf("accountKey(%s): %v", c.kind, err)
		}
		if got != c.want {
			t.Errorf("accountKey(%s) = %q, want %q", c.kind, got, c.want)
		}
	}
}

// TestInvalidInputs covers the validation guards: bad kind and malformed
// mailbox id are rejected before any keyring call.
func TestInvalidInputs(t *testing.T) {
	keyring.MockInit()
	s := New()

	if err := s.Set(testMailboxID, Kind("bogus"), "x"); !errors.Is(err, ErrInvalidKind) {
		t.Errorf("Set bad kind = %v, want ErrInvalidKind", err)
	}
	if err := s.Set("", RefreshToken, "x"); !errors.Is(err, ErrInvalidMailboxID) {
		t.Errorf("Set empty id = %v, want ErrInvalidMailboxID", err)
	}
	if err := s.Set("has/slash", RefreshToken, "x"); !errors.Is(err, ErrInvalidMailboxID) {
		t.Errorf("Set id with slash = %v, want ErrInvalidMailboxID", err)
	}
	if err := s.DeleteAll(""); !errors.Is(err, ErrInvalidMailboxID) {
		t.Errorf("DeleteAll empty id = %v, want ErrInvalidMailboxID", err)
	}
}

// TestKeyringUnavailable simulates a missing/locked OS keyring via
// MockInitWithError and asserts every operation surfaces ErrUnavailable rather
// than a silent fallback (SPEC-0007 REQ "Keyring Availability").
func TestKeyringUnavailable(t *testing.T) {
	keyring.MockInitWithError(errors.New("dbus: connection refused"))
	t.Cleanup(keyring.MockInit) // restore a working mock for any later test
	s := New()

	if err := s.Set(testMailboxID, RefreshToken, "x"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Set = %v, want ErrUnavailable", err)
	}
	if _, err := s.Get(testMailboxID, RefreshToken); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Get = %v, want ErrUnavailable", err)
	}
	if err := s.Delete(testMailboxID, RefreshToken); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Delete = %v, want ErrUnavailable", err)
	}
	if err := s.DeleteAll(testMailboxID); !errors.Is(err, ErrUnavailable) {
		t.Errorf("DeleteAll = %v, want ErrUnavailable", err)
	}
}

// TestErrorsDoNotLeakSecret guards the "No Secret Leakage" requirement: even on
// a transport failure during Set, the returned error must not contain the
// secret value.
//
// Governing: SPEC-0007 REQ "No Secret Leakage" scenario "Errors do not echo
// secrets".
func TestErrorsDoNotLeakSecret(t *testing.T) {
	const secret = "super-secret-passphrase-do-not-print"
	keyring.MockInitWithError(errors.New("dbus: connection refused"))
	t.Cleanup(keyring.MockInit)
	s := New()

	err := s.Set(testMailboxID, MailboxPassphrase, secret)
	if err == nil {
		t.Fatal("expected error from unavailable keyring")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error string leaked the secret: %q", err.Error())
	}
}
