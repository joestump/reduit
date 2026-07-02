package proton

import (
	"context"
	"errors"
	"testing"
)

// These tests exercise the concrete client's lifecycle guards, which are pure
// (they short-circuit before any network call) and so run without a live
// account. The network paths themselves are the thin edge delegated to
// go-proton-api and are not unit-tested here (ADR-0001).

func TestGPAClient_GuardsBeforeAuth(t *testing.T) {
	ctx := context.Background()
	c := &gpaClient{} // no manager call needed; cli is nil

	if err := c.SubmitTOTP(ctx, "123"); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("SubmitTOTP: %v", err)
	}
	if err := c.Unlock(ctx, []byte("p")); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("Unlock: %v", err)
	}
	if _, err := c.LatestEventID(ctx); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("LatestEventID: %v", err)
	}
	if _, err := c.GetEvents(ctx, "e0"); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("GetEvents: %v", err)
	}
	if err := c.Refresh(ctx); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("Refresh without token: %v", err)
	}
}

func TestGPAClient_GuardsBeforeUnlock(t *testing.T) {
	ctx := context.Background()
	c := &gpaClient{} // addrKRs nil => not unlocked

	if _, err := c.DecryptMessage(ctx, "m1"); !errors.Is(err, ErrNotUnlocked) {
		t.Errorf("DecryptMessage: %v", err)
	}
	if _, err := c.DecryptAttachment(ctx, "m1", "a1"); !errors.Is(err, ErrNotUnlocked) {
		t.Errorf("DecryptAttachment: %v", err)
	}
	if _, err := c.Send(ctx, validMsg()); !errors.Is(err, ErrNotUnlocked) {
		t.Errorf("Send: %v", err)
	}
}

func TestGPAClient_AccessorsZeroValue(t *testing.T) {
	c := &gpaClient{}
	if c.ProtonUserID() != "" {
		t.Error("ProtonUserID should be empty before auth")
	}
	if c.RefreshToken() != "" {
		t.Error("RefreshToken should be empty before auth")
	}
	if c.SessionUID() != "" {
		t.Error("SessionUID should be empty before auth")
	}
	c.Close() // must not panic with nil cli
}

func TestNewDialer_NewClientImplementsInterface(t *testing.T) {
	d := NewDialer(Config{HostURL: "https://example.invalid", AppVersion: "reduit@test"})
	defer d.Close()

	var _ Dialer = d
	c := d.NewClient()
	if c == nil {
		t.Fatal("NewClient returned nil")
	}
	if c.ProtonUserID() != "" {
		t.Error("fresh client should have no proton user id")
	}
	c.Close()
}

// addressByID resolves only unlocked addresses (used by Send to fill the
// sender). Verify the lookup logic directly.
func TestGPAClient_AddressByID(t *testing.T) {
	c := &gpaClient{}
	if _, ok := c.addressByID("missing"); ok {
		t.Error("addressByID found an address with empty table")
	}
}
