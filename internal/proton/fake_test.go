package proton

import (
	"context"
	"errors"
	"testing"
)

// Fake must satisfy the Client interface the downstream layers depend on.
var _ Client = (*Fake)(nil)

func TestFake_HappyPath_LoginTOTPUnlockSend(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	f.UserID = "user-xyz"
	f.Token = "rt-1"
	f.TwoFA = TwoFATOTP
	f.TOTPCode = "123456"
	f.Passphrase = "correct horse"
	f.SentID = "sent-1"

	st, err := f.Login(ctx, "joe@proton.me", []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if st.ProtonUserID != "user-xyz" || !st.Needs2FA() {
		t.Fatalf("unexpected status %+v", st)
	}

	// Send before unlock is refused.
	if _, err := f.Send(ctx, validMsg()); !errors.Is(err, ErrNotUnlocked) {
		t.Fatalf("send before unlock: err = %v, want ErrNotUnlocked", err)
	}
	// Unlock before clearing 2FA is refused.
	if err := f.Unlock(ctx, []byte("correct horse")); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("unlock with 2FA pending: err = %v, want ErrAuthFailed", err)
	}

	// Wrong then right TOTP.
	if err := f.SubmitTOTP(ctx, "000000"); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("wrong TOTP: err = %v, want ErrAuthFailed", err)
	}
	if err := f.SubmitTOTP(ctx, "123456"); err != nil {
		t.Fatal(err)
	}

	// Wrong then right passphrase.
	if err := f.Unlock(ctx, []byte("nope")); !errors.Is(err, ErrUnlockFailed) {
		t.Fatalf("wrong passphrase: err = %v, want ErrUnlockFailed", err)
	}
	if err := f.Unlock(ctx, []byte("correct horse")); err != nil {
		t.Fatal(err)
	}

	sent, err := f.Send(ctx, validMsg())
	if err != nil {
		t.Fatal(err)
	}
	if sent.MessageID != "sent-1" {
		t.Errorf("MessageID = %q, want sent-1", sent.MessageID)
	}
	if len(f.Sent) != 1 {
		t.Errorf("recorded %d sends, want 1", len(f.Sent))
	}
}

func TestFake_DataMethodsRequireAuthAndUnlock(t *testing.T) {
	ctx := context.Background()
	f := NewFake()

	if _, err := f.LatestEventID(ctx); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("LatestEventID before auth: %v", err)
	}
	if _, err := f.GetEvents(ctx, "e0"); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("GetEvents before auth: %v", err)
	}
	if _, err := f.DecryptMessage(ctx, "m1"); !errors.Is(err, ErrNotUnlocked) {
		t.Errorf("DecryptMessage before unlock: %v", err)
	}
	if _, err := f.DecryptAttachment(ctx, "m1", "a1"); !errors.Is(err, ErrNotUnlocked) {
		t.Errorf("DecryptAttachment before unlock: %v", err)
	}
}

func TestFake_EventDrainingAndCursorEcho(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	f.TwoFA = TwoFANone
	if _, err := f.Login(ctx, "a", nil); err != nil {
		t.Fatal(err)
	}
	f.LatestEvent = "head"
	f.Batches = []EventBatch{
		{Events: []Event{{EventID: "e1"}}, NextCursor: "e1", More: true},
		{Events: []Event{{EventID: "e2"}}, NextCursor: "e2", More: false},
	}

	if id, _ := f.LatestEventID(ctx); id != "head" {
		t.Errorf("LatestEventID = %q, want head", id)
	}
	b1, _ := f.GetEvents(ctx, "e0")
	if b1.NextCursor != "e1" || !b1.More {
		t.Errorf("batch1 = %+v", b1)
	}
	b2, _ := f.GetEvents(ctx, "e1")
	if b2.NextCursor != "e2" || b2.More {
		t.Errorf("batch2 = %+v", b2)
	}
	// Drained: cursor echoes the request, no events.
	b3, _ := f.GetEvents(ctx, "e2")
	if b3.NextCursor != "e2" || len(b3.Events) != 0 {
		t.Errorf("drained batch = %+v, want cursor echo e2 and no events", b3)
	}
}

func TestFake_RefreshRotatesToken(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	f.Token = "rt-0"
	f.RefreshTokens = []string{"rt-1", "rt-2"}

	if err := f.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if f.RefreshToken() != "rt-1" {
		t.Errorf("after 1st refresh token = %q, want rt-1", f.RefreshToken())
	}
	if err := f.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if f.RefreshToken() != "rt-2" {
		t.Errorf("after 2nd refresh token = %q, want rt-2", f.RefreshToken())
	}
	if f.RefreshCalls != 2 {
		t.Errorf("RefreshCalls = %d, want 2", f.RefreshCalls)
	}
}

func TestFake_SendValidates(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	f.TwoFA = TwoFANone
	_, _ = f.Login(ctx, "a", nil)
	_ = f.Unlock(ctx, nil)

	bad := validMsg()
	bad.Subject = ""
	if _, err := f.Send(ctx, bad); err == nil {
		t.Fatal("expected validation error for empty subject")
	}
	if len(f.Sent) != 0 {
		t.Error("invalid send should not be recorded")
	}
}

func TestFake_ScriptedErrors(t *testing.T) {
	ctx := context.Background()
	sentinel := errors.New("boom")

	f := NewFake()
	f.LoginErr = sentinel
	if _, err := f.Login(ctx, "a", nil); !errors.Is(err, sentinel) {
		t.Errorf("LoginErr not returned: %v", err)
	}

	f2 := NewFake()
	f2.TwoFA = TwoFANone
	_, _ = f2.Login(ctx, "a", nil)
	f2.UnlockErr = sentinel
	if err := f2.Unlock(ctx, nil); !errors.Is(err, sentinel) {
		t.Errorf("UnlockErr not returned: %v", err)
	}
}
