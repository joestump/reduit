package proton

import (
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"
)

func TestClassify2FA(t *testing.T) {
	tests := []struct {
		name string
		in   gpa.TwoFAInfo
		want TwoFAState
	}{
		{"none", gpa.TwoFAInfo{Enabled: 0}, TwoFANone},
		{"totp", gpa.TwoFAInfo{Enabled: gpa.HasTOTP}, TwoFATOTP},
		{"fido2-and-totp prefers totp", gpa.TwoFAInfo{Enabled: gpa.HasFIDO2AndTOTP}, TwoFATOTP},
		{"fido2-only unsupported", gpa.TwoFAInfo{Enabled: gpa.HasFIDO2}, TwoFAUnsupported},
		{"unknown nonzero is unsupported", gpa.TwoFAInfo{Enabled: 99}, TwoFAUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classify2FA(tt.in); got != tt.want {
				t.Fatalf("classify2FA(%v) = %v, want %v", tt.in.Enabled, got, tt.want)
			}
		})
	}
}

func TestAuthStatusNeeds2FA(t *testing.T) {
	if !(AuthStatus{TwoFA: TwoFATOTP}).Needs2FA() {
		t.Error("TwoFATOTP should need 2FA")
	}
	if (AuthStatus{TwoFA: TwoFANone}).Needs2FA() {
		t.Error("TwoFANone should not need 2FA")
	}
	if (AuthStatus{TwoFA: TwoFAUnsupported}).Needs2FA() {
		t.Error("TwoFAUnsupported is not a TOTP challenge the caller can satisfy")
	}
}

func TestTwoFAStateString(t *testing.T) {
	for st, want := range map[TwoFAState]string{
		TwoFANone:        "none",
		TwoFATOTP:        "totp",
		TwoFAUnsupported: "unsupported",
		TwoFAState(42):   "unknown",
	} {
		if got := st.String(); got != want {
			t.Errorf("TwoFAState(%d).String() = %q, want %q", st, got, want)
		}
	}
}
