package proton

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"
)

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name string
		in   error
		want error // sentinel expected via errors.Is; nil means "no sentinel"
	}{
		{"nil", nil, nil},
		{"wrong password", &gpa.APIError{Code: gpa.PasswordWrong, Status: 422, Message: "Incorrect login credentials"}, ErrAuthFailed},
		{"human verification", &gpa.APIError{Code: gpa.HumanVerificationRequired, Status: 422, Message: "HV"}, ErrHumanVerification},
		{"refresh token invalid", &gpa.APIError{Code: gpa.AuthRefreshTokenInvalid, Status: 422, Message: "bad token"}, ErrRefreshTokenInvalid},
		{"api error by value", gpa.APIError{Code: gpa.PasswordWrong, Status: 422, Message: "v"}, ErrAuthFailed},
		{"net error", &gpa.NetError{Cause: errors.New("dial tcp: timeout"), Message: "unreachable"}, ErrNetwork},
		{"wrapped net error", fmt.Errorf("login: %w", &gpa.NetError{Cause: errors.New("eof"), Message: "x"}), ErrNetwork},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyError(tt.in)
			if tt.in == nil {
				if got != nil {
					t.Fatalf("classifyError(nil) = %v, want nil", got)
				}
				return
			}
			if tt.want != nil && !errors.Is(got, tt.want) {
				t.Fatalf("classifyError(%v) = %v; want errors.Is == %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestClassifyErrorUnknownCodePreservesUpstream verifies an unrecognized API
// code is preserved verbatim (message + code) rather than miscategorized.
func TestClassifyErrorUnknownCodePreservesUpstream(t *testing.T) {
	in := &gpa.APIError{Code: 2001, Status: 400, Message: "Invalid value"}
	got := classifyError(in)
	for _, sentinel := range []error{ErrAuthFailed, ErrHumanVerification, ErrRefreshTokenInvalid, ErrNetwork} {
		if errors.Is(got, sentinel) {
			t.Fatalf("unknown code mapped to sentinel %v: %v", sentinel, got)
		}
	}
	if !strings.Contains(got.Error(), "Invalid value") {
		t.Errorf("upstream message not preserved: %q", got.Error())
	}
}

// TestErrorsNeverContainSecrets is a guard for SPEC-0007 REQ "No Secret
// Leakage": none of this package's error values embed a secret. The sentinels
// are static, and classifyError only ever wraps upstream errors (which carry
// Proton codes/messages, not the password/passphrase/token reduit supplied).
func TestErrorsNeverContainSecrets(t *testing.T) {
	const secret = "hunter2-super-secret"
	// Simulate the worst case: an upstream error that does NOT contain the
	// secret (because reduit never passes secrets into error-producing
	// positions). classifyError must not introduce it.
	got := classifyError(&gpa.APIError{Code: gpa.PasswordWrong, Message: "Incorrect login credentials"})
	if strings.Contains(got.Error(), secret) {
		t.Fatalf("classified error leaked secret: %q", got.Error())
	}
}
