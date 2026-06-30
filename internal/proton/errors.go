package proton

import (
	"errors"
	"fmt"

	gpa "github.com/ProtonMail/go-proton-api"
)

// Sentinel errors let the auth/sync/send layers branch on a failure's meaning
// without parsing go-proton-api's wire errors or its messages. classifyError
// maps upstream errors onto these; callers use errors.Is.
//
// Governing: SPEC-0007 REQ "SRP and 2FA Handling" (the auth flow must
// distinguish wrong-credentials from human-verification from a generic
// failure, and must not echo secrets), ADR-0001 (upstream error tables).
var (
	// ErrAuthFailed is a rejected password or TOTP code (SPEC-0007 scenario
	// "Wrong password or 2FA code"). The message never contains the secret.
	ErrAuthFailed = errors.New("proton: authentication failed")

	// ErrHumanVerification is Proton requesting human verification / CAPTCHA
	// (SPEC-0007 scenario "Human verification / CAPTCHA is requested"). The
	// auth flow surfaces actionable guidance instead of crashing.
	ErrHumanVerification = errors.New("proton: human verification required")

	// ErrRefreshTokenInvalid means the stored refresh token is no longer
	// valid; the mailbox needs re-auth (SPEC-0007 REQ "Re-Auth Flow"). Sync
	// maps this to the needs_reauth state.
	ErrRefreshTokenInvalid = errors.New("proton: refresh token invalid")

	// ErrNetwork is a transport-level failure reaching Proton; the operation
	// may succeed on retry (ADR-0014 — sync is resumable).
	ErrNetwork = errors.New("proton: network error")

	// ErrNotAuthenticated is returned by methods that need a session before
	// Login (or a successful Resume) has established one.
	ErrNotAuthenticated = errors.New("proton: not authenticated")

	// ErrNotUnlocked is returned by decrypt/send methods before Unlock has
	// decrypted the mailbox keys.
	ErrNotUnlocked = errors.New("proton: mailbox keys not unlocked")

	// ErrNo2FAPending is returned by SubmitTOTP when no 2FA challenge is
	// outstanding.
	ErrNo2FAPending = errors.New("proton: no 2FA challenge pending")

	// ErrUnsupported2FA is returned when the account requires a second factor
	// reduit does not implement (e.g. FIDO2-only). SPEC-0007 scopes TOTP only.
	ErrUnsupported2FA = errors.New("proton: unsupported 2FA method (TOTP only)")

	// ErrUnlockFailed means the mailbox passphrase did not decrypt the OpenPGP
	// keys (SPEC-0007 scenario "Passphrase unlocks OpenPGP keys"). The message
	// never contains the passphrase.
	ErrUnlockFailed = errors.New("proton: mailbox passphrase did not unlock keys")

	// ErrSendNotWired marks the live send-packaging edge that resolves
	// recipient public keys and builds encryption packages. Defining the Send
	// surface is in scope for the wrapper (#82); wiring the recipient-pref
	// resolution — which cannot be exercised without a live account — is the
	// send feature's work (ADR-0020). See gpaClient.Send.
	ErrSendNotWired = errors.New("proton: send packaging not wired in the client wrapper")

	// ErrAddressNotUnlocked means OutgoingMessage.FromAddressID does not match
	// any unlocked address keyring (ADR-0020 "Explicit from-mailbox").
	ErrAddressNotUnlocked = errors.New("proton: from-address has no unlocked keyring")

	// ErrMessageNotFound is returned when a requested message or attachment is
	// absent (used by the Fake; the concrete client surfaces the upstream 404
	// through classifyError).
	ErrMessageNotFound = errors.New("proton: message not found")
)

// classifyError maps a go-proton-api error onto a reduit sentinel so callers
// can branch on meaning. Unrecognized errors are wrapped verbatim — the
// upstream message is preserved but never enriched with secret values, since
// this package is only ever handed secrets as opaque []byte it does not log.
//
// Governing: SPEC-0007 REQ "No Secret Leakage" (errors describe the failure
// without echoing the entered secret — this package never places a secret in
// an error), ADR-0001 (Proton error codes).
func classifyError(err error) error {
	if err == nil {
		return nil
	}

	// Transport failures: go-proton-api wraps these in *gpa.NetError.
	var netErr *gpa.NetError
	if errors.As(err, &netErr) {
		return fmt.Errorf("%w: %v", ErrNetwork, netErr)
	}

	// API-level failures carry a numeric Proton code.
	var apiErr *gpa.APIError
	if errors.As(err, &apiErr) {
		return classifyAPICode(apiErr)
	}
	// Some upstream paths return APIError by value rather than pointer.
	var apiErrVal gpa.APIError
	if errors.As(err, &apiErrVal) {
		return classifyAPICode(&apiErrVal)
	}

	return fmt.Errorf("proton: %w", err)
}

func classifyAPICode(apiErr *gpa.APIError) error {
	switch apiErr.Code {
	case gpa.PasswordWrong:
		return fmt.Errorf("%w (code %d)", ErrAuthFailed, apiErr.Code)
	case gpa.HumanVerificationRequired:
		return fmt.Errorf("%w (code %d)", ErrHumanVerification, apiErr.Code)
	case gpa.AuthRefreshTokenInvalid:
		return fmt.Errorf("%w (code %d)", ErrRefreshTokenInvalid, apiErr.Code)
	default:
		// Preserve the upstream message and code without inventing a category.
		return fmt.Errorf("proton: api error: %w", apiErr)
	}
}
