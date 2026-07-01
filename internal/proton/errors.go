package proton

import (
	"errors"
	"fmt"
	"strings"

	gpa "github.com/ProtonMail/go-proton-api"
)

// HVRequiredError is a typed human-verification (CAPTCHA) challenge carried out
// of Login/LoginWithHV so the CLI can SOLVE it rather than merely report it
// (SPEC-0007 scenario "Human verification / CAPTCHA is requested"). Proton
// returns code 9001 with the challenge details; this type carries the offered
// Methods (e.g. "captcha", "email", "sms") and the challenge Token the solver
// fetches the CAPTCHA with and, once solved, retries the login with. It unwraps
// to ErrHumanVerification so existing errors.Is checks keep working.
//
// Governing: SPEC-0007 REQ "SRP and 2FA Handling", ADR-0001.
type HVRequiredError struct {
	// Methods are the human-verification methods Proton will accept. reduit
	// only solves "captcha"; the CLI reports the offered set when it cannot.
	Methods []string
	// Token is the HV challenge token. It is not a login secret, but it is not
	// echoed in Error() to keep failure logs clean.
	Token string
}

// Error describes the challenge without echoing the token.
func (e *HVRequiredError) Error() string {
	if len(e.Methods) == 0 {
		return ErrHumanVerification.Error()
	}
	return fmt.Sprintf("%s (methods: %s)", ErrHumanVerification.Error(), strings.Join(e.Methods, ", "))
}

// Unwrap lets errors.Is(err, ErrHumanVerification) match an *HVRequiredError,
// preserving the sentinel-based branching callers already use.
func (e *HVRequiredError) Unwrap() error { return ErrHumanVerification }

// AsHVRequired reports whether err is (or wraps) an *HVRequiredError, returning
// it so the caller can drive the CAPTCHA solve. It is the CLI's branch point
// after Login.
func AsHVRequired(err error) (*HVRequiredError, bool) {
	var hv *HVRequiredError
	if errors.As(err, &hv) {
		return hv, true
	}
	return nil, false
}

// hvRequiredFrom builds an *HVRequiredError from a go-proton-api HV APIError,
// reporting false when err is not a human-verification error or its details do
// not parse. The Methods/Token come from the upstream APIHVDetails payload.
func hvRequiredFrom(err error) (*HVRequiredError, bool) {
	apiErr, ok := gpaAPIError(err)
	if !ok || !apiErr.IsHVError() {
		return nil, false
	}
	details, derr := apiErr.GetHVDetails()
	if derr != nil {
		return nil, false
	}
	return &HVRequiredError{Methods: details.Methods, Token: details.Token}, true
}

// gpaAPIError unwraps err to a *gpa.APIError, handling both the pointer and
// by-value shapes go-proton-api returns from different paths.
func gpaAPIError(err error) (*gpa.APIError, bool) {
	var apiErr *gpa.APIError
	if errors.As(err, &apiErr) {
		return apiErr, true
	}
	var apiErrVal gpa.APIError
	if errors.As(err, &apiErrVal) {
		return &apiErrVal, true
	}
	return nil, false
}

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

	// ErrAppVersionRejected means Proton rejected the client's app-version
	// header (codes 5001 missing / 5003 bad). The fix is operator-actionable —
	// set a value Proton accepts — so the message points at the config knob
	// rather than reading as a generic auth failure.
	ErrAppVersionRejected = errors.New("proton: rejected the client app version; set proton.app_version in your config (or REDUIT_PROTON_APP_VERSION) to a value Proton accepts")

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

	// ErrNoPrimaryKey means the account's key set has no key flagged Primary,
	// so a salt-for-key derivation cannot proceed (#123). It replaces the panic
	// in go-proton-api's Keys.Primary(); the mailbox cannot be unlocked.
	ErrNoPrimaryKey = errors.New("proton: account has no primary key")

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

	// API-level failures carry a numeric Proton code. Handles both the pointer
	// and by-value shapes upstream returns from different paths.
	if apiErr, ok := gpaAPIError(err); ok {
		return classifyAPICode(apiErr)
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
	case gpa.AppVersionMissingCode, gpa.AppVersionBadCode:
		return fmt.Errorf("%w (code %d)", ErrAppVersionRejected, apiErr.Code)
	default:
		// Preserve the upstream message and code without inventing a category.
		return fmt.Errorf("proton: api error: %w", apiErr)
	}
}
