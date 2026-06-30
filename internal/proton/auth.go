package proton

import gpa "github.com/ProtonMail/go-proton-api"

// classify2FA reduces go-proton-api's 2FA description to the state machine the
// auth flow drives (SPEC-0007 REQ "SRP and 2FA Handling"). It is pure so the
// 2FA branching is unit-tested without a live account.
//
// Mapping rationale: SPEC-0007 scopes TOTP as the only supported second factor
// ("FIDO2 / hardware-key second factors beyond TOTP — handled upstream … not
// specified here"). So any account offering TOTP (alone or alongside FIDO2)
// resolves to TwoFATOTP; a FIDO2-only account has no path reduit drives and
// resolves to TwoFAUnsupported; no 2FA resolves to TwoFANone.
func classify2FA(info gpa.TwoFAInfo) TwoFAState {
	switch info.Enabled {
	case 0:
		// No second factor enabled.
		return TwoFANone
	case gpa.HasTOTP, gpa.HasFIDO2AndTOTP:
		// TOTP is available; prefer it (we don't drive FIDO2).
		return TwoFATOTP
	case gpa.HasFIDO2:
		// FIDO2 only — no reduit-driven path.
		return TwoFAUnsupported
	default:
		// Unknown non-zero status: treat conservatively as unsupported rather
		// than silently proceeding as if no 2FA were required.
		return TwoFAUnsupported
	}
}
