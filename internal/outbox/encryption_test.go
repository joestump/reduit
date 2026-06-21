// Encryption-mode selector tests. Each test wires a fakeProtonClient
// that returns a deterministic key shape and asserts the selector
// picks the spec-mandated mode.
//
// Governing: SPEC-0004 REQ "Encryption Pipeline".

package outbox

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/proton"
)

// fakeProtonClient is the test-only proton.Client. Only the
// GetPublicKeys method is implemented — the rest panics so a test
// that accidentally calls a non-key method fails loudly.
type fakeProtonClient struct {
	keys map[string]struct {
		keys     proton.PublicKeys
		rcptType proton.RecipientType
		err      error
	}
}

func (f *fakeProtonClient) GetPublicKeys(_ context.Context, address string) (proton.PublicKeys, proton.RecipientType, error) {
	v, ok := f.keys[address]
	if !ok {
		return nil, proton.RecipientTypeExternal, errors.New("fakeProtonClient: address not configured: " + address)
	}
	return v.keys, v.rcptType, v.err
}

// All other proton.Client methods panic — tests should not reach them.
func (f *fakeProtonClient) AuthInfo(context.Context, proton.AuthInfoReq) (proton.AuthInfo, error) {
	panic("fakeProtonClient: AuthInfo not implemented")
}
func (f *fakeProtonClient) AuthTOTP(context.Context, string) error {
	panic("fakeProtonClient: AuthTOTP not implemented")
}
func (f *fakeProtonClient) AuthFIDO2(context.Context, proton.FIDO2Req) error {
	panic("fakeProtonClient: AuthFIDO2 not implemented")
}
func (f *fakeProtonClient) KeySalts(context.Context) (proton.Salts, error) {
	panic("fakeProtonClient: KeySalts not implemented")
}
func (f *fakeProtonClient) GetUser(context.Context) (proton.User, error) {
	panic("fakeProtonClient: GetUser not implemented")
}
func (f *fakeProtonClient) GetAddresses(context.Context) ([]proton.Address, error) {
	panic("fakeProtonClient: GetAddresses not implemented")
}
func (f *fakeProtonClient) Unlock(proton.User, []proton.Address, []byte) (*proton.KeyRing, map[string]*proton.KeyRing, error) {
	panic("fakeProtonClient: Unlock not implemented")
}
func (f *fakeProtonClient) GetEvent(context.Context, string) ([]proton.Event, bool, error) {
	panic("fakeProtonClient: GetEvent not implemented")
}
func (f *fakeProtonClient) GetMessage(context.Context, string) (proton.Message, error) {
	panic("fakeProtonClient: GetMessage not implemented")
}
func (f *fakeProtonClient) GetMessageRFC822(context.Context, string) ([]byte, error) {
	panic("fakeProtonClient: GetMessageRFC822 not implemented")
}
func (f *fakeProtonClient) ListMessages(context.Context, proton.MessageFilter) ([]proton.MessageMetadata, error) {
	panic("fakeProtonClient: ListMessages not implemented")
}
func (f *fakeProtonClient) ListMessagesPage(context.Context, int, int, proton.MessageFilter) ([]proton.MessageMetadata, error) {
	panic("fakeProtonClient: ListMessagesPage not implemented")
}
func (f *fakeProtonClient) GroupedMessageCount(context.Context) ([]proton.MessageGroupCount, error) {
	panic("fakeProtonClient: GroupedMessageCount not implemented")
}
func (f *fakeProtonClient) GetLabels(context.Context, ...proton.LabelType) ([]proton.Label, error) {
	panic("fakeProtonClient: GetLabels not implemented")
}
func (f *fakeProtonClient) SendDraft(context.Context, string, proton.SendDraftReq) (proton.Message, error) {
	panic("fakeProtonClient: SendDraft not implemented")
}
func (f *fakeProtonClient) GetAttachment(context.Context, string) ([]byte, error) {
	panic("fakeProtonClient: GetAttachment not implemented")
}
func (f *fakeProtonClient) LatestRefreshToken() string {
	return ""
}
func (f *fakeProtonClient) Logout(context.Context) error {
	panic("fakeProtonClient: Logout not implemented")
}

// Methods added to proton.Client by SPEC-0002 (GetLatestEventID) and
// SPEC-0003 (LabelMessages/UnlabelMessages). The outbox does not call
// any of these — they panic so a regression that does is loud.
func (f *fakeProtonClient) GetLatestEventID(context.Context) (string, error) {
	panic("fakeProtonClient: GetLatestEventID not implemented")
}
func (f *fakeProtonClient) LabelMessages(context.Context, []string, string) error {
	panic("fakeProtonClient: LabelMessages not implemented")
}
func (f *fakeProtonClient) UnlabelMessages(context.Context, []string, string) error {
	panic("fakeProtonClient: UnlabelMessages not implemented")
}
func (f *fakeProtonClient) MarkMessagesRead(context.Context, ...string) error {
	panic("fakeProtonClient: MarkMessagesRead not implemented")
}
func (f *fakeProtonClient) MarkMessagesUnread(context.Context, ...string) error {
	panic("fakeProtonClient: MarkMessagesUnread not implemented")
}

// TestSelectMode_ProtonInternalGetsE2E covers the SPEC-0004 scenario
// "Proton recipient gets E2E": an internal recipient with at least one
// active key resolves to ModeProtonE2E.
func TestSelectMode_ProtonInternalGetsE2E(t *testing.T) {
	t.Parallel()
	fc := &fakeProtonClient{keys: map[string]struct {
		keys     proton.PublicKeys
		rcptType proton.RecipientType
		err      error
	}{
		"alice@proton.me": {
			keys:     proton.PublicKeys{{Flags: proton.KeyStateActive | proton.KeyStateTrusted, PublicKey: "PGP-INTERNAL"}},
			rcptType: proton.RecipientTypeInternal,
		},
	}}
	modes, err := SelectMode(context.Background(), fc, []string{"alice@proton.me"})
	if err != nil {
		t.Fatalf("SelectMode: %v", err)
	}
	if got, want := modes["alice@proton.me"], ModeProtonE2E; got != want {
		t.Errorf("alice@proton.me mode = %v, want %v", got, want)
	}
}

// TestSelectMode_ExternalNoKeyGetsCleartext covers "External recipient
// with no published key gets plain": the recipient resolves to
// ModeCleartext (Proton's outbound MTA relays in cleartext).
func TestSelectMode_ExternalNoKeyGetsCleartext(t *testing.T) {
	t.Parallel()
	fc := &fakeProtonClient{keys: map[string]struct {
		keys     proton.PublicKeys
		rcptType proton.RecipientType
		err      error
	}{
		"bob@external.tld": {
			keys:     proton.PublicKeys{},
			rcptType: proton.RecipientTypeExternal,
		},
	}}
	modes, err := SelectMode(context.Background(), fc, []string{"bob@external.tld"})
	if err != nil {
		t.Fatalf("SelectMode: %v", err)
	}
	if got, want := modes["bob@external.tld"], ModeCleartext; got != want {
		t.Errorf("bob@external.tld mode = %v, want %v", got, want)
	}
}

// TestSelectMode_ExternalWithKeyGetsExternalE2E covers "External
// recipient with WKD/published key gets optional E2E": v0.1 mirrors
// Proton's "encrypt to outside" preference, so a published external
// key resolves to ModeExternalE2E.
func TestSelectMode_ExternalWithKeyGetsExternalE2E(t *testing.T) {
	t.Parallel()
	fc := &fakeProtonClient{keys: map[string]struct {
		keys     proton.PublicKeys
		rcptType proton.RecipientType
		err      error
	}{
		"carol@external.tld": {
			keys:     proton.PublicKeys{{Flags: proton.KeyStateActive | proton.KeyStateTrusted, PublicKey: "PGP-WKD"}},
			rcptType: proton.RecipientTypeExternal,
		},
	}}
	modes, err := SelectMode(context.Background(), fc, []string{"carol@external.tld"})
	if err != nil {
		t.Fatalf("SelectMode: %v", err)
	}
	if got, want := modes["carol@external.tld"], ModeExternalE2E; got != want {
		t.Errorf("carol@external.tld mode = %v, want %v", got, want)
	}
}

// TestSelectMode_KeyLookupErrorFailsClosed is THE security test the
// hostile reviewer will scrutinise. A 5xx-style error from
// GetPublicKeys for a Proton-internal recipient MUST produce
// *ErrKeyLookup, not silently downgrade to ModeCleartext.
//
// Governing: SPEC-0004 Security checklist + the SPEC-0004 design
// rationale in encryption.go's package doc.
func TestSelectMode_KeyLookupErrorFailsClosed(t *testing.T) {
	t.Parallel()
	upstreamErr := errors.New("simulated 503 from /core/v4/keys")
	fc := &fakeProtonClient{keys: map[string]struct {
		keys     proton.PublicKeys
		rcptType proton.RecipientType
		err      error
	}{
		"alice@proton.me": {err: upstreamErr},
	}}

	_, err := SelectMode(context.Background(), fc, []string{"alice@proton.me"})
	if err == nil {
		t.Fatal("SelectMode succeeded with key-lookup error; expected fail-closed")
	}
	var keyErr *ErrKeyLookup
	if !errors.As(err, &keyErr) {
		t.Fatalf("expected *ErrKeyLookup, got %T: %v", err, err)
	}
	if !errors.Is(err, upstreamErr) {
		t.Errorf("error chain does not contain upstream cause; got %v", err)
	}
	if keyErr.Recipient != "alice@proton.me" {
		t.Errorf("Recipient = %q, want alice@proton.me", keyErr.Recipient)
	}
}

// TestSelectMode_InternalWithoutActiveKeysFailsClosed covers a
// degraded /core/v4/keys response (RecipientType=Internal but no
// active keys returned). We refuse to send rather than silently
// downgrade.
func TestSelectMode_InternalWithoutActiveKeysFailsClosed(t *testing.T) {
	t.Parallel()
	fc := &fakeProtonClient{keys: map[string]struct {
		keys     proton.PublicKeys
		rcptType proton.RecipientType
		err      error
	}{
		// All keys present but none have KeyStateActive flag set.
		"alice@proton.me": {
			keys:     proton.PublicKeys{{Flags: proton.KeyStateTrusted, PublicKey: "OBSOLETE"}},
			rcptType: proton.RecipientTypeInternal,
		},
	}}

	_, err := SelectMode(context.Background(), fc, []string{"alice@proton.me"})
	if err == nil {
		t.Fatal("SelectMode succeeded with internal-no-active-keys; expected fail-closed")
	}
	var keyErr *ErrKeyLookup
	if !errors.As(err, &keyErr) {
		t.Fatalf("expected *ErrKeyLookup, got %T: %v", err, err)
	}
}

// TestSelectModeRejectsCompromisedKey covers the security-critical
// "Active but NOT Trusted" scenario. Per upstream
// go-proton-api keys_types.go, KeyStateActive means "still in use" and
// KeyStateTrusted means "not compromised". A key with Active set but
// Trusted clear is a compromised-but-still-active key — Proton has
// disavowed it but kept it in rotation during a migration window.
// Encrypting user mail to such a key would leak content to a
// repudiated key. The selector MUST require BOTH bits and fail closed
// when only Active is present.
//
// Governing: SPEC-0004 REQ "Encryption Pipeline" — fail-closed on
// compromised-but-still-active Proton keys.
func TestSelectModeRejectsCompromisedKey(t *testing.T) {
	t.Parallel()
	t.Run("internal-active-not-trusted", func(t *testing.T) {
		t.Parallel()
		fc := &fakeProtonClient{keys: map[string]struct {
			keys     proton.PublicKeys
			rcptType proton.RecipientType
			err      error
		}{
			// Active=2, Trusted=0 → compromised-but-still-active.
			"alice@proton.me": {
				keys:     proton.PublicKeys{{Flags: proton.KeyStateActive, PublicKey: "COMPROMISED"}},
				rcptType: proton.RecipientTypeInternal,
			},
		}}
		mode, err := classify("alice@proton.me",
			fc.keys["alice@proton.me"].keys,
			fc.keys["alice@proton.me"].rcptType)
		if err == nil {
			t.Fatalf("classify accepted compromised key; got mode=%v", mode)
		}
		if mode == ModeProtonE2E || mode == ModeExternalE2E {
			t.Errorf("classify returned encrypted mode %v for compromised key", mode)
		}
		var keyErr *ErrKeyLookup
		if !errors.As(err, &keyErr) {
			t.Fatalf("expected *ErrKeyLookup, got %T: %v", err, err)
		}

		// Round-trip through SelectMode for parity with the production
		// call site; same expectation.
		_, err = SelectMode(context.Background(), fc, []string{"alice@proton.me"})
		if err == nil {
			t.Fatal("SelectMode accepted compromised internal key; expected fail-closed")
		}
		if !errors.As(err, &keyErr) {
			t.Fatalf("SelectMode: expected *ErrKeyLookup, got %T: %v", err, err)
		}
	})

	t.Run("external-active-not-trusted-falls-back-to-cleartext", func(t *testing.T) {
		t.Parallel()
		// For an external recipient an Active-but-not-Trusted key is
		// equivalent to "no usable key" — the selector falls through to
		// ModeCleartext rather than encrypting to a disavowed key. This
		// is the "no usable key returned" branch; cleartext relay via
		// Proton's outbound MTA is the spec-mandated default.
		fc := &fakeProtonClient{keys: map[string]struct {
			keys     proton.PublicKeys
			rcptType proton.RecipientType
			err      error
		}{
			"bob@external.tld": {
				keys:     proton.PublicKeys{{Flags: proton.KeyStateActive, PublicKey: "COMPROMISED-WKD"}},
				rcptType: proton.RecipientTypeExternal,
			},
		}}
		modes, err := SelectMode(context.Background(), fc, []string{"bob@external.tld"})
		if err != nil {
			t.Fatalf("SelectMode: %v", err)
		}
		if got := modes["bob@external.tld"]; got == ModeExternalE2E {
			t.Errorf("external recipient with compromised key returned ModeExternalE2E; want ModeCleartext or fail-closed")
		}
	})

	t.Run("trusted-but-not-active-fails-closed", func(t *testing.T) {
		t.Parallel()
		// Trusted=1, Active=0 → key is no longer in use even though it
		// was never compromised. Same fail-closed as
		// TestSelectMode_InternalWithoutActiveKeysFailsClosed but stated
		// as a security-symmetric companion to the Active-but-not-Trusted
		// case above so a future reader sees both halves of the
		// "require both bits" invariant.
		fc := &fakeProtonClient{keys: map[string]struct {
			keys     proton.PublicKeys
			rcptType proton.RecipientType
			err      error
		}{
			"alice@proton.me": {
				keys:     proton.PublicKeys{{Flags: proton.KeyStateTrusted, PublicKey: "RETIRED"}},
				rcptType: proton.RecipientTypeInternal,
			},
		}}
		_, err := SelectMode(context.Background(), fc, []string{"alice@proton.me"})
		if err == nil {
			t.Fatal("SelectMode accepted retired (Trusted-only) key; expected fail-closed")
		}
		var keyErr *ErrKeyLookup
		if !errors.As(err, &keyErr) {
			t.Fatalf("expected *ErrKeyLookup, got %T: %v", err, err)
		}
	})
}

// TestSelectMode_PerRecipientDecisionIsIndependent feeds a mix of
// Proton-internal + external-no-key recipients. The result map MUST
// reflect the per-recipient decision (one E2E, one cleartext) rather
// than aggregating to a single mode.
func TestSelectMode_PerRecipientDecisionIsIndependent(t *testing.T) {
	t.Parallel()
	fc := &fakeProtonClient{keys: map[string]struct {
		keys     proton.PublicKeys
		rcptType proton.RecipientType
		err      error
	}{
		"alice@proton.me": {
			keys:     proton.PublicKeys{{Flags: proton.KeyStateActive | proton.KeyStateTrusted, PublicKey: "PGP-INTERNAL"}},
			rcptType: proton.RecipientTypeInternal,
		},
		"bob@external.tld": {
			keys:     proton.PublicKeys{},
			rcptType: proton.RecipientTypeExternal,
		},
	}}
	modes, err := SelectMode(context.Background(), fc, []string{"alice@proton.me", "bob@external.tld"})
	if err != nil {
		t.Fatalf("SelectMode: %v", err)
	}
	if got := modes["alice@proton.me"]; got != ModeProtonE2E {
		t.Errorf("alice mode = %v, want ModeProtonE2E", got)
	}
	if got := modes["bob@external.tld"]; got != ModeCleartext {
		t.Errorf("bob mode = %v, want ModeCleartext", got)
	}
}

// TestSelectMode_NormalisesAddressBeforeLookup confirms the selector
// lower-cases + trims the recipient before the key lookup, mirroring
// the SMTP layer's normalisation. Otherwise "Alice@PROTON.ME" with a
// trailing space would key-miss against "alice@proton.me" and
// downgrade to fail-closed even though the address is the same.
func TestSelectMode_NormalisesAddressBeforeLookup(t *testing.T) {
	t.Parallel()
	fc := &fakeProtonClient{keys: map[string]struct {
		keys     proton.PublicKeys
		rcptType proton.RecipientType
		err      error
	}{
		"alice@proton.me": {
			keys:     proton.PublicKeys{{Flags: proton.KeyStateActive | proton.KeyStateTrusted, PublicKey: "PGP-INTERNAL"}},
			rcptType: proton.RecipientTypeInternal,
		},
	}}
	modes, err := SelectMode(context.Background(), fc, []string{"  Alice@PROTON.ME  "})
	if err != nil {
		t.Fatalf("SelectMode: %v", err)
	}
	if _, ok := modes["alice@proton.me"]; !ok {
		t.Errorf("modes did not contain normalised key; got %v", modes)
	}
}

// TestSelectMode_UnknownRecipientTypeFailsClosed: a forwards-
// compatibility hazard. Proton may add a new RecipientType value; we
// must fail closed rather than coerce to external.
func TestSelectMode_UnknownRecipientTypeFailsClosed(t *testing.T) {
	t.Parallel()
	fc := &fakeProtonClient{keys: map[string]struct {
		keys     proton.PublicKeys
		rcptType proton.RecipientType
		err      error
	}{
		"alice@proton.me": {
			keys:     proton.PublicKeys{{Flags: proton.KeyStateActive | proton.KeyStateTrusted, PublicKey: "PGP"}},
			rcptType: proton.RecipientType(99), // future Proton type
		},
	}}
	_, err := SelectMode(context.Background(), fc, []string{"alice@proton.me"})
	if err == nil {
		t.Fatal("SelectMode succeeded for unknown RecipientType; expected fail-closed")
	}
	var keyErr *ErrKeyLookup
	if !errors.As(err, &keyErr) {
		t.Errorf("expected *ErrKeyLookup, got %T: %v", err, err)
	}
}

// slowKeyClient simulates an upstream /core/v4/keys that takes longer
// than the ctx allows for. Each GetPublicKeys call sleeps for `delay`
// (or until ctx fires, whichever first), then returns the configured
// keys. Used by the multi-recipient timeout test below.
type slowKeyClient struct {
	fakeProtonClient
	delay time.Duration
}

func (s *slowKeyClient) GetPublicKeys(ctx context.Context, _ string) (proton.PublicKeys, proton.RecipientType, error) {
	select {
	case <-time.After(s.delay):
		return proton.PublicKeys{{Flags: proton.KeyStateActive | proton.KeyStateTrusted, PublicKey: "PGP"}},
			proton.RecipientTypeInternal, nil
	case <-ctx.Done():
		return nil, proton.RecipientTypeExternal, ctx.Err()
	}
}

// TestSelectMode_MultiRecipientTimeoutMapsToTimedOut covers Concern C1
// from the hostile review: a multi-recipient submission whose ctx
// deadline fires mid-loop (because each GetPublicKeys ate enough of the
// budget to leave nothing for the next iteration) MUST surface as
// ErrSubmissionTimedOut, not *ErrKeyLookup. The SMTP code mapping for
// 451 4.4.7 (timeout) is distinct from 451 4.4.4 (key-lookup); a
// sender's MTA may track these separately and a mis-classification
// misleads it.
//
// Setup: ctx has 80ms; per-recipient delay is 60ms; two recipients.
// First lookup completes; second is cancelled by the deadline.
//
// Governing: SPEC-0004 REQ "Outbox Handoff and Synchronous
// Confirmation" — code reflects actual cause.
func TestSelectMode_MultiRecipientTimeoutMapsToTimedOut(t *testing.T) {
	t.Parallel()
	fc := &slowKeyClient{delay: 60 * time.Millisecond}

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	_, err := SelectMode(ctx, fc, []string{
		"alice@proton.me",
		"bob@proton.me",
	})
	if err == nil {
		t.Fatal("SelectMode succeeded under ctx deadline; expected timeout")
	}
	if !errors.Is(err, ErrSubmissionTimedOut) {
		var keyErr *ErrKeyLookup
		if errors.As(err, &keyErr) {
			t.Fatalf("err = *ErrKeyLookup (would map to 451 4.4.4); want ErrSubmissionTimedOut (451 4.4.7). cause: %v", err)
		}
		t.Fatalf("err = %T %v; want ErrSubmissionTimedOut", err, err)
	}
}

// TestSelectMode_PreLoopTimeoutMapsToTimedOut covers the corner case
// where the ctx is already past its deadline before the first
// GetPublicKeys call. The pre-loop ctx.Err() check picks this up.
func TestSelectMode_PreLoopTimeoutMapsToTimedOut(t *testing.T) {
	t.Parallel()
	fc := &fakeProtonClient{keys: map[string]struct {
		keys     proton.PublicKeys
		rcptType proton.RecipientType
		err      error
	}{
		"alice@proton.me": {
			keys:     proton.PublicKeys{{Flags: proton.KeyStateActive | proton.KeyStateTrusted, PublicKey: "PGP"}},
			rcptType: proton.RecipientTypeInternal,
		},
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	// Sleep past the deadline so the first iteration sees ctx.Err().
	time.Sleep(5 * time.Millisecond)

	_, err := SelectMode(ctx, fc, []string{"alice@proton.me"})
	if !errors.Is(err, ErrSubmissionTimedOut) {
		t.Fatalf("err = %T %v; want ErrSubmissionTimedOut", err, err)
	}
}
