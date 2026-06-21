// Governing: SPEC-0002 REQ "Event Cursor Persistence" — tests need a
//             non-nil ClientFactory now that New() rejects nil.

package sync

import (
	"context"

	"github.com/joestump/reduit/internal/proton"
)

// stubClient is a no-op proton.Client returned by StubClientFactory.
// Every method panics on call so a test that accidentally exercises a
// Proton round-trip via a stubbed-out worker fails loudly instead of
// returning silent zero values. Tests that need real GetEvent /
// GetLatestEventID semantics use fakeProtonClient (see
// eventprocessor_test.go) or override Config.ClientFactory directly.
//
// stubClient exists specifically so lifecycle tests
// (start/stop/panic-isolation) can construct a Supervisor without
// also wiring a Proton fake. Before PR #41's hostile-review fix to
// New(), the same role was played by a nil ClientFactory + a
// "no-Proton mode" code path inside worker.tick(); that path was
// removed because a production deploy that forgot to wire the
// factory had no operator-visible signal.
type stubClient struct{}

func (stubClient) AuthInfo(context.Context, proton.AuthInfoReq) (proton.AuthInfo, error) {
	panic("stubClient.AuthInfo: lifecycle tests must not reach Proton")
}
func (stubClient) AuthTOTP(context.Context, string) error {
	panic("stubClient.AuthTOTP: lifecycle tests must not reach Proton")
}
func (stubClient) AuthFIDO2(context.Context, proton.FIDO2Req) error {
	panic("stubClient.AuthFIDO2: lifecycle tests must not reach Proton")
}
func (stubClient) KeySalts(context.Context) (proton.Salts, error) {
	panic("stubClient.KeySalts: lifecycle tests must not reach Proton")
}
func (stubClient) GetUser(context.Context) (proton.User, error) {
	panic("stubClient.GetUser: lifecycle tests must not reach Proton")
}
func (stubClient) GetAddresses(context.Context) ([]proton.Address, error) {
	panic("stubClient.GetAddresses: lifecycle tests must not reach Proton")
}
func (stubClient) Unlock(proton.User, []proton.Address, []byte) (*proton.KeyRing, map[string]*proton.KeyRing, error) {
	panic("stubClient.Unlock: lifecycle tests must not reach Proton")
}

// GetEvent + GetLatestEventID are reached by the worker's real tick
// path now that nil-ClientFactory mode is gone. We return innocuous
// "no work to do" values so a tick exits cleanly without forcing the
// lifecycle test to also assert on cursor advancement.
//
// GetEvent: empty batch + more=false + no error means processOnce
// upserts the cursor (initially the bootstrap cursor "stub-bootstrap")
// and returns more=false, so the tick stops at the first iteration.
// GetLatestEventID: returns the bootstrap cursor used on first boot.
func (stubClient) GetEvent(context.Context, string) ([]proton.Event, bool, error) {
	return nil, false, nil
}
func (stubClient) GetLatestEventID(context.Context) (string, error) {
	return "stub-bootstrap", nil
}
func (stubClient) GetMessage(context.Context, string) (proton.Message, error) {
	panic("stubClient.GetMessage: lifecycle tests must not reach Proton")
}
func (stubClient) GetMessageRFC822(context.Context, string) ([]byte, error) {
	panic("stubClient.GetMessageRFC822: lifecycle tests must not reach Proton")
}
func (stubClient) ListMessages(context.Context, proton.MessageFilter) ([]proton.MessageMetadata, error) {
	panic("stubClient.ListMessages: lifecycle tests must not reach Proton")
}
func (stubClient) ListMessagesPage(context.Context, int, int, proton.MessageFilter) ([]proton.MessageMetadata, error) {
	panic("stubClient.ListMessagesPage: lifecycle tests must not reach Proton")
}
func (stubClient) GroupedMessageCount(context.Context) ([]proton.MessageGroupCount, error) {
	panic("stubClient.GroupedMessageCount: lifecycle tests must not reach Proton")
}
func (stubClient) GetLabels(context.Context, ...proton.LabelType) ([]proton.Label, error) {
	panic("stubClient.GetLabels: lifecycle tests must not reach Proton")
}
func (stubClient) SendDraft(context.Context, string, proton.SendDraftReq) (proton.Message, error) {
	panic("stubClient.SendDraft: lifecycle tests must not reach Proton")
}
func (stubClient) GetAttachment(context.Context, string) ([]byte, error) {
	panic("stubClient.GetAttachment: lifecycle tests must not reach Proton")
}
func (stubClient) Logout(context.Context) error { return nil }
func (stubClient) LatestRefreshToken() string   { return "" }

// Methods added to proton.Client by SPEC-0003 (LabelMessages /
// UnlabelMessages) and SPEC-0004 (GetPublicKeys). The lifecycle worker
// does not exercise any of these; panic so a regression that does is
// loud.
func (stubClient) GetPublicKeys(context.Context, string) (proton.PublicKeys, proton.RecipientType, error) {
	panic("stubClient.GetPublicKeys: lifecycle tests must not reach Proton")
}
func (stubClient) LabelMessages(context.Context, []string, string) error {
	panic("stubClient.LabelMessages: lifecycle tests must not reach Proton")
}
func (stubClient) UnlabelMessages(context.Context, []string, string) error {
	panic("stubClient.UnlabelMessages: lifecycle tests must not reach Proton")
}
func (stubClient) ImportMessage(context.Context, []byte, string, bool) (string, error) {
	panic("stubClient.ImportMessage: lifecycle tests must not reach Proton")
}
func (stubClient) MarkMessagesRead(context.Context, ...string) error {
	panic("stubClient.MarkMessagesRead: lifecycle tests must not reach Proton")
}
func (stubClient) MarkMessagesUnread(context.Context, ...string) error {
	panic("stubClient.MarkMessagesUnread: lifecycle tests must not reach Proton")
}

// StubClientFactory is a ClientFactory that returns a stubClient for
// any account ID. It satisfies New()'s "non-nil ClientFactory" guard
// in lifecycle tests without forcing each test to wire a fake Proton
// client of its own. Tests that need real GetEvent semantics replace
// Config.ClientFactory after fastConfig() returns.
var StubClientFactory ClientFactory = func(context.Context, string) (proton.Client, error) {
	return stubClient{}, nil
}

// Compile-time assertion: stubClient satisfies proton.Client.
var _ proton.Client = stubClient{}
