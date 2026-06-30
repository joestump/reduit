package proton

import (
	"fmt"
	"net/mail"

	"github.com/ProtonMail/gluon/rfc822"
	gpa "github.com/ProtonMail/go-proton-api"
)

// defaultMIMEType is the body content type used when an OutgoingMessage leaves
// MIMEType empty.
const defaultMIMEType = "text/plain"

// validateOutgoing enforces ADR-0020's "no underspecified send" rule: an
// explicit from-address, at least one recipient, and a non-empty subject and
// body. It is pure so the guard is unit-tested without a live account, and it
// runs before any network call so a bad Send fails fast and locally.
//
// Governing: ADR-0020 (explicit from-mailbox; required fields so an agent
// cannot fire mail as a side effect).
func validateOutgoing(msg OutgoingMessage) error {
	if msg.FromAddressID == "" {
		return fmt.Errorf("proton: send: from-address is required")
	}
	if len(msg.To)+len(msg.CC)+len(msg.BCC) == 0 {
		return fmt.Errorf("proton: send: at least one recipient is required")
	}
	if msg.Subject == "" {
		return fmt.Errorf("proton: send: subject is required")
	}
	if msg.Body == "" {
		return fmt.Errorf("proton: send: body is required")
	}
	for _, r := range allRecipients(msg) {
		if _, err := mail.ParseAddress(r.Email); err != nil {
			return fmt.Errorf("proton: send: invalid recipient address %q: %w", r.Email, err)
		}
	}
	return nil
}

// allRecipients returns To+CC+BCC in a single slice.
func allRecipients(msg OutgoingMessage) []Address {
	out := make([]Address, 0, len(msg.To)+len(msg.CC)+len(msg.BCC))
	out = append(out, msg.To...)
	out = append(out, msg.CC...)
	out = append(out, msg.BCC...)
	return out
}

// buildDraftTemplate translates a validated OutgoingMessage into the
// go-proton-api draft template. sender is the resolved Address of
// FromAddressID. It is pure (no network) so the composition mapping is
// unit-tested directly; the concrete client calls it before CreateDraft.
func buildDraftTemplate(msg OutgoingMessage, sender Address) gpa.DraftTemplate {
	mimeType := msg.MIMEType
	if mimeType == "" {
		mimeType = defaultMIMEType
	}
	return gpa.DraftTemplate{
		Subject:  msg.Subject,
		Sender:   toMailAddress(sender),
		ToList:   toMailAddresses(msg.To),
		CCList:   toMailAddresses(msg.CC),
		BCCList:  toMailAddresses(msg.BCC),
		Body:     msg.Body,
		MIMEType: rfc822.MIMEType(mimeType),
	}
}

func toMailAddress(a Address) *mail.Address {
	return &mail.Address{Name: a.Name, Address: a.Email}
}

func toMailAddresses(addrs []Address) []*mail.Address {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]*mail.Address, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, toMailAddress(a))
	}
	return out
}

// fromMailAddresses maps go-proton-api's net/mail addresses into reduit
// Addresses (the inbound direction, used when decrypting a message).
func fromMailAddresses(addrs []*mail.Address) []Address {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]Address, 0, len(addrs))
	for _, a := range addrs {
		if a == nil {
			continue
		}
		out = append(out, Address{Name: a.Name, Email: a.Address})
	}
	return out
}
