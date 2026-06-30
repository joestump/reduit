package proton

import (
	"strings"
	"testing"
)

func validMsg() OutgoingMessage {
	return OutgoingMessage{
		FromAddressID: "addr-1",
		To:            []Address{{Name: "Bob", Email: "bob@example.com"}},
		Subject:       "hi",
		Body:          "hello",
	}
}

func TestValidateOutgoing_OK(t *testing.T) {
	if err := validateOutgoing(validMsg()); err != nil {
		t.Fatalf("valid message rejected: %v", err)
	}
	// CC/BCC-only recipients also satisfy the recipient requirement.
	m := validMsg()
	m.To = nil
	m.BCC = []Address{{Email: "x@example.com"}}
	if err := validateOutgoing(m); err != nil {
		t.Fatalf("bcc-only message rejected: %v", err)
	}
}

func TestValidateOutgoing_Rejects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*OutgoingMessage)
		substr string
	}{
		{"no from", func(m *OutgoingMessage) { m.FromAddressID = "" }, "from-address"},
		{"no recipients", func(m *OutgoingMessage) { m.To, m.CC, m.BCC = nil, nil, nil }, "recipient"},
		{"no subject", func(m *OutgoingMessage) { m.Subject = "" }, "subject"},
		{"no body", func(m *OutgoingMessage) { m.Body = "" }, "body"},
		{"bad recipient", func(m *OutgoingMessage) { m.To = []Address{{Email: "not-an-email"}} }, "invalid recipient"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := validMsg()
			tt.mutate(&m)
			err := validateOutgoing(m)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.substr) {
				t.Errorf("error %q does not mention %q", err.Error(), tt.substr)
			}
		})
	}
}

func TestBuildDraftTemplate(t *testing.T) {
	m := OutgoingMessage{
		FromAddressID: "addr-1",
		To:            []Address{{Name: "Bob", Email: "bob@example.com"}},
		CC:            []Address{{Email: "cc@example.com"}},
		Subject:       "subject line",
		Body:          "body text",
	}
	sender := Address{Name: "Joe", Email: "joe@proton.me"}
	tmpl := buildDraftTemplate(m, sender)

	if tmpl.Subject != "subject line" {
		t.Errorf("subject = %q", tmpl.Subject)
	}
	if tmpl.Sender == nil || tmpl.Sender.Address != "joe@proton.me" || tmpl.Sender.Name != "Joe" {
		t.Errorf("sender mismapped: %+v", tmpl.Sender)
	}
	if len(tmpl.ToList) != 1 || tmpl.ToList[0].Address != "bob@example.com" || tmpl.ToList[0].Name != "Bob" {
		t.Errorf("ToList mismapped: %+v", tmpl.ToList)
	}
	if len(tmpl.CCList) != 1 || tmpl.CCList[0].Address != "cc@example.com" {
		t.Errorf("CCList mismapped: %+v", tmpl.CCList)
	}
	if len(tmpl.BCCList) != 0 {
		t.Errorf("BCCList should be empty, got %+v", tmpl.BCCList)
	}
	if string(tmpl.MIMEType) != defaultMIMEType {
		t.Errorf("MIMEType = %q, want default %q", tmpl.MIMEType, defaultMIMEType)
	}
}

func TestBuildDraftTemplate_HonoursMIMEType(t *testing.T) {
	m := validMsg()
	m.MIMEType = "text/html"
	tmpl := buildDraftTemplate(m, Address{Email: "joe@proton.me"})
	if string(tmpl.MIMEType) != "text/html" {
		t.Errorf("MIMEType = %q, want text/html", tmpl.MIMEType)
	}
}

func TestAllRecipients(t *testing.T) {
	m := OutgoingMessage{
		To:  []Address{{Email: "a@x.com"}},
		CC:  []Address{{Email: "b@x.com"}},
		BCC: []Address{{Email: "c@x.com"}},
	}
	if got := len(allRecipients(m)); got != 3 {
		t.Fatalf("allRecipients len = %d, want 3", got)
	}
}
