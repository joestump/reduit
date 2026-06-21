// Send tool: send_message.
//
// send_message assembles the caller's structured parameters (to, cc,
// bcc, subject, body, body_format, attachments) into an RFC 5322
// envelope and hands it to the SPEC-0004 outbox. The outbox -- NOT this
// tool -- performs per-recipient encryption-mode selection and the
// PGP/cleartext send. The caller never specifies an encryption mode, per
// SPEC-0006 REQ "Send-Message Encryption". Each recipient's encryption
// outcome is read back from the outbox Result and reported.
//
// Governing: SPEC-0006 REQ "Required Tool Set" (send_message), SPEC-0006
// REQ "Send-Message Encryption".
package mcpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/joestump/reduit/internal/outbox"
)

// AttachmentIn is one inline attachment in a send_message call. Content
// is base64-encoded so binary payloads survive the JSON transport.
type AttachmentIn struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type,omitempty" jsonschema:"MIME type; defaults to application/octet-stream"`
	Content     string `json:"content" jsonschema:"base64-encoded attachment bytes"`
}

// SendMessageIn is the input schema for send_message. body_format is
// either text or html and selects the Content-Type of the body part.
type SendMessageIn struct {
	To          []string       `json:"to" jsonschema:"Recipient addresses"`
	CC          []string       `json:"cc,omitempty"`
	BCC         []string       `json:"bcc,omitempty"`
	Subject     string         `json:"subject"`
	Body        string         `json:"body"`
	BodyFormat  string         `json:"body_format" jsonschema:"text or html"`
	Attachments []AttachmentIn `json:"attachments,omitempty"`
}

// SendMessageOut is the output schema for send_message. On success it
// reports each recipient's encryption mode (proton_e2e / external_e2e /
// cleartext) as chosen by the outbox. On failure Error carries the
// structured {code, message, retriable, details}.
type SendMessageOut struct {
	Sent       bool              `json:"sent"`
	Recipients map[string]string `json:"recipients,omitempty" jsonschema:"per-recipient encryption mode chosen by the outbox"`
	Error      *ToolError        `json:"error,omitempty"`
}

func (r *toolRegistry) registerSend(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "send_message",
		Description: "Send an email. Proton-recipient encryption is applied automatically by the outbox; the caller does not specify an encryption mode.",
	}, r.sendMessage)
}

// sendMessage implements the send_message tool.
func (r *toolRegistry) sendMessage(ctx context.Context, _ *mcp.CallToolRequest, in SendMessageIn) (*mcp.CallToolResult, SendMessageOut, error) {
	acct, err := r.accountFor(ctx)
	if err != nil {
		return nil, SendMessageOut{}, err
	}

	if terr := validateSendInput(in); terr != nil {
		return nil, SendMessageOut{Error: terr}, nil
	}

	if r.deps.Outbox == nil {
		// The tool is registered for surface-completeness even when the
		// outbox is not wired (e.g. an HTTP-only deployment with sending
		// disabled). Report a structured unavailable error rather than
		// panicking.
		return nil, SendMessageOut{Error: &ToolError{
			Code:      codeProtonUnavailable,
			Message:   "sending is not enabled on this deployment",
			Retriable: false,
		}}, nil
	}

	// The envelope sender is the account's canonical primary alias (the
	// same identity SMTP submission authorises against). Fall back to the
	// Proton login email if no alias is set.
	from := acct.PrimaryAlias
	if strings.TrimSpace(from) == "" {
		from = acct.Email
	}
	if strings.TrimSpace(from) == "" {
		return nil, SendMessageOut{Error: &ToolError{
			Code:      codeBadRequest,
			Message:   "account has no sending address configured",
			Retriable: false,
		}}, nil
	}

	body, buildErr := buildRFC5322(from, in)
	if buildErr != nil {
		return nil, SendMessageOut{Error: &ToolError{
			Code:      codeInvalidArgument,
			Message:   buildErr.Error(),
			Retriable: false,
		}}, nil
	}

	// Hand the assembled envelope to the SPEC-0004 outbox. Encryption-
	// mode selection and the Proton send happen there; we deliberately do
	// NOT reimplement any of it here.
	recipients := allRecipients(in)
	res := r.deps.Outbox.Submit(ctx, outbox.Submission{
		AccountID:  acct.ID,
		MailFrom:   strings.ToLower(strings.TrimSpace(from)),
		Recipients: recipients,
		Body:       body,
	})
	if res.Err != nil {
		return nil, SendMessageOut{Error: mapOutboxError(res.Err)}, nil
	}

	out := SendMessageOut{Sent: true}
	if len(res.Modes) > 0 {
		out.Recipients = make(map[string]string, len(res.Modes))
		for addr, mode := range res.Modes {
			out.Recipients[addr] = mode.String()
		}
	}
	return nil, out, nil
}

// validateSendInput enforces the required fields, the body_format enum,
// and -- critically -- that every recipient address is a single, well-
// formed RFC 5322 address with no embedded CR/LF. Without this an
// attacker-controlled recipient like "a@x.com\r\nBcc: evil@e.com" would
// inject headers that survive to the wire (the outbox relays the body
// verbatim). Each recipient MUST parse via net/mail.ParseAddress and
// MUST NOT contain a carriage return or line feed.
//
// Governing: SPEC-0006 REQ "Required Tool Set" (send_message); hostile
// review of PR #31 (header-injection finding).
func validateSendInput(in SendMessageIn) *ToolError {
	if len(allRecipients(in)) == 0 {
		return &ToolError{Code: codeInvalidArgument, Message: "at least one recipient (to/cc/bcc) is required", Retriable: false}
	}
	for _, group := range [][]string{in.To, in.CC, in.BCC} {
		for _, raw := range group {
			if _, terr := sanitiseAddress(raw); terr != nil {
				return terr
			}
		}
	}
	switch strings.ToLower(strings.TrimSpace(in.BodyFormat)) {
	case "text", "html":
	case "":
		return &ToolError{Code: codeInvalidArgument, Message: "body_format is required (text or html)", Retriable: false}
	default:
		return &ToolError{Code: codeInvalidArgument, Message: fmt.Sprintf("unknown body_format %q; expected text or html", in.BodyFormat), Retriable: false}
	}
	return nil
}

// sanitiseAddress parses one address with net/mail.ParseAddress and
// rejects any value containing CR or LF (defence against header
// injection even for inputs ParseAddress would otherwise tolerate inside
// a quoted display name). Returns the parsed *mail.Address so callers can
// render the canonical form via (*mail.Address).String().
func sanitiseAddress(raw string) (*mail.Address, *ToolError) {
	if strings.ContainsAny(raw, "\r\n") {
		return nil, &ToolError{Code: codeInvalidArgument, Message: "recipient address contains a line break", Retriable: false}
	}
	a, err := mail.ParseAddress(raw)
	if err != nil {
		return nil, &ToolError{Code: codeInvalidArgument, Message: fmt.Sprintf("invalid recipient address %q", raw), Retriable: false}
	}
	// ParseAddress accepts a display name that may itself smuggle bytes;
	// re-check the canonical rendering for CR/LF as belt-and-suspenders.
	if strings.ContainsAny(a.String(), "\r\n") {
		return nil, &ToolError{Code: codeInvalidArgument, Message: "recipient address contains a line break", Retriable: false}
	}
	return a, nil
}

// renderAddressList parses + canonicalises a list of addresses into a
// single, injection-safe RFC 5322 header value. Callers MUST have run
// validateSendInput first (which rejects non-parsing / CR-LF inputs); a
// parse failure here is therefore a programmer error and is skipped
// rather than silently emitting the raw value.
func renderAddressList(addrs []string) string {
	parts := make([]string, 0, len(addrs))
	for _, raw := range addrs {
		if a, terr := sanitiseAddress(raw); terr == nil {
			parts = append(parts, a.String())
		}
	}
	return strings.Join(parts, ", ")
}

// allRecipients flattens to + cc + bcc into the envelope recipient list
// the outbox expects (the order matches to, then cc, then bcc).
func allRecipients(in SendMessageIn) []string {
	out := make([]string, 0, len(in.To)+len(in.CC)+len(in.BCC))
	out = append(out, in.To...)
	out = append(out, in.CC...)
	out = append(out, in.BCC...)
	return out
}

// buildRFC5322 assembles a minimal but valid RFC 5322 message from the
// structured send_message params. When there are no attachments the body
// is a single text/plain or text/html part; with attachments the message
// is a multipart/mixed envelope. BCC recipients are intentionally NOT
// written into a header (they travel only in the SMTP/outbox envelope).
func buildRFC5322(from string, in SendMessageIn) ([]byte, error) {
	var buf bytes.Buffer

	writeHeader := func(k, v string) {
		fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
	}

	// From is account-derived (primary alias / Proton email) so it is
	// trusted; To/Cc are caller-controlled and MUST be rendered through
	// the sanitising parser (validateSendInput already rejected any that
	// fail to parse or carry CR/LF). Bcc is deliberately omitted from the
	// header set -- it travels only in the outbox envelope.
	writeHeader("From", from)
	if v := renderAddressList(in.To); v != "" {
		writeHeader("To", v)
	}
	if v := renderAddressList(in.CC); v != "" {
		writeHeader("Cc", v)
	}
	writeHeader("Subject", mime.QEncoding.Encode("utf-8", in.Subject))
	writeHeader("Date", time.Now().UTC().Format(time.RFC1123Z))
	writeHeader("MIME-Version", "1.0")

	bodyContentType := "text/plain; charset=utf-8"
	if strings.EqualFold(strings.TrimSpace(in.BodyFormat), "html") {
		bodyContentType = "text/html; charset=utf-8"
	}

	if len(in.Attachments) == 0 {
		writeHeader("Content-Type", bodyContentType)
		writeHeader("Content-Transfer-Encoding", "8bit")
		buf.WriteString("\r\n")
		buf.WriteString(normaliseBody(in.Body))
		return buf.Bytes(), nil
	}

	// multipart/mixed: body part first, then each attachment.
	mw := multipart.NewWriter(&buf)
	writeHeader("Content-Type", fmt.Sprintf("multipart/mixed; boundary=%s", mw.Boundary()))
	buf.WriteString("\r\n")

	bodyHeader := textproto.MIMEHeader{}
	bodyHeader.Set("Content-Type", bodyContentType)
	bodyHeader.Set("Content-Transfer-Encoding", "8bit")
	bw, err := mw.CreatePart(bodyHeader)
	if err != nil {
		return nil, fmt.Errorf("assemble body part: %w", err)
	}
	if _, err := bw.Write([]byte(normaliseBody(in.Body))); err != nil {
		return nil, fmt.Errorf("write body part: %w", err)
	}

	for i, att := range in.Attachments {
		// Reject CR/LF in the filename: it is interpolated into the
		// Content-Disposition header, where a line break would inject
		// arbitrary MIME-part headers. %q escapes quotes but not CR/LF.
		if strings.ContainsAny(att.Filename, "\r\n") {
			return nil, fmt.Errorf("attachment %d: filename contains a line break", i)
		}
		// The Content-Type is also header-interpolated; reject CR/LF there
		// for the same reason.
		if strings.ContainsAny(att.ContentType, "\r\n") {
			return nil, fmt.Errorf("attachment %d (%s): content_type contains a line break", i, att.Filename)
		}
		raw, decErr := base64.StdEncoding.DecodeString(att.Content)
		if decErr != nil {
			return nil, fmt.Errorf("attachment %d (%s): content is not valid base64: %w", i, att.Filename, decErr)
		}
		ct := att.ContentType
		if strings.TrimSpace(ct) == "" {
			ct = "application/octet-stream"
		}
		ah := textproto.MIMEHeader{}
		ah.Set("Content-Type", ct)
		ah.Set("Content-Transfer-Encoding", "base64")
		ah.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", att.Filename))
		aw, err := mw.CreatePart(ah)
		if err != nil {
			return nil, fmt.Errorf("attachment %d (%s): %w", i, att.Filename, err)
		}
		// Re-encode in wrapped base64 lines for transport hygiene.
		enc := base64.StdEncoding.EncodeToString(raw)
		for len(enc) > 76 {
			if _, err := aw.Write([]byte(enc[:76] + "\r\n")); err != nil {
				return nil, fmt.Errorf("attachment %d write: %w", i, err)
			}
			enc = enc[76:]
		}
		if _, err := aw.Write([]byte(enc + "\r\n")); err != nil {
			return nil, fmt.Errorf("attachment %d write: %w", i, err)
		}
	}

	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("close multipart: %w", err)
	}
	return buf.Bytes(), nil
}

// normaliseBody ensures the body uses CRLF line endings, matching RFC
// 5322 wire form.
func normaliseBody(body string) string {
	body = strings.ReplaceAll(body, "\r\n", "\n")
	return strings.ReplaceAll(body, "\n", "\r\n")
}

// mapOutboxError translates the outbox's typed error vocabulary into the
// SPEC-0006 structured send error. The retriable flag mirrors the SMTP
// reply-code class the outbox would have produced.
//
// Governing: SPEC-0006 REQ "Send-Message Encryption" (Scenario "Send
// failure surfaces structured error").
func mapOutboxError(err error) *ToolError {
	if err == nil {
		return nil
	}
	var keyErr *outbox.ErrKeyLookup
	if errors.As(err, &keyErr) {
		return &ToolError{
			Code:      codeRecipientKeyUnavailable,
			Message:   "could not fetch a recipient's encryption key",
			Retriable: false,
			Details:   map[string]any{"recipient": keyErr.Recipient},
		}
	}
	var authErr *outbox.ErrProtonAuth
	if errors.As(err, &authErr) {
		return &ToolError{Code: codeAuthRequired, Message: "Proton authentication failed", Retriable: false}
	}
	var rateErr *outbox.ErrProtonRateLimit
	if errors.As(err, &rateErr) {
		return &ToolError{Code: codeRateLimited, Message: "Proton rate limited the send", Retriable: true}
	}
	var rejectErr *outbox.ErrProtonReject
	if errors.As(err, &rejectErr) {
		return &ToolError{Code: codeBadRequest, Message: "Proton rejected the message", Retriable: false}
	}
	switch {
	case errors.Is(err, outbox.ErrSubmissionTimedOut):
		return &ToolError{Code: codeProtonUnavailable, Message: "send timed out", Retriable: true}
	case errors.Is(err, outbox.ErrAccountClosed):
		return &ToolError{Code: codeAuthRequired, Message: "account is not available for sending", Retriable: false}
	case errors.Is(err, outbox.ErrSubmissionEnvelope):
		return &ToolError{Code: codeInvalidArgument, Message: "invalid message envelope", Retriable: false}
	}
	var serverErr *outbox.ErrProtonServer
	if errors.As(err, &serverErr) {
		return &ToolError{Code: codeProtonUnavailable, Message: "Proton server error", Retriable: true}
	}
	return &ToolError{Code: codeProtonUnavailable, Message: "send failed", Retriable: true}
}
