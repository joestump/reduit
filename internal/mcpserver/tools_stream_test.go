// Tests for the streaming read tools: get_message(format=raw) chunked
// content + 16 MiB cap, and download_attachment streaming + cap.
//
// Governing: SPEC-0006 REQ "Streaming Bodies and Attachments".
package mcpserver

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/joestump/reduit/internal/proton"
)

// rawContentString reassembles the text content chunks of a raw
// get_message result into the original source.
func rawContentString(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	var b strings.Builder
	for _, c := range res.Content {
		tc, ok := c.(*mcp.TextContent)
		if !ok {
			t.Fatalf("content chunk is %T, want *mcp.TextContent", c)
		}
		b.WriteString(tc.Text)
	}
	return b.String()
}

func TestGetMessage_RawStreamsChunkedContent(t *testing.T) {
	// A body larger than one chunk but under the cap: should come back in
	// multiple ordered text content blocks that reassemble exactly, with
	// truncated=false.
	body := strings.Repeat("A", streamChunkBytes+1234)
	cl := &fakeClient{messages: map[string]proton.Message{
		"m1": {
			MessageMetadata: proton.MessageMetadata{ID: "m1", Subject: "Big"},
			Header:          "Subject: Big",
			Body:            body,
		},
	}}
	r := testRegistry(cl, nil)

	res, out, err := r.getMessage(ctxWithAccount(activeAccount()), nil, GetMessageIn{MessageID: "m1", Format: "raw"})
	if err != nil {
		t.Fatalf("getMessage raw: %v", err)
	}
	if out.Error != nil {
		t.Fatalf("unexpected tool error: %+v", out.Error)
	}
	if out.RawStream == nil {
		t.Fatal("RawStream metadata is nil for format=raw")
	}
	if out.RawStream.Truncated {
		t.Error("RawStream.Truncated = true for a sub-cap body")
	}
	if out.RawStream.Chunks < 2 {
		t.Errorf("RawStream.Chunks = %d, want >= 2 for a >1 chunk body", out.RawStream.Chunks)
	}
	if res == nil || len(res.Content) != out.RawStream.Chunks {
		t.Fatalf("content chunk count %d != RawStream.Chunks %d", len(res.Content), out.RawStream.Chunks)
	}
	// The raw struct field MUST be empty -- raw bytes ride in Content only.
	if out.Message.Raw != "" {
		t.Error("Message.Raw is populated; raw bytes must live in Content chunks only")
	}
	want := "Subject: Big\r\n\r\n" + body
	if got := rawContentString(t, res); got != want {
		t.Errorf("reassembled raw mismatch: got %d bytes, want %d bytes", len(got), len(want))
	}
}

func TestGetMessage_RawCapTruncates(t *testing.T) {
	// A body over the 16 MiB cap must truncate to exactly the cap and flag
	// truncated, so process memory never exceeds the cap.
	body := strings.Repeat("B", streamCapBytes+5_000_000)
	cl := &fakeClient{messages: map[string]proton.Message{
		"big": {
			MessageMetadata: proton.MessageMetadata{ID: "big"},
			// No header so rawSource returns just the body, keeping the
			// length math exact at the cap boundary.
			Body: body,
		},
	}}
	r := testRegistry(cl, nil)

	res, out, err := r.getMessage(ctxWithAccount(activeAccount()), nil, GetMessageIn{MessageID: "big", Format: "raw"})
	if err != nil {
		t.Fatalf("getMessage raw: %v", err)
	}
	if out.RawStream == nil || !out.RawStream.Truncated {
		t.Fatalf("RawStream.Truncated = false; want true for an over-cap body")
	}
	if out.RawStream.Size != streamCapBytes {
		t.Errorf("RawStream.Size = %d, want exactly the cap %d", out.RawStream.Size, streamCapBytes)
	}
	if got := len(rawContentString(t, res)); got != streamCapBytes {
		t.Errorf("reassembled content = %d bytes, want capped %d", got, streamCapBytes)
	}
}

func TestGetMessage_MetadataUnaffected(t *testing.T) {
	cl := &fakeClient{messages: map[string]proton.Message{
		"m1": {MessageMetadata: proton.MessageMetadata{ID: "m1", Subject: "Hi"}, Body: "plain body"},
	}}
	r := testRegistry(cl, nil)
	res, out, err := r.getMessage(ctxWithAccount(activeAccount()), nil, GetMessageIn{MessageID: "m1"})
	if err != nil || out.Error != nil {
		t.Fatalf("getMessage metadata: err=%v toolErr=%+v", err, out.Error)
	}
	if res != nil {
		t.Error("metadata format returned a custom CallToolResult; want nil (inline body)")
	}
	if out.RawStream != nil {
		t.Error("metadata format set RawStream; want nil")
	}
	if out.Message.Body != "plain body" {
		t.Errorf("Message.Body = %q, want inline body", out.Message.Body)
	}
}

func TestGetMessage_ListsAttachments(t *testing.T) {
	cl := &fakeClient{messages: map[string]proton.Message{
		"m1": {
			MessageMetadata: proton.MessageMetadata{ID: "m1"},
			Attachments: []proton.Attachment{
				{ID: "att-1", Name: "report.pdf", MIMEType: "application/pdf", Size: 4096},
			},
		},
	}}
	r := testRegistry(cl, nil)
	_, out, err := r.getMessage(ctxWithAccount(activeAccount()), nil, GetMessageIn{MessageID: "m1"})
	if err != nil || out.Error != nil {
		t.Fatalf("getMessage: err=%v toolErr=%+v", err, out.Error)
	}
	if len(out.Message.Attachments) != 1 {
		t.Fatalf("attachments = %d, want 1", len(out.Message.Attachments))
	}
	a := out.Message.Attachments[0]
	if a.AttachmentID != "att-1" || a.Name != "report.pdf" || a.Size != 4096 {
		t.Errorf("attachment meta mismatch: %+v", a)
	}
}

// ----- download_attachment -----

func decodeBlobs(t *testing.T, res *mcp.CallToolResult) []byte {
	t.Helper()
	var out []byte
	for _, c := range res.Content {
		er, ok := c.(*mcp.EmbeddedResource)
		if !ok {
			t.Fatalf("content chunk is %T, want *mcp.EmbeddedResource", c)
		}
		dec, err := base64.StdEncoding.DecodeString(er.Resource.Text)
		if err != nil {
			t.Fatalf("base64 decode chunk: %v", err)
		}
		out = append(out, dec...)
	}
	return out
}

func TestDownloadAttachment_StreamsChunks(t *testing.T) {
	payload := []byte(strings.Repeat("Z", streamChunkBytes+777))
	cl := &fakeClient{
		messages: map[string]proton.Message{
			"m1": {
				MessageMetadata: proton.MessageMetadata{ID: "m1"},
				Attachments:     []proton.Attachment{{ID: "att-1", Name: "data.bin", MIMEType: "application/octet-stream", Size: int64(len(payload))}},
			},
		},
		attachments: map[string][]byte{"att-1": payload},
	}
	r := testRegistry(cl, nil)

	res, out, err := r.downloadAttachment(ctxWithAccount(activeAccount()), nil, DownloadAttachmentIn{
		MessageID: "m1", AttachmentID: "att-1",
	})
	if err != nil {
		t.Fatalf("downloadAttachment: %v", err)
	}
	if out.Error != nil {
		t.Fatalf("unexpected tool error: %+v", out.Error)
	}
	if out.Truncated {
		t.Error("Truncated = true for a sub-cap attachment")
	}
	if out.Size != len(payload) {
		t.Errorf("Size = %d, want %d", out.Size, len(payload))
	}
	if out.Filename != "data.bin" || out.MIMEType != "application/octet-stream" {
		t.Errorf("metadata mismatch: %+v", out)
	}
	if out.Chunks < 2 {
		t.Errorf("Chunks = %d, want >= 2", out.Chunks)
	}
	if got := decodeBlobs(t, res); string(got) != string(payload) {
		t.Errorf("reassembled attachment mismatch: got %d bytes want %d", len(got), len(payload))
	}
}

func TestDownloadAttachment_CapTruncates(t *testing.T) {
	payload := []byte(strings.Repeat("Y", streamCapBytes+3_000_000))
	cl := &fakeClient{
		messages: map[string]proton.Message{
			"m1": {
				MessageMetadata: proton.MessageMetadata{ID: "m1"},
				Attachments:     []proton.Attachment{{ID: "att-1", Size: int64(len(payload))}},
			},
		},
		attachments: map[string][]byte{"att-1": payload},
	}
	r := testRegistry(cl, nil)

	res, out, err := r.downloadAttachment(ctxWithAccount(activeAccount()), nil, DownloadAttachmentIn{
		MessageID: "m1", AttachmentID: "att-1",
	})
	if err != nil {
		t.Fatalf("downloadAttachment: %v", err)
	}
	if !out.Truncated {
		t.Fatal("Truncated = false; want true for an over-cap attachment")
	}
	if out.Size != streamCapBytes {
		t.Errorf("Size = %d, want capped %d", out.Size, streamCapBytes)
	}
	if got := len(decodeBlobs(t, res)); got != streamCapBytes {
		t.Errorf("reassembled = %d bytes, want capped %d", got, streamCapBytes)
	}
}

func TestDownloadAttachment_UnknownAttachmentIsNotFound(t *testing.T) {
	cl := &fakeClient{messages: map[string]proton.Message{
		"m1": {MessageMetadata: proton.MessageMetadata{ID: "m1"}}, // no attachments
	}}
	r := testRegistry(cl, nil)
	_, out, err := r.downloadAttachment(ctxWithAccount(activeAccount()), nil, DownloadAttachmentIn{
		MessageID: "m1", AttachmentID: "nope",
	})
	if err != nil {
		t.Fatalf("downloadAttachment: %v", err)
	}
	if out.Error == nil || out.Error.Code != codeNotFound {
		t.Fatalf("error = %+v, want not_found", out.Error)
	}
}

func TestDownloadAttachment_UnknownMessageIsNotFound(t *testing.T) {
	cl := &fakeClient{messages: map[string]proton.Message{}}
	r := testRegistry(cl, nil)
	_, out, err := r.downloadAttachment(ctxWithAccount(activeAccount()), nil, DownloadAttachmentIn{
		MessageID: "ghost", AttachmentID: "att-1",
	})
	if err != nil {
		t.Fatalf("downloadAttachment: %v", err)
	}
	if out.Error == nil || out.Error.Code != codeNotFound {
		t.Fatalf("error = %+v, want not_found", out.Error)
	}
}

func TestDownloadAttachment_RequiresIDs(t *testing.T) {
	r := testRegistry(&fakeClient{}, nil)
	_, out, _ := r.downloadAttachment(ctxWithAccount(activeAccount()), nil, DownloadAttachmentIn{AttachmentID: "a"})
	if out.Error == nil || out.Error.Code != codeInvalidArgument {
		t.Errorf("missing message_id: error = %+v, want invalid_argument", out.Error)
	}
	_, out2, _ := r.downloadAttachment(ctxWithAccount(activeAccount()), nil, DownloadAttachmentIn{MessageID: "m"})
	if out2.Error == nil || out2.Error.Code != codeInvalidArgument {
		t.Errorf("missing attachment_id: error = %+v, want invalid_argument", out2.Error)
	}
}

// cappedBuffer unit coverage: exercise the sink directly so the cap math
// is pinned independent of the tool wiring.
func TestCappedBuffer_RetainsUpToCapAndFlags(t *testing.T) {
	c := newCappedBuffer(10)
	n, err := c.ReadFrom(strings.NewReader("0123456789ABCDEF"))
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != 10 {
		t.Errorf("retained = %d, want 10", n)
	}
	if !c.Truncated() {
		t.Error("Truncated = false; want true")
	}
	if string(c.Bytes()) != "0123456789" {
		t.Errorf("retained bytes = %q, want first 10", c.Bytes())
	}
}

func TestCappedBuffer_UnderCapNoTruncation(t *testing.T) {
	c := newCappedBuffer(100)
	if _, err := c.ReadFrom(strings.NewReader("short")); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if c.Truncated() {
		t.Error("Truncated = true for a sub-cap source")
	}
	if c.Len() != 5 {
		t.Errorf("Len = %d, want 5", c.Len())
	}
}
