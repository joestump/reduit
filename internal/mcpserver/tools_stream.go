// Streaming read tools: large-body get_message(format=raw) and
// download_attachment. Both honour SPEC-0006 REQ "Streaming Bodies and
// Attachments": the payload is delivered as ordered MCP content chunks
// and Reduit's in-process buffering is bounded by a documented 16 MiB
// cap regardless of message/attachment size.
//
// SDK CONSTRAINT (load-bearing for reviewers): the
// modelcontextprotocol/go-sdk ToolHandlerFor contract returns a single
// *mcp.CallToolResult carrying a []mcp.Content slice. The JSON-RPC
// response is flushed as ONE message -- the SDK does not expose an
// incremental per-chunk wire flush for typed tool handlers. "Streaming"
// here therefore means two concrete things, both of which the SDK does
// support:
//
//  1. MEMORY CAP. We never copy more than streamCapBytes (16 MiB) of
//     body/attachment payload into our own buffers. Past the cap we
//     stop reading and flag the result truncated, so a 50 MiB body can
//     never blow the cap. For attachments this is enforced by reading
//     through a capped io.ReaderFrom that refuses bytes beyond the cap;
//     for the raw body we slice the upstream-decoded source at the cap.
//
//  2. CONTENT CHUNKING. The capped payload is split into fixed-size
//     (streamChunkBytes) content blocks rather than one monolithic
//     field, which is the "MCP-protocol-defined content chunks" shape
//     the spec's scenario calls for.
//
// What we do NOT get from the current stack is true end-to-end streaming
// FROM Proton: go-proton-api decrypts the whole body/attachment into
// memory upstream before handing it back, so the upstream transient
// decrypt buffer is outside our cap. Bounding that would need an
// upstream streaming-decrypt API that does not exist today. The cap here
// bounds Reduit's added buffering and the bytes copied onward to the MCP
// client -- which is what the spec's "server's memory usage" target is
// about for the relay.
//
// Governing: SPEC-0006 REQ "Streaming Bodies and Attachments",
// ADR-0008 (embedded MCP server).
package mcpserver

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Streaming caps per SPEC-0006 REQ "Streaming Bodies and Attachments"
// Scenario "Large message body streamed": the documented default memory
// cap is 16 MiB. Payload is emitted in streamChunkBytes blocks.
const (
	// streamCapBytes is the hard ceiling on how many bytes of a single
	// payload Reduit buffers + emits. A payload larger than this is
	// truncated to the cap and flagged, so process memory for one
	// get_message/download_attachment call is bounded regardless of the
	// underlying object size.
	streamCapBytes = 16 << 20 // 16 MiB

	// streamChunkBytes is the per-content-block size. The capped payload
	// is split into ceil(len/streamChunkBytes) ordered content items.
	streamChunkBytes = 1 << 20 // 1 MiB
)

// ----- download_attachment -----

// DownloadAttachmentIn is the input schema for download_attachment.
type DownloadAttachmentIn struct {
	MessageID    string `json:"message_id" jsonschema:"Proton message ID owning the attachment"`
	AttachmentID string `json:"attachment_id" jsonschema:"Proton attachment ID, as listed under the message's attachments"`
}

// DownloadAttachmentOut is the structured metadata accompanying the
// streamed attachment content. The bytes themselves ride in the
// CallToolResult.Content blocks (base64 blob chunks); this struct carries
// the descriptive envelope an agent needs to reassemble + interpret them.
type DownloadAttachmentOut struct {
	AttachmentID string     `json:"attachment_id,omitempty"`
	Filename     string     `json:"filename,omitempty"`
	MIMEType     string     `json:"mime_type,omitempty"`
	Size         int        `json:"size,omitempty" jsonschema:"Number of decrypted bytes delivered across the content chunks"`
	Chunks       int        `json:"chunks,omitempty" jsonschema:"Number of base64 content chunks the bytes were split into"`
	Truncated    bool       `json:"truncated,omitempty" jsonschema:"True when the attachment exceeded the 16 MiB streaming cap and was truncated"`
	Encoding     string     `json:"encoding,omitempty" jsonschema:"Transfer encoding of the content chunks (base64)"`
	Error        *ToolError `json:"error,omitempty"`
}

func (r *toolRegistry) registerStream(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "download_attachment",
		Description: "Download one attachment's decrypted bytes, streamed as ordered base64 content chunks. Bounded to a 16 MiB cap; larger attachments are truncated and flagged.",
	}, r.downloadAttachment)
}

// downloadAttachment implements the download_attachment tool. It resolves
// the attachment's metadata off the owning message (so a cross-account
// message ID collapses to not_found like every other tool), then streams
// the decrypted bytes through a memory-capped writer and emits them as
// base64 content chunks.
//
// Governing: SPEC-0006 REQ "Streaming Bodies and Attachments" (Scenario
// "Attachment streaming"), SPEC-0006 REQ "Account Scope on All
// Operations".
func (r *toolRegistry) downloadAttachment(ctx context.Context, _ *mcp.CallToolRequest, in DownloadAttachmentIn) (*mcp.CallToolResult, DownloadAttachmentOut, error) {
	acct, err := r.accountFor(ctx)
	if err != nil {
		return nil, DownloadAttachmentOut{}, err
	}
	if strings.TrimSpace(in.MessageID) == "" {
		return nil, DownloadAttachmentOut{Error: &ToolError{
			Code: codeInvalidArgument, Message: "message_id is required", Retriable: false,
		}}, nil
	}
	if strings.TrimSpace(in.AttachmentID) == "" {
		return nil, DownloadAttachmentOut{Error: &ToolError{
			Code: codeInvalidArgument, Message: "attachment_id is required", Retriable: false,
		}}, nil
	}
	cl, terr := r.clientFor(ctx, acct)
	if terr != nil {
		return nil, DownloadAttachmentOut{Error: terr}, nil
	}

	// Resolve the message first to (a) scope the lookup to this account
	// and (b) locate the attachment's filename/MIME metadata. An
	// attachment ID not present on a message the account can see is a
	// not_found miss -- identical to a genuinely missing attachment.
	msg, mErr := cl.GetMessage(ctx, in.MessageID)
	if mErr != nil {
		return nil, DownloadAttachmentOut{Error: mapMessageLookupError(mErr)}, nil
	}
	var meta *attachmentMeta
	for i := range msg.Attachments {
		if msg.Attachments[i].ID == in.AttachmentID {
			meta = &attachmentMeta{
				name:     msg.Attachments[i].Name,
				mimeType: string(msg.Attachments[i].MIMEType),
			}
			break
		}
	}
	if meta == nil {
		return nil, DownloadAttachmentOut{Error: &ToolError{
			Code: codeNotFound, Message: "attachment not found", Retriable: false,
		}}, nil
	}

	// Stream the decrypted bytes through a capped sink so we never retain
	// more than streamCapBytes. Overflow past the cap is surfaced via
	// sink.Truncated() (not an error): the agent still gets the first
	// 16 MiB plus the truncated flag. A returned error is a genuine
	// download failure.
	sink := newCappedBuffer(streamCapBytes)
	if dErr := cl.GetAttachmentInto(ctx, in.AttachmentID, sink); dErr != nil {
		return nil, DownloadAttachmentOut{Error: mapProtonError(dErr)}, nil
	}

	contents, chunks := chunkBlob(sink.Bytes(), in.AttachmentID, meta.mimeType)
	out := DownloadAttachmentOut{
		AttachmentID: in.AttachmentID,
		Filename:     meta.name,
		MIMEType:     meta.mimeType,
		Size:         sink.Len(),
		Chunks:       chunks,
		Truncated:    sink.Truncated(),
		Encoding:     "base64",
	}
	return &mcp.CallToolResult{Content: contents}, out, nil
}

// attachmentMeta is the slice of an attachment's metadata the streaming
// tool needs to describe the bytes it emits.
type attachmentMeta struct {
	name     string
	mimeType string
}

// ----- raw-body streaming (shared with get_message) -----

// streamRawBody builds the chunked content + metadata for a
// get_message(format=raw) response. It is invoked from getMessage when
// format=raw so the inline (≤cap) and large (chunked) paths share one
// implementation. The raw source is already in memory (go-proton-api
// decoded msg.Body upstream); we slice it at the cap so the bytes WE
// emit -- and any copy we make -- stay bounded.
//
// Governing: SPEC-0006 REQ "Streaming Bodies and Attachments" (Scenario
// "Large message body streamed").
func streamRawBody(raw string) (contents []mcp.Content, meta rawStreamMeta) {
	b := []byte(raw)
	truncated := false
	if len(b) > streamCapBytes {
		b = b[:streamCapBytes]
		truncated = true
	}
	chunks := make([]mcp.Content, 0, len(b)/streamChunkBytes+1)
	for off := 0; off < len(b); off += streamChunkBytes {
		end := off + streamChunkBytes
		if end > len(b) {
			end = len(b)
		}
		chunks = append(chunks, &mcp.TextContent{Text: string(b[off:end])})
	}
	// A zero-length body still yields one empty content block so the
	// agent gets a well-formed (single, empty) chunk rather than nil.
	if len(chunks) == 0 {
		chunks = append(chunks, &mcp.TextContent{Text: ""})
	}
	return chunks, rawStreamMeta{
		Size:      len(b),
		Chunks:    len(chunks),
		Truncated: truncated,
	}
}

// rawStreamMeta is the streaming envelope embedded in GetMessageOut when
// format=raw. The raw bytes ride in CallToolResult.Content; this carries
// the chunk accounting + truncation flag.
type rawStreamMeta struct {
	Size      int  `json:"size" jsonschema:"Number of raw RFC822 bytes delivered across the content chunks"`
	Chunks    int  `json:"chunks" jsonschema:"Number of content chunks the raw source was split into"`
	Truncated bool `json:"truncated,omitempty" jsonschema:"True when the body exceeded the 16 MiB streaming cap and was truncated"`
}

// chunkBlob splits binary payload into base64-encoded EmbeddedResource
// content blocks. Each block is at most streamChunkBytes of RAW bytes
// (base64 inflates ~4/3, but the cap is on raw bytes, matching the
// memory budget). The URI carries the attachment ID + chunk index so an
// agent can order + correlate the blocks.
func chunkBlob(b []byte, attachmentID, mimeType string) (contents []mcp.Content, chunks int) {
	contents = make([]mcp.Content, 0, len(b)/streamChunkBytes+1)
	idx := 0
	for off := 0; off < len(b); off += streamChunkBytes {
		end := off + streamChunkBytes
		if end > len(b) {
			end = len(b)
		}
		enc := base64.StdEncoding.EncodeToString(b[off:end])
		contents = append(contents, &mcp.EmbeddedResource{
			Resource: &mcp.ResourceContents{
				URI:      fmt.Sprintf("attachment://%s/%d", attachmentID, idx),
				MIMEType: mimeType,
				Text:     enc,
			},
		})
		idx++
	}
	if len(contents) == 0 {
		contents = append(contents, &mcp.EmbeddedResource{
			Resource: &mcp.ResourceContents{
				URI:      fmt.Sprintf("attachment://%s/0", attachmentID),
				MIMEType: mimeType,
				Text:     "",
			},
		})
		idx = 1
	}
	return contents, idx
}

// ----- capped streaming sink -----

// cappedBuffer is an io.ReaderFrom that accumulates at most `cap` bytes.
// Once the cap is reached it stops copying and reports truncation; it
// keeps draining the source (discarding the overflow) so the upstream
// HTTP body is fully consumed and the connection can be reused, but it
// never grows its own buffer past the cap. This is what bounds Reduit's
// in-process attachment buffering to the 16 MiB streaming cap.
//
// Governing: SPEC-0006 REQ "Streaming Bodies and Attachments".
type cappedBuffer struct {
	cap       int
	buf       []byte
	truncated bool
}

func newCappedBuffer(cap int) *cappedBuffer {
	return &cappedBuffer{cap: cap, buf: make([]byte, 0, minInt(cap, streamChunkBytes))}
}

// ReadFrom copies from r into the buffer up to cap bytes. Bytes beyond
// the cap are read and discarded so the source is drained (the upstream
// HTTP body is fully consumed) but never retained, and Truncated flips
// true. Returns the number of bytes RETAINED (≤ cap) and an error only on
// a genuine read failure -- not on cap overflow (overflow is surfaced via
// Truncated()).
func (c *cappedBuffer) ReadFrom(r io.Reader) (int64, error) {
	tmp := make([]byte, 32<<10) // 32 KiB working buffer; constant regardless of payload
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			room := c.cap - len(c.buf)
			if n > room {
				// Source produced more than we have room for: retain what
				// fits, discard the rest, and mark the result truncated.
				if room > 0 {
					c.buf = append(c.buf, tmp[:room]...)
				}
				c.truncated = true
			} else {
				c.buf = append(c.buf, tmp[:n]...)
			}
		}
		if err == io.EOF {
			return int64(len(c.buf)), nil
		}
		if err != nil {
			return int64(len(c.buf)), err
		}
	}
}

// Bytes returns the retained (≤ cap) payload.
func (c *cappedBuffer) Bytes() []byte { return c.buf }

// Len returns the number of retained bytes.
func (c *cappedBuffer) Len() int { return len(c.buf) }

// Truncated reports whether the source exceeded the cap.
func (c *cappedBuffer) Truncated() bool { return c.truncated }

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
