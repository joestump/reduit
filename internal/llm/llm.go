// Package llm is Reduit's single, OpenAI-compatible gateway to a language
// model. It is the ONLY package in Reduit that makes outbound-network/egress
// calls for model work — the Proton sync client (ADR-0001/0014/0020) is the one
// other, separate boundary. Embeddings, text chat (contact-fact extraction,
// RAG composition), and opt-in multimodal media handling (OCR, captions, audio
// transcription) all route through here, so the set of places mail content can
// leave the machine is a single, auditable line of config.
//
// Two independently-configured model roles share this one client (ADR-0018):
//
//   - Text/embedding role — Embed + text Chat (SPEC-0008: embeddings & search).
//     Local by default, so out of the box nothing leaves the device.
//   - Multimodal role — Vision / Transcribe (SPEC-0009: attachment extraction).
//     Independently configured base URL / model / key; opt-in. Pointing it at a
//     hosted model is the heaviest, most sensitive egress Reduit has (raw
//     image/audio bytes) and must be a deliberate, documented choice.
//
// There is NO telemetry and NO analytics. API keys come from the environment
// (ADR-0018) and are never logged: errors surface request paths and status
// codes, never the Authorization header.
//
// Governing: ADR-0018 (LLM access & single-egress privacy posture).
package llm

import (
	"context"
	"errors"
)

// ErrMultimodalNotConfigured is returned by Vision and Transcribe when the
// multimodal role has no base URL / model configured. The multimodal role is
// opt-in (ADR-0018); with it unset, media features fail cleanly rather than
// silently borrowing the text role's endpoint and widening egress by accident.
var ErrMultimodalNotConfigured = errors.New("llm: multimodal role not configured")

// Client is the provider-agnostic gateway the rest of Reduit depends on. All
// methods are safe for concurrent use. Embed and Chat use the text/embedding
// role; Vision and Transcribe use the multimodal role — content is routed to
// the correct role's endpoint/model/key and never crosses between them.
type Client interface {
	// Embed returns one embedding vector per input string, in order, via the
	// text/embedding role. The vectors share the model's dimensionality.
	Embed(ctx context.Context, inputs []string) ([][]float32, error)

	// Chat returns a single text completion via the text/embedding role.
	Chat(ctx context.Context, req ChatRequest) (string, error)

	// Vision returns a short caption/description of an image via the
	// multimodal role. mimeType is the image's content type (e.g.
	// "image/jpeg"). Returns ErrMultimodalNotConfigured if the role is unset.
	Vision(ctx context.Context, image []byte, mimeType, prompt string) (string, error)

	// Transcribe converts audio bytes (e.g. a voice note) to text via the
	// multimodal role. filename hints the audio format (e.g. "voice.m4a").
	// Returns ErrMultimodalNotConfigured if the role is unset.
	Transcribe(ctx context.Context, audio []byte, filename string) (string, error)
}

// Role identifies the author of a chat message.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// Message is one chat turn.
type Message struct {
	Role    Role
	Content string
}

// ChatRequest parameterizes a single text completion. Model is optional; when
// empty the text role's configured chat model is used.
type ChatRequest struct {
	Messages    []Message
	Model       string
	Temperature float32
	MaxTokens   int
}
