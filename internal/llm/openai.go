package llm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

// Compile-time assurance that OpenAIClient satisfies the Client interface.
var _ Client = (*OpenAIClient)(nil)

// base64Std standard-base64-encodes b (for data: URLs).
func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// endpoint is one configured egress: a base URL, an optional bearer key, and
// an HTTP client. Each of the two model roles is backed by its own endpoint, so
// text content and raw media bytes never share a destination unless the
// operator deliberately points both roles at the same URL (ADR-0018).
type endpoint struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// OpenAIClient is an OpenAI-compatible Client with two independently-configured
// model roles (ADR-0018). It targets any endpoint speaking the OpenAI REST
// shapes (/v1/embeddings, /v1/chat/completions, /v1/audio/transcriptions) — a
// local LiteLLM proxy (the default), Ollama, vLLM, or OpenAI itself.
type OpenAIClient struct {
	// text backs the text/embedding role (Embed + text Chat).
	text endpoint
	// multimodal backs the multimodal role (Vision + Transcribe). It is nil
	// when the role is unconfigured (opt-in); Vision/Transcribe then return
	// ErrMultimodalNotConfigured rather than falling back to the text role.
	multimodal *endpoint

	embedModel string // text/embedding role: embedding model
	textModel  string // text/embedding role: chat model
	mmModel    string // multimodal role: OCR/vision/audio model
}

// Options configures an OpenAIClient. The text and multimodal roles are
// configured independently (ADR-0018); supplying no multimodal base URL or
// model leaves that role disabled.
type Options struct {
	// Text/embedding role. Local by default. An empty TextAPIKey is allowed
	// (local proxies/Ollama accept any or no key).
	TextBaseURL string // e.g. http://127.0.0.1:4000/v1 (trailing slash optional)
	TextAPIKey  string
	TextModel   string // chat model
	EmbedModel  string // embedding model

	// Multimodal role (opt-in). When MultimodalBaseURL or MultimodalModel is
	// empty the role is disabled and Vision/Transcribe return
	// ErrMultimodalNotConfigured.
	MultimodalBaseURL string
	MultimodalAPIKey  string
	MultimodalModel   string

	Timeout    time.Duration
	HTTPClient *http.Client // optional; for tests
}

// New constructs an OpenAIClient. The text base URL and model names are
// required for their corresponding operations; an empty API key is allowed. The
// multimodal role is enabled only when both its base URL and model are set.
func New(opts Options) *OpenAIClient {
	hc := opts.HTTPClient
	if hc == nil {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = 60 * time.Second
		}
		hc = &http.Client{Timeout: timeout}
	}
	c := &OpenAIClient{
		text: endpoint{
			baseURL:    strings.TrimRight(opts.TextBaseURL, "/"),
			apiKey:     opts.TextAPIKey,
			httpClient: hc,
		},
		embedModel: opts.EmbedModel,
		textModel:  opts.TextModel,
		mmModel:    opts.MultimodalModel,
	}
	if opts.MultimodalBaseURL != "" && opts.MultimodalModel != "" {
		c.multimodal = &endpoint{
			baseURL:    strings.TrimRight(opts.MultimodalBaseURL, "/"),
			apiKey:     opts.MultimodalAPIKey,
			httpClient: hc,
		}
	}
	return c
}

// --- Embeddings (text/embedding role) ---

type embedRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

type embedResponse struct {
	Data []struct {
		Embedding []float32 `json:"embedding"`
		Index     int       `json:"index"`
	} `json:"data"`
}

// Embed implements Client using the text/embedding role.
func (c *OpenAIClient) Embed(ctx context.Context, inputs []string) ([][]float32, error) {
	if len(inputs) == 0 {
		return nil, nil
	}
	if c.embedModel == "" {
		return nil, fmt.Errorf("llm: embed model not configured")
	}
	var resp embedResponse
	if err := c.text.postJSON(ctx, "/embeddings", embedRequest{Model: c.embedModel, Input: inputs}, &resp); err != nil {
		return nil, err
	}
	if len(resp.Data) != len(inputs) {
		return nil, fmt.Errorf("llm: embeddings count mismatch: got %d, want %d", len(resp.Data), len(inputs))
	}
	// Reorder defensively by the provider-reported index.
	out := make([][]float32, len(inputs))
	for _, d := range resp.Data {
		if d.Index < 0 || d.Index >= len(out) {
			return nil, fmt.Errorf("llm: embedding index %d out of range", d.Index)
		}
		out[d.Index] = d.Embedding
	}
	for i, v := range out {
		if len(v) == 0 {
			return nil, fmt.Errorf("llm: missing embedding for input %d", i)
		}
	}
	return out, nil
}

// --- Chat (text/embedding role) ---

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float32       `json:"temperature,omitempty"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

// Chat implements Client using the text/embedding role.
func (c *OpenAIClient) Chat(ctx context.Context, req ChatRequest) (string, error) {
	model := req.Model
	if model == "" {
		model = c.textModel
	}
	if model == "" {
		return "", fmt.Errorf("llm: text model not configured")
	}
	body := chatRequest{Model: model, Temperature: req.Temperature, MaxTokens: req.MaxTokens}
	for _, m := range req.Messages {
		body.Messages = append(body.Messages, chatMessage{Role: string(m.Role), Content: m.Content})
	}
	var resp chatResponse
	if err := c.text.postJSON(ctx, "/chat/completions", body, &resp); err != nil {
		return "", err
	}
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("llm: chat returned no choices")
	}
	return resp.Choices[0].Message.Content, nil
}

// --- Vision (multimodal role) ---

// Vision implements Client using a chat completion with an image_url content
// part (OpenAI vision shape; a data: URL so the provider performs no external
// fetch). It routes to the multimodal role, never the text role (SPEC-0009).
func (c *OpenAIClient) Vision(ctx context.Context, image []byte, mimeType, prompt string) (string, error) {
	if c.multimodal == nil || c.mmModel == "" {
		return "", ErrMultimodalNotConfigured
	}
	if prompt == "" {
		prompt = "Briefly describe this image in one sentence."
	}
	dataURL := "data:" + mimeType + ";base64," + base64Std(image)
	// Vision uses the array-content message shape, which differs from the plain
	// chat shape, so it is built inline here.
	payload := map[string]any{
		"model": c.mmModel,
		"messages": []any{
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{"type": "text", "text": prompt},
					map[string]any{"type": "image_url", "image_url": map[string]any{"url": dataURL}},
				},
			},
		},
	}
	var resp chatResponse
	if err := c.multimodal.postJSON(ctx, "/chat/completions", payload, &resp); err != nil {
		return "", err
	}
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("llm: vision returned no choices")
	}
	return resp.Choices[0].Message.Content, nil
}

// --- Transcription (multimodal role) ---

// Transcribe implements Client using the OpenAI /audio/transcriptions endpoint
// (multipart form), routed to the multimodal role (SPEC-0009). The configured
// multimodal model names the ASR; a LiteLLM proxy maps it to the concrete
// local/hosted backend.
func (c *OpenAIClient) Transcribe(ctx context.Context, audio []byte, filename string) (string, error) {
	if c.multimodal == nil || c.mmModel == "" {
		return "", ErrMultimodalNotConfigured
	}
	if filename == "" {
		filename = "audio.m4a"
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		return "", err
	}
	if _, err := fw.Write(audio); err != nil {
		return "", err
	}
	if err := mw.WriteField("model", c.mmModel); err != nil {
		return "", err
	}
	if err := mw.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.multimodal.baseURL+"/audio/transcriptions", &buf)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	c.multimodal.setAuth(req)

	respBody, err := c.multimodal.do(req)
	if err != nil {
		return "", err
	}
	var resp struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("llm: decode transcription: %w", err)
	}
	return resp.Text, nil
}

// --- HTTP plumbing (per endpoint) ---

// postJSON marshals body to JSON, POSTs it to baseURL+path, and decodes the
// response into out.
func (e *endpoint) postJSON(ctx context.Context, path string, body, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	e.setAuth(req)

	respBody, err := e.do(req)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("llm: decode response from %s: %w", path, err)
	}
	return nil
}

// setAuth attaches the bearer key when one is configured. The key is only ever
// written to the Authorization header — never to logs or error messages.
func (e *endpoint) setAuth(req *http.Request) {
	if e.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.apiKey)
	}
}

// do executes the request and returns the body, mapping non-2xx to an error
// that includes a (truncated) response body for diagnosis. Errors carry only
// the request path and status — never the Authorization header / API key.
func (e *endpoint) do(req *http.Request) ([]byte, error) {
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("llm: request to %s: %w", req.URL.Path, err)
	}
	defer resp.Body.Close()
	// Cap the response body to bound memory against a misbehaving endpoint. The
	// largest legitimate response is an embeddings batch: max batch (512) ×
	// large dims (e.g. 3072) as JSON ≈ ~14 MiB, so 64 MiB leaves ample headroom
	// while still bounding pathological responses.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := string(body)
		if len(snippet) > 500 {
			snippet = snippet[:500]
		}
		return nil, fmt.Errorf("llm: %s returned %d: %s", req.URL.Path, resp.StatusCode, snippet)
	}
	return body, nil
}
