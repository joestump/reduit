package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newDualClient stands up two fake OpenAI-compatible endpoints — one per model
// role — and returns a client wired to both, plus the two servers' base URLs so
// a test can assert which role a call actually hit. This is the core guarantee
// of ADR-0018: text content goes to the text endpoint, media to the multimodal
// endpoint, and the two never cross.
func newDualClient(t *testing.T, textH, mmH http.HandlerFunc) *OpenAIClient {
	t.Helper()
	textSrv := httptest.NewServer(textH)
	t.Cleanup(textSrv.Close)
	mmSrv := httptest.NewServer(mmH)
	t.Cleanup(mmSrv.Close)
	return New(Options{
		TextBaseURL:       textSrv.URL + "/v1",
		TextAPIKey:        "text-key",
		TextModel:         "test-chat",
		EmbedModel:        "test-embed",
		MultimodalBaseURL: mmSrv.URL + "/v1",
		MultimodalAPIKey:  "mm-key",
		MultimodalModel:   "test-vision",
		HTTPClient:        textSrv.Client(),
	})
}

// failHandler fails the test if the endpoint is contacted at all — used to
// prove the *other* role's endpoint is never touched.
func failHandler(t *testing.T, role string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("%s endpoint must not be contacted, but got %s %s", role, r.Method, r.URL.Path)
		w.WriteHeader(http.StatusTeapot)
	}
}

func TestEmbed(t *testing.T) {
	c := newDualClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/embeddings" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer text-key" {
			t.Errorf("auth header = %q", got)
		}
		var req embedRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Model != "test-embed" {
			t.Errorf("model = %q", req.Model)
		}
		// Return vectors out of order to exercise index-based reordering.
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":[
			{"index":1,"embedding":[0.1,0.2]},
			{"index":0,"embedding":[0.3,0.4]}
		]}`)
	}, failHandler(t, "multimodal"))

	vecs, err := c.Embed(context.Background(), []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(vecs) != 2 {
		t.Fatalf("got %d vectors", len(vecs))
	}
	// index 0 → [0.3,0.4], index 1 → [0.1,0.2]
	if vecs[0][0] != 0.3 || vecs[1][0] != 0.1 {
		t.Errorf("vectors not reordered by index: %v", vecs)
	}
}

func TestEmbedCountMismatch(t *testing.T) {
	c := newDualClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":[{"index":0,"embedding":[0.1]}]}`)
	}, failHandler(t, "multimodal"))
	if _, err := c.Embed(context.Background(), []string{"a", "b"}); err == nil {
		t.Error("expected count-mismatch error")
	}
}

func TestChat(t *testing.T) {
	c := newDualClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer text-key" {
			t.Errorf("auth header = %q", got)
		}
		var req chatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Model != "test-chat" || len(req.Messages) != 2 {
			t.Errorf("unexpected request: %+v", req)
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"hello there"}}]}`)
	}, failHandler(t, "multimodal"))
	got, err := c.Chat(context.Background(), ChatRequest{Messages: []Message{
		{Role: RoleSystem, Content: "sys"}, {Role: RoleUser, Content: "hi"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got != "hello there" {
		t.Errorf("chat = %q", got)
	}
}

func TestVisionUsesMultimodalRole(t *testing.T) {
	c := newDualClient(t, failHandler(t, "text"), func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("path = %s", r.URL.Path)
		}
		// Vision must authenticate with the multimodal key, not the text key.
		if got := r.Header.Get("Authorization"); got != "Bearer mm-key" {
			t.Errorf("auth header = %q, want multimodal key", got)
		}
		body, _ := io.ReadAll(r.Body)
		s := string(body)
		if !strings.Contains(s, "image_url") || !strings.Contains(s, "data:image/png;base64,") {
			t.Errorf("vision payload missing image_url/data URL: %s", s)
		}
		if !strings.Contains(s, "test-vision") {
			t.Errorf("vision payload missing multimodal model: %s", s)
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"a cat"}}]}`)
	})
	got, err := c.Vision(context.Background(), []byte("PNGDATA"), "image/png", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "a cat" {
		t.Errorf("vision = %q", got)
	}
}

func TestTranscribeUsesMultimodalRole(t *testing.T) {
	c := newDualClient(t, failHandler(t, "text"), func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/audio/transcriptions" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer mm-key" {
			t.Errorf("auth header = %q, want multimodal key", got)
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "multipart/form-data") {
			t.Errorf("content-type = %q", ct)
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Fatalf("parse multipart: %v", err)
		}
		if r.FormValue("model") != "test-vision" {
			t.Errorf("model field = %q, want configured multimodal model", r.FormValue("model"))
		}
		_, _ = io.WriteString(w, `{"text":"transcribed words"}`)
	})
	got, err := c.Transcribe(context.Background(), []byte("fakeaudio"), "voice.m4a")
	if err != nil {
		t.Fatal(err)
	}
	if got != "transcribed words" {
		t.Errorf("transcribe = %q", got)
	}
}

// TestMultimodalDisabled asserts that with no multimodal role configured (the
// opt-in default, ADR-0018) Vision/Transcribe fail cleanly and make no call.
func TestMultimodalDisabled(t *testing.T) {
	c := New(Options{
		TextBaseURL: "http://text.invalid/v1",
		TextModel:   "test-chat",
		EmbedModel:  "test-embed",
		// No multimodal base URL / model: role disabled.
	})
	if _, err := c.Vision(context.Background(), []byte("x"), "image/png", ""); !errors.Is(err, ErrMultimodalNotConfigured) {
		t.Errorf("Vision err = %v, want ErrMultimodalNotConfigured", err)
	}
	if _, err := c.Transcribe(context.Background(), []byte("x"), "a.m4a"); !errors.Is(err, ErrMultimodalNotConfigured) {
		t.Errorf("Transcribe err = %v, want ErrMultimodalNotConfigured", err)
	}
}

// TestMultimodalRequiresModel asserts the role stays disabled if a base URL is
// given without a model name (both are required to enable it).
func TestMultimodalRequiresModel(t *testing.T) {
	c := New(Options{
		TextBaseURL:       "http://text.invalid/v1",
		MultimodalBaseURL: "http://mm.invalid/v1",
		// MultimodalModel intentionally empty.
	})
	if _, err := c.Vision(context.Background(), []byte("x"), "image/png", ""); !errors.Is(err, ErrMultimodalNotConfigured) {
		t.Errorf("Vision err = %v, want ErrMultimodalNotConfigured", err)
	}
}

func TestErrorStatus(t *testing.T) {
	c := newDualClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":"rate limited"}`)
	}, failHandler(t, "multimodal"))
	_, err := c.Chat(context.Background(), ChatRequest{Messages: []Message{{Role: RoleUser, Content: "x"}}})
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Errorf("expected 429 error, got %v", err)
	}
}

// TestErrorNeverLeaksKey ensures a non-2xx error carries the path/status but
// never the API key (ADR-0018: keys are never logged).
func TestErrorNeverLeaksKey(t *testing.T) {
	c := newDualClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `nope`)
	}, failHandler(t, "multimodal"))
	_, err := c.Chat(context.Background(), ChatRequest{Messages: []Message{{Role: RoleUser, Content: "x"}}})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "text-key") {
		t.Errorf("error leaked API key: %v", err)
	}
}
