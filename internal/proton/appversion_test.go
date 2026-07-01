package proton

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectAppVersion_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"branch":"proton-mail@5.0.121.4","version":"5.0.121.4"}`))
	}))
	defer srv.Close()

	got, err := detectAppVersion(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("detectAppVersion: unexpected error: %v", err)
	}
	if want := "web-mail@5.0.121.4"; got != want {
		t.Fatalf("detectAppVersion = %q, want %q", got, want)
	}
}

func TestDetectAppVersion_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	got, err := detectAppVersion(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("detectAppVersion: expected error on 500, got nil")
	}
	if got != FallbackAppVersion {
		t.Fatalf("detectAppVersion = %q, want fallback %q", got, FallbackAppVersion)
	}
}

func TestDetectAppVersion_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer srv.Close()

	got, err := detectAppVersion(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("detectAppVersion: expected error on malformed JSON, got nil")
	}
	if got != FallbackAppVersion {
		t.Fatalf("detectAppVersion = %q, want fallback %q", got, FallbackAppVersion)
	}
}

func TestDetectAppVersion_MissingVersionField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"branch":"proton-mail@5.0.121.4"}`))
	}))
	defer srv.Close()

	got, err := detectAppVersion(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("detectAppVersion: expected error on missing version field, got nil")
	}
	if got != FallbackAppVersion {
		t.Fatalf("detectAppVersion = %q, want fallback %q", got, FallbackAppVersion)
	}
}

func TestDetectAppVersion_Unreachable(t *testing.T) {
	// A cancelled context makes the request fail immediately, standing in for
	// an offline/timeout fetch without the wall-clock wait: the caller must
	// still get the fallback plus an error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":"5.0.121.4"}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := detectAppVersion(ctx, srv.URL)
	if err == nil {
		t.Fatal("detectAppVersion: expected error on cancelled context, got nil")
	}
	if got != FallbackAppVersion {
		t.Fatalf("detectAppVersion = %q, want fallback %q", got, FallbackAppVersion)
	}
}
