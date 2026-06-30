// Package mcp implements Reduit's Model Context Protocol server: the PRIMARY
// surface through which Claude and other agents search, read, and act on the
// user's locally-cached Proton mail (ADR-0017).
//
// Transport is stdio JSON-RPC over the official
// github.com/modelcontextprotocol/go-sdk: the process is spawned by the user's
// own MCP client as `reduit mcp`. There is NO network listener, NO OIDC, NO
// account record, and NO auth handshake — the server runs with the authority
// of the single local OS user (ADR-0012). All diagnostics go to stderr (via
// the injected slog.Logger) so stdout carries exclusively the JSON-RPC stream.
//
// Every tool is a thin adapter over internal/store — the same methods the
// loopback UI uses (ADR-0005) — so behaviour cannot drift between surfaces.
// This package owns no query path of its own.
//
// Governing: ADR-0017 (stdio MCP + hybrid RAG), ADR-0012 (single-user
//
//	local-first), ADR-0005 (loopback UI / shared store),
//	SPEC-0006 (MCP Tool Surface).
package mcp

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/joestump/reduit/internal/store"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Server wires the Reduit store into an MCP tool surface.
//
// It holds the underlying SDK server (srv) plus the store every tool reads
// from. The struct is deliberately small: this story (S7.1) ships the server
// bootstrap and the read-only `status`/`list_mailboxes` tools; the hybrid
// search, message-retrieval, attachment, contact-fact, and `send` tools land
// in later stories (#100/#101) and will hang additional dependencies (the LLM
// client for query embedding) off this struct.
type Server struct {
	store *store.Store
	log   *slog.Logger
	srv   *mcpsdk.Server
}

// Options configures the MCP server.
type Options struct {
	// Version is reported to the client in the MCP initialize handshake.
	Version string
	// Logger receives all diagnostics. It MUST write to stderr (never stdout):
	// stdout is reserved for the JSON-RPC protocol stream (SPEC-0006 REQ
	// "Stdio Transport, No Auth"). A nil Logger is replaced with a no-op
	// handler so a misconfigured caller can never corrupt stdout.
	Logger *slog.Logger
}

// NewServer builds the MCP server and registers every tool.
//
// Governing: SPEC-0006 REQ "Thin Adapter Over the Store" (tools read only via
//
//	st), SPEC-0006 REQ "Stdio Transport, No Auth" (no listener constructed).
func NewServer(st *store.Store, opts Options) *Server {
	log := opts.Logger
	if log == nil {
		// Never fall back to slog.Default() here: its handler may write to
		// stdout and corrupt the JSON-RPC stream. Discard instead.
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	version := opts.Version
	if version == "" {
		version = "dev"
	}
	s := &Server{store: st, log: log}
	s.srv = mcpsdk.NewServer(&mcpsdk.Implementation{Name: "reduit", Version: version}, nil)
	s.registerTools()
	return s
}

// RunStdio serves the MCP protocol over stdio until ctx is cancelled. stdin
// and stdout carry the JSON-RPC stream; all logging is on stderr.
//
// A SIGINT/SIGTERM-driven shutdown cancels ctx, which surfaces as
// context.Canceled from Run; that is a clean stop, so RunStdio swallows it and
// returns nil. The process then exits 0 instead of printing a spurious
// "context canceled" error.
//
// Governing: SPEC-0006 REQ "Stdio Transport, No Auth".
func (s *Server) RunStdio(ctx context.Context) error {
	err := s.srv.Run(ctx, &mcpsdk.StdioTransport{})
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return nil
	}
	return err
}
