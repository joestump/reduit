// Live-server integration test for the wired tool surface (issue #30).
//
// The existing tool tests prove two things in isolation: the white-box
// handler tests (tools_test.go) call the Go handlers directly with a
// fake client, and tools_registration_test.go drives a real MCP
// client/server pair over the SDK's *in-memory* transport. Neither
// exercises the production path issue #30 wires: a populated
// mcpserver.ToolDeps flowing through New() -> Handler() -> the full
// bearer-auth + concurrency middleware chain -> the SDK's streamable-HTTP
// transport, reached by a real MCP client over HTTP for an authenticated,
// active account.
//
// This test closes that gap. It is the "tools are reachable through the
// LIVE MCP server" assertion the composition-root wiring (serve.go flipping
// Tools: nil -> &ToolDeps{Clients: liveClients.Resolver()}) needs: tools/list
// returns the required set, and a tool (list_labels) actually dispatches end
// to end against the resolved per-account client.
//
// Governing: SPEC-0006 REQ "Required Tool Set" (Scenario "Tool listing
// reflects the required set"), REQ "Bearer Authentication Required"
// (Scenario "Per-account MCP token authenticates as the bound account"),
// REQ "Account Scope on All Operations"; ADR-0008.
package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/auth"
	"github.com/joestump/reduit/internal/auth/mcptoken"
	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/store"
	"github.com/joestump/reduit/internal/storetest"
)

// openLiveTempStore opens a migrated SQLite store in a temp dir. The
// black-box auth_test.go has its own openTempStore helper; this white-box
// test (which reuses fakeClient from tools_test.go) needs its own.
func openLiveTempStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir + "/reduit.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Migrate(""); err != nil {
		st.Close()
		t.Fatalf("Migrate: %v", err)
	}
	return st
}

// bearerRoundTripper injects a fixed Authorization header on every request
// the SDK's streamable-HTTP client issues, so the live server's bearer-auth
// middleware binds the request to the token's account.
type bearerRoundTripper struct {
	token string
	next  http.RoundTripper
}

func (b bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(req)
}

// TestLiveServer_ToolsReachable wires a populated ToolDeps (the issue #30
// shape: a real ClientResolver, Outbox nil) through New() and proves the
// surface is reachable over the live streamable-HTTP transport behind the
// bearer-auth chain. tools/list returns the required set, and list_labels
// dispatches end to end against the resolved per-account client.
func TestLiveServer_ToolsReachable(t *testing.T) {
	t.Parallel()

	st := openLiveTempStore(t)
	defer st.Close()

	const acctID = "acct-live-30"
	storetest.SeedUserAccountActive(t, st, acctID)

	masterKey, err := cryptenv.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	accountSvc := account.New(st, masterKey)
	tokens := mcptoken.NewRepository(st.DB)
	validator := auth.NewBearerValidator(nil, tokens)

	// The resolver returns a fake client for the active account, modelling
	// the protonlive.Resolver wired at the composition root. list_labels
	// dispatches against this client, proving the resolver -> client path is
	// live (not just that the tool is listed). An empty label set is a valid
	// successful response.
	fake := &fakeClient{labels: nil}
	resolver := ClientResolverFunc(func(_ context.Context, id string) (proton.Client, error) {
		if id != acctID {
			return nil, nil
		}
		return fake, nil
	})

	srv := New(Deps{
		Validator: validator,
		Accounts:  accountSvc,
		Limiter:   NoLimiter(),
		Tools: &ToolDeps{
			Clients: resolver,
			Outbox:  nil, // send_message stays registered, returns `unavailable` (issue #30 deferred outbox).
		},
	})

	mux := http.NewServeMux()
	mux.Handle("/mcp", srv.Handler())
	httpSrv := httptest.NewServer(mux)
	defer httpSrv.Close()

	tok, err := tokens.Issue(context.Background(), mcptoken.IssueParams{AccountID: acctID})
	if err != nil {
		t.Fatalf("Issue token: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	httpClient := &http.Client{Transport: bearerRoundTripper{token: tok.Plaintext, next: http.DefaultTransport}}
	client := mcp.NewClient(&mcp.Implementation{Name: "live-test-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   httpSrv.URL + "/mcp",
		HTTPClient: httpClient,
	}, nil)
	if err != nil {
		t.Fatalf("client connect through live server: %v", err)
	}
	defer cs.Close()

	// tools/list is non-empty and carries the required set over the LIVE
	// transport (the empty-tools/list scaffolding shipped Tools: nil).
	res, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("tools/list over live server: %v", err)
	}
	got := make(map[string]struct{}, len(res.Tools))
	for _, tool := range res.Tools {
		got[tool.Name] = struct{}{}
	}
	if len(got) == 0 {
		t.Fatal("tools/list returned an empty set; ToolDeps did not wire the surface")
	}
	for _, name := range []string{
		"list_messages", "get_message", "search_messages", "send_message",
		"list_labels", "add_label", "remove_label", "move_to_folder",
		"mark_read", "mark_unread",
	} {
		if _, ok := got[name]; !ok {
			t.Errorf("tools/list missing required tool %q", name)
		}
	}

	// A read tool dispatches end to end: the bearer binds the account, the
	// resolver hands back the fake client, and list_labels returns a clean
	// (error-free) result. This is the assertion that the wired ClientResolver
	// is actually reached, not merely advertised.
	out, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_labels"})
	if err != nil {
		t.Fatalf("call list_labels over live server: %v", err)
	}
	if out.IsError {
		t.Fatalf("list_labels returned a protocol error: %+v", out.Content)
	}
	sc, ok := out.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("list_labels structured content has unexpected type %T", out.StructuredContent)
	}
	if errVal, present := sc["error"]; present && errVal != nil {
		t.Fatalf("list_labels surfaced a tool error for an active account: %v", errVal)
	}
}
