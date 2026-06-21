// Transport-level registration test: drives a real MCP client/server
// pair over the SDK's in-memory transport and asserts tools/list returns
// every tool SPEC-0006 REQ "Required Tool Set" mandates, each with a
// non-empty input schema. This is the authoritative "required set is
// present and listable" assertion the white-box tests defer to.
//
// Governing: SPEC-0006 REQ "Required Tool Set" (Scenario "Tool listing
// reflects the required set").
package mcpserver

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/joestump/reduit/internal/proton"
)

func TestToolsList_ReflectsRequiredSet(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "reduit", Version: Version}, nil)
	registerTools(srv, ToolDeps{
		Clients: ClientResolverFunc(func(context.Context, string) (proton.Client, error) {
			return &fakeClient{}, nil
		}),
		Outbox: &fakeOutbox{},
	})

	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	res, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}

	got := make(map[string]*mcp.Tool, len(res.Tools))
	for _, tool := range res.Tools {
		got[tool.Name] = tool
	}

	// The exact tool names from SPEC-0006 REQ "Required Tool Set". The
	// write/send tools accept the parameter shapes the spec enumerates;
	// the listing assertion pins the names so a rename surfaces as a
	// documented breaking change (Scenario "Each tool has a stable name
	// and schema").
	required := []string{
		"list_messages",
		"get_message",
		"search_messages",
		"send_message",
		"list_labels",
		"add_label",
		"remove_label",
		"move_to_folder",
		"mark_read",
		"mark_unread",
		// download_attachment landed with streaming (issue #19); it is
		// part of the SPEC-0006 required set.
		"download_attachment",
	}
	for _, name := range required {
		tool, ok := got[name]
		if !ok {
			t.Errorf("tools/list missing required tool %q", name)
			continue
		}
		if tool.Description == "" {
			t.Errorf("tool %q has empty description", name)
		}
		if tool.InputSchema == nil {
			t.Errorf("tool %q has nil input schema", name)
		}
	}
}
