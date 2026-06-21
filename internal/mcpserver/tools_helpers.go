// Shared projection + error-mapping helpers for the MCP tools.
package mcpserver

import (
	"errors"
	"net/mail"

	"github.com/joestump/reduit/internal/proton"
)

// addrString renders a single mail.Address as its bare address (e.g.
// "joe@example.com"), or "" when nil. The display name is dropped: the
// agent-facing surface keys on the address, and Proton's metadata
// already split name vs address.
func addrString(a *mail.Address) string {
	if a == nil {
		return ""
	}
	return a.Address
}

// addrStrings renders a list of addresses as bare-address strings,
// skipping nils. Returns nil (not an empty slice) when there are no
// addresses so the JSON omitempty fields stay absent.
func addrStrings(as []*mail.Address) []string {
	if len(as) == 0 {
		return nil
	}
	out := make([]string, 0, len(as))
	for _, a := range as {
		if a == nil {
			continue
		}
		out = append(out, a.Address)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// mapMessageLookupError maps a Proton GetMessage failure to a structured
// tool error. A 404 / unknown message ID collapses to the same
// `not_found` code a cross-account miss produces, per SPEC-0006 REQ
// "Account Scope on All Operations" (Scenario "Message lookup filters by
// account_id") -- the agent cannot distinguish "wrong account" from
// "genuinely missing".
func mapMessageLookupError(err error) *ToolError {
	var apiErr *proton.APIError
	if errors.As(err, &apiErr) && (apiErr.Status == 404 || apiErr.Status == 422) {
		return &ToolError{
			Code:      codeNotFound,
			Message:   "message not found",
			Retriable: false,
		}
	}
	return mapProtonError(err)
}
