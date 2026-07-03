package proton

import (
	"context"
	"sort"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"
)

// metadataPager is the slice of go-proton-api the backfill enumeration needs.
// *gpa.Client satisfies it directly; tests supply a fake so collectBackfillIDs
// — the paging + time-window logic that is the wrapper's own — is exercised
// without a live account (mirroring events.go's eventFetcher).
type metadataPager interface {
	GetMessageMetadataPage(ctx context.Context, page, pageSize int, filter gpa.MessageFilter) ([]gpa.MessageMetadata, error)
}

// backfillPageSize is Proton's maximum message-metadata page size
// (go-proton-api's internal maxPageSize). Each request pulls at most this many
// rows, so a large mailbox is walked page-by-page and never loaded in one
// unbounded request (SPEC-0002 REQ "Rate-Limit Respect", "Bootstrap Then
// Tail" — the first sync backfills a BOUNDED window).
const backfillPageSize = 150

// collectBackfillIDs enumerates the Proton message ids whose message timestamp
// is at or after since, returned OLDEST-FIRST, by paging Proton's
// message-metadata endpoint.
//
// Why metadata paging (GetMessageMetadataPage) and not GetMessageIDs: the first
// sync's backfill is bounded to a time window (SPEC-0002 "First sync backfills a
// bounded window"), and applying that window needs each message's timestamp.
// GetMessageIDs returns bare ids with no time, which would force an N+1 metadata
// fetch per id to apply the window; the metadata page carries Time on the rows
// we already fetched. It also honors Proton's server-side paging (PageSize ≤
// backfillPageSize per request), so the scan never surges the API.
//
// Server-side time filtering is not available in this pin of go-proton-api:
// gpa.MessageFilter exposes only ID/Subject/AddressID/ExternalID/LabelID/EndID/
// Desc — no time lower-bound — so the window is applied client-side over the
// paged scan. The scan still walks the mailbox's metadata pages once; the window
// bounds which ids are RETAINED for backfill, not how many pages are requested.
//
// Ordering: results are sorted oldest-first by (Time, ID). Oldest-first is the
// friendliest order for a resumable backfill — an interrupted run has imported
// the oldest messages and the engine can resume forward without re-walking what
// it already applied. The ID tie-break makes the order deterministic when two
// messages share a timestamp.
func collectBackfillIDs(ctx context.Context, p metadataPager, since time.Time) ([]string, error) {
	sinceUnix := since.Unix()
	type row struct {
		id string
		ts int64
	}
	var kept []row
	for page := 0; ; page++ {
		// Honor cancellation between pages: a large mailbox walks many metadata
		// pages (the window is filtered client-side, see the doc above), so a
		// cancelled sync must stop promptly rather than only when the next
		// request happens to fail.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		metas, err := p.GetMessageMetadataPage(ctx, page, backfillPageSize, gpa.MessageFilter{})
		if err != nil {
			return nil, classifyError(err)
		}
		for _, m := range metas {
			if m.Time >= sinceUnix {
				kept = append(kept, row{id: m.ID, ts: m.Time})
			}
		}
		// A short (or empty) page is the last page under Proton's paging
		// contract, so we stop rather than issue a further empty request.
		if len(metas) < backfillPageSize {
			break
		}
	}
	sort.SliceStable(kept, func(i, j int) bool {
		if kept[i].ts != kept[j].ts {
			return kept[i].ts < kept[j].ts
		}
		return kept[i].id < kept[j].id
	})
	ids := make([]string, len(kept))
	for i := range kept {
		ids[i] = kept[i].id
	}
	return ids, nil
}
