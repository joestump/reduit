package proton

import (
	"context"
	"errors"
	"testing"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"
)

// fakeMetadataPager scripts metadata pages for collectBackfillIDs, recording the
// page indices requested so the paging loop can be asserted.
type fakeMetadataPager struct {
	pages       [][]gpa.MessageMetadata
	err         error
	pagesAsked  []int
	pageSizeGot int
}

func (f *fakeMetadataPager) GetMessageMetadataPage(_ context.Context, page, pageSize int, _ gpa.MessageFilter) ([]gpa.MessageMetadata, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.pagesAsked = append(f.pagesAsked, page)
	f.pageSizeGot = pageSize
	if page < 0 || page >= len(f.pages) {
		return nil, nil
	}
	return f.pages[page], nil
}

func meta(id string, ts int64) gpa.MessageMetadata {
	return gpa.MessageMetadata{ID: id, Time: ts}
}

// TestCollectBackfillFiltersAndOrders: ids at or after `since` are kept and
// returned oldest-first by time; older ones are dropped.
func TestCollectBackfillFiltersAndOrders(t *testing.T) {
	t.Parallel()
	// One short page (< backfillPageSize) so the loop stops after it.
	pager := &fakeMetadataPager{pages: [][]gpa.MessageMetadata{{
		meta("new", 300),
		meta("old", 100), // before since → dropped
		meta("mid", 200),
		meta("boundary", 150), // exactly since → kept
	}}}
	since := time.Unix(150, 0)

	ids, err := collectBackfillIDs(context.Background(), pager, since)
	if err != nil {
		t.Fatalf("collectBackfillIDs: %v", err)
	}
	want := []string{"boundary", "mid", "new"} // oldest-first: 150,200,300
	if len(ids) != len(want) {
		t.Fatalf("ids=%v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("ids=%v, want %v", ids, want)
		}
	}
}

// TestCollectBackfillPaginates: a full page is followed by another request; the
// short final page ends the loop. Ids across pages are merged and ordered.
func TestCollectBackfillPaginates(t *testing.T) {
	t.Parallel()
	full := make([]gpa.MessageMetadata, backfillPageSize)
	for i := range full {
		// Times 1000+ so all are kept; ids that sort deterministically.
		full[i] = meta("p0-"+string(rune('a'+i%26))+itoa(i), int64(1000+i))
	}
	second := []gpa.MessageMetadata{meta("p1-x", 5000)}
	pager := &fakeMetadataPager{pages: [][]gpa.MessageMetadata{full, second}}

	ids, err := collectBackfillIDs(context.Background(), pager, time.Unix(0, 0))
	if err != nil {
		t.Fatalf("collectBackfillIDs: %v", err)
	}
	if len(ids) != backfillPageSize+1 {
		t.Fatalf("got %d ids, want %d", len(ids), backfillPageSize+1)
	}
	// Two pages requested (0 then 1); the short second page stops the loop.
	if len(pager.pagesAsked) != 2 || pager.pagesAsked[0] != 0 || pager.pagesAsked[1] != 1 {
		t.Errorf("pages asked = %v, want [0 1]", pager.pagesAsked)
	}
	if pager.pageSizeGot != backfillPageSize {
		t.Errorf("pageSize = %d, want %d", pager.pageSizeGot, backfillPageSize)
	}
	// Highest time sorts last (oldest-first).
	if ids[len(ids)-1] != "p1-x" {
		t.Errorf("last id = %q, want p1-x (newest, oldest-first ordering)", ids[len(ids)-1])
	}
}

// TestCollectBackfillPropagatesError: an API error surfaces (classified).
func TestCollectBackfillPropagatesError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("boom")
	pager := &fakeMetadataPager{err: sentinel}
	if _, err := collectBackfillIDs(context.Background(), pager, time.Unix(0, 0)); err == nil {
		t.Fatal("want error, got nil")
	}
}

// TestFakeBackfillMessageIDs: the Fake returns its scripted list once
// authenticated and rejects an unauthenticated call, matching GetEvents.
func TestFakeBackfillMessageIDs(t *testing.T) {
	t.Parallel()
	f := NewFake()
	f.BackfillIDs = []string{"a", "b", "c"}

	if _, err := f.BackfillMessageIDs(context.Background(), time.Unix(0, 0)); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("unauthenticated: err=%v, want ErrNotAuthenticated", err)
	}
	if _, err := f.Login(context.Background(), "a@example.com", []byte("pw")); err != nil {
		t.Fatalf("login: %v", err)
	}
	ids, err := f.BackfillMessageIDs(context.Background(), time.Unix(0, 0))
	if err != nil {
		t.Fatalf("BackfillMessageIDs: %v", err)
	}
	if len(ids) != 3 || ids[0] != "a" || ids[2] != "c" {
		t.Errorf("ids=%v, want [a b c]", ids)
	}
}

// itoa is a tiny local int->string to keep the test dependency-free.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
