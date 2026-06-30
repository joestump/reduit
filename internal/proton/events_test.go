package proton

import (
	"context"
	"errors"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"
)

// stubFetcher is a scripted eventFetcher for exercising collectEvents without a
// live account.
type stubFetcher struct {
	events []gpa.Event
	more   bool
	err    error
	gotID  string // records the cursor it was asked for
}

func (s *stubFetcher) GetEvent(_ context.Context, eventID string) ([]gpa.Event, bool, error) {
	s.gotID = eventID
	return s.events, s.more, s.err
}

func TestCollectEvents_AdvancesCursor(t *testing.T) {
	f := &stubFetcher{
		events: []gpa.Event{
			{EventID: "e1", Messages: []gpa.MessageEvent{{EventItem: gpa.EventItem{ID: "m1", Action: gpa.EventCreate}}}},
			{EventID: "e2", Messages: []gpa.MessageEvent{{EventItem: gpa.EventItem{ID: "m2", Action: gpa.EventDelete}}}},
		},
		more: true,
	}
	batch, err := collectEvents(context.Background(), f, "e0")
	if err != nil {
		t.Fatal(err)
	}
	if f.gotID != "e0" {
		t.Errorf("fetched from cursor %q, want e0", f.gotID)
	}
	if batch.NextCursor != "e2" {
		t.Errorf("NextCursor = %q, want e2", batch.NextCursor)
	}
	if !batch.More {
		t.Error("More = false, want true")
	}
	if len(batch.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(batch.Events))
	}
	if batch.Events[0].Messages[0].Action != EventCreate || batch.Events[0].Messages[0].MessageID != "m1" {
		t.Errorf("event[0] message mismapped: %+v", batch.Events[0].Messages[0])
	}
	if batch.Events[1].Messages[0].Action != EventDelete {
		t.Errorf("event[1] action = %v, want delete", batch.Events[1].Messages[0].Action)
	}
}

// Cursor invariant (ADR-0014): an empty fetch must leave the caller pointed at
// the same cursor, never backward.
func TestCollectEvents_EmptyKeepsCursor(t *testing.T) {
	f := &stubFetcher{events: nil, more: false}
	batch, err := collectEvents(context.Background(), f, "e5")
	if err != nil {
		t.Fatal(err)
	}
	if batch.NextCursor != "e5" {
		t.Errorf("NextCursor = %q, want e5 (unchanged)", batch.NextCursor)
	}
	if len(batch.Events) != 0 {
		t.Errorf("got %d events, want 0", len(batch.Events))
	}
	if batch.More {
		t.Error("More = true, want false")
	}
}

func TestCollectEvents_RefreshFlag(t *testing.T) {
	f := &stubFetcher{events: []gpa.Event{{EventID: "e1", Refresh: gpa.RefreshAll}}}
	batch, err := collectEvents(context.Background(), f, "e0")
	if err != nil {
		t.Fatal(err)
	}
	if !batch.Events[0].Refresh {
		t.Error("Refresh flag not propagated to event")
	}
	if !batch.Refresh() {
		t.Error("EventBatch.Refresh() = false, want true")
	}
}

func TestCollectEvents_FlagsUpdateMapsToUpdate(t *testing.T) {
	f := &stubFetcher{events: []gpa.Event{
		{EventID: "e1", Messages: []gpa.MessageEvent{{EventItem: gpa.EventItem{ID: "m1", Action: gpa.EventUpdateFlags}}}},
	}}
	batch, err := collectEvents(context.Background(), f, "e0")
	if err != nil {
		t.Fatal(err)
	}
	if batch.Events[0].Messages[0].Action != EventUpdate {
		t.Errorf("UpdateFlags should collapse to EventUpdate, got %v", batch.Events[0].Messages[0].Action)
	}
}

func TestCollectEvents_ErrorIsClassified(t *testing.T) {
	f := &stubFetcher{err: &gpa.NetError{Cause: errors.New("eof"), Message: "down"}}
	_, err := collectEvents(context.Background(), f, "e0")
	if !errors.Is(err, ErrNetwork) {
		t.Fatalf("err = %v, want ErrNetwork", err)
	}
}
