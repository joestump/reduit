package proton

import (
	"context"
	"errors"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"
)

func TestLabelTypeString(t *testing.T) {
	cases := map[gpa.LabelType]string{
		gpa.LabelTypeLabel:        LabelTypeLabel,
		gpa.LabelTypeFolder:       LabelTypeFolder,
		gpa.LabelTypeSystem:       LabelTypeSystem,
		gpa.LabelTypeContactGroup: LabelTypeUnknown, // not surfaced by reduit
		gpa.LabelType(999):        LabelTypeUnknown,
	}
	for in, want := range cases {
		if got := labelTypeString(in); got != want {
			t.Errorf("labelTypeString(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestPrimaryKeyID(t *testing.T) {
	// A key set with a primary key returns its id.
	keys := gpa.Keys{
		{ID: "k1", Primary: gpa.Bool(false)},
		{ID: "k2", Primary: gpa.Bool(true)},
	}
	id, err := primaryKeyID(keys)
	if err != nil {
		t.Fatalf("primaryKeyID: %v", err)
	}
	if id != "k2" {
		t.Errorf("primary id = %q, want k2", id)
	}

	// No primary flag → typed error, NOT a panic (#123).
	none := gpa.Keys{{ID: "k1", Primary: gpa.Bool(false)}}
	if _, err := primaryKeyID(none); !errors.Is(err, ErrNoPrimaryKey) {
		t.Errorf("expected ErrNoPrimaryKey, got %v", err)
	}

	// Empty key set → same typed error.
	if _, err := primaryKeyID(gpa.Keys{}); !errors.Is(err, ErrNoPrimaryKey) {
		t.Errorf("empty keys: expected ErrNoPrimaryKey, got %v", err)
	}
}

func TestGPAClientLabelsGuard(t *testing.T) {
	c := &gpaClient{} // cli nil → not authenticated
	if _, err := c.Labels(context.Background()); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("Labels before auth: %v", err)
	}
}

func TestFakeLabels(t *testing.T) {
	ctx := context.Background()
	f := NewFake()

	// Before Login the Fake reports not-authenticated.
	if _, err := f.Labels(ctx); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("Labels before login: %v", err)
	}

	f.LabelList = []Label{
		{ID: "0", Name: "Inbox", Type: LabelTypeSystem},
		{ID: "ab12", Name: "Receipts", Type: LabelTypeLabel, Color: "#c44800"},
	}
	if _, err := f.Login(ctx, "a@b.test", []byte("pw")); err != nil {
		t.Fatalf("Login: %v", err)
	}
	got, err := f.Labels(ctx)
	if err != nil {
		t.Fatalf("Labels: %v", err)
	}
	if len(got) != 2 || got[1].Name != "Receipts" {
		t.Errorf("unexpected labels: %+v", got)
	}

	f.LabelsErr = errors.New("boom")
	if _, err := f.Labels(ctx); err == nil {
		t.Error("expected scripted LabelsErr")
	}
}
