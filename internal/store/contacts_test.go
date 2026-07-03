package store

import (
	"context"
	"testing"
)

// TestContactMaterialization: a new address creates one contact + identifier; a
// known address reuses it without creating a second contact (SPEC-0002
// "Contact Materialization").
func TestContactMaterialization(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()

	// New address → one contact, one identifier.
	id1, err := st.UpsertContactIdentifier(ctx, "alice@example.com", "Alice")
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if id1 == "" {
		t.Fatal("empty contact id for new address")
	}
	if got := countRows(t, st, "contacts"); got != 1 {
		t.Errorf("contacts=%d, want 1", got)
	}
	if got := countRows(t, st, "contact_identifiers"); got != 1 {
		t.Errorf("identifiers=%d, want 1", got)
	}

	// Same address again → reuse, no new rows. Case/space-insensitive.
	id2, err := st.UpsertContactIdentifier(ctx, "  Alice@Example.com ", "")
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if id2 != id1 {
		t.Errorf("known address minted a new contact: %q != %q", id2, id1)
	}
	if got := countRows(t, st, "contacts"); got != 1 {
		t.Errorf("contacts grew: %d, want 1", got)
	}
	if got := countRows(t, st, "contact_identifiers"); got != 1 {
		t.Errorf("identifiers grew: %d, want 1", got)
	}

	// A different address → a distinct contact.
	id3, err := st.UpsertContactIdentifier(ctx, "bob@example.com", "Bob")
	if err != nil {
		t.Fatalf("third upsert: %v", err)
	}
	if id3 == id1 {
		t.Error("distinct address shared a contact")
	}
	if got := countRows(t, st, "contacts"); got != 2 {
		t.Errorf("contacts=%d, want 2", got)
	}
}

// TestContactNameBackfill: a name is backfilled only when the contact's
// display_name was empty; an existing name is never overwritten.
func TestContactNameBackfill(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()

	// First seen with no name.
	id, err := st.UpsertContactIdentifier(ctx, "carol@example.com", "")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// Later seen with a name → backfilled.
	if _, err := st.UpsertContactIdentifier(ctx, "carol@example.com", "Carol"); err != nil {
		t.Fatalf("backfill upsert: %v", err)
	}
	var name string
	if err := st.DB.GetContext(ctx, &name, `SELECT display_name FROM contacts WHERE id = ?`, id); err != nil {
		t.Fatalf("read name: %v", err)
	}
	if name != "Carol" {
		t.Errorf("name not backfilled: %q", name)
	}
	// Seen again with a different name → NOT overwritten.
	if _, err := st.UpsertContactIdentifier(ctx, "carol@example.com", "Caroline"); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	if err := st.DB.GetContext(ctx, &name, `SELECT display_name FROM contacts WHERE id = ?`, id); err != nil {
		t.Fatalf("read name 2: %v", err)
	}
	if name != "Carol" {
		t.Errorf("existing name overwritten: %q", name)
	}
}

// TestContactEmptyAddressNoOp: an empty/whitespace address writes nothing and
// does not error (headers may carry a name with no parseable address).
func TestContactEmptyAddressNoOp(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	ctx := context.Background()

	id, err := st.UpsertContactIdentifier(ctx, "   ", "No Address")
	if err != nil {
		t.Fatalf("empty address errored: %v", err)
	}
	if id != "" {
		t.Errorf("empty address returned id %q", id)
	}
	if got := countRows(t, st, "contacts"); got != 0 {
		t.Errorf("contacts created for empty address: %d", got)
	}
}
