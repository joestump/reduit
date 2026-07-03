// Package syncengine — mapping a decrypted Proton message into store writes.
//
// This file is the pure, network-free half of the engine: it turns one
// proton.DecryptedMessage into the single atomic store.MessageWrite the engine
// commits (the message row plus its contacts, links, and attachments). Keeping
// it side-effect-free makes the folder resolution, body rendering, and link
// extraction directly unit-testable without a Proton client or a store.
//
// Governing: SPEC-0002 (Contact Materialization, Link Extraction, Decrypt In
// The Pipeline), ADR-0014 (stable-hash keying).
package syncengine

import (
	"html"
	"regexp"
	"strings"

	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/store"
)

// urlRE matches bare http(s) URLs in a message body. It is deliberately
// permissive on the scheme and host and stops at whitespace or the handful of
// delimiters that never belong inside a URL, so it works on both plaintext
// bodies and the raw HTML source (where links live in href="…" attributes and
// as visible text). Trailing sentence punctuation is trimmed afterward.
var urlRE = regexp.MustCompile(`https?://[^\s"'<>()\[\]{}]+`)

// tagRE strips HTML tags when rendering an HTML body down to plaintext.
var tagRE = regexp.MustCompile(`(?s)<[^>]*>`)

// wsRE collapses runs of whitespace introduced by tag stripping.
var wsRE = regexp.MustCompile(`[ \t\f\v]*\n\s*`)

// mapMessage turns a decrypted Proton message into the atomic store write the
// engine applies under one message identity (SPEC-0002). folders resolves a
// message's Proton label ids to a human folder name; it is built once per run
// from the mailbox's label list (see folderResolver).
//
// Mapping decisions:
//   - Sender/recipients (From, To, CC, BCC) all become ContactInputs so the
//     contact layer materializes for every correspondent the pipeline sees
//     (SPEC-0002 "Contact Materialization"). The From address additionally
//     lands in the message row's sender column.
//   - Body is rendered to plaintext (HTML → text) for the cache and FTS; link
//     extraction runs over the RAW body so href targets in HTML mail are not
//     lost when tags are stripped (SPEC-0002 "Link Extraction").
//   - Attachment METADATA only (name/mime/size); payloads and extracted text
//     are the downstream extract pass's concern (ADR-0016).
func mapMessage(mailboxID string, m proton.DecryptedMessage, folders folderResolver) store.MessageWrite {
	body := string(m.Body)
	plain := renderPlaintext(body, m.MIMEType)

	w := store.MessageWrite{
		Message: store.MessageRow{
			MailboxID: mailboxID,
			ProtonID:  m.MessageID,
			Timestamp: m.Date,
			Sender:    formatAddress(m.Sender),
			Subject:   m.Subject,
			Body:      plain,
			Folder:    folders.resolve(m.LabelIDs),
		},
		Contacts:    contactsOf(m),
		Links:       extractLinks(body),
		Attachments: attachmentsOf(m.Attachments),
	}
	return w
}

// contactsOf collects every distinct correspondent address on the message —
// sender plus all To/CC/BCC recipients — as contact inputs. Deduplication and
// the "known address reuses its contact" guarantee are the store's job
// (upsertContactIdentifier); here we simply surface everyone the message names.
func contactsOf(m proton.DecryptedMessage) []store.ContactInput {
	var out []store.ContactInput
	add := func(a proton.Address) {
		if strings.TrimSpace(a.Email) == "" {
			return
		}
		out = append(out, store.ContactInput{Address: a.Email, DisplayName: a.Name})
	}
	add(m.Sender)
	for _, a := range m.To {
		add(a)
	}
	for _, a := range m.CC {
		add(a)
	}
	for _, a := range m.BCC {
		add(a)
	}
	return out
}

// attachmentsOf maps Proton attachment metadata into store inputs. No payloads
// are fetched or decrypted here (ADR-0016).
func attachmentsOf(atts []proton.AttachmentMeta) []store.AttachmentInput {
	if len(atts) == 0 {
		return nil
	}
	out := make([]store.AttachmentInput, 0, len(atts))
	for _, a := range atts {
		out = append(out, store.AttachmentInput{
			ProtonAttID: a.ID,
			Filename:    a.Name,
			MIME:        a.MIMEType,
			SizeBytes:   a.Size,
		})
	}
	return out
}

// extractLinks parses every http(s) URL out of a message body into link inputs,
// deduplicating within the message so a URL repeated in the body yields one
// input (the store also upserts by (message_hash, url), so re-sync converges).
// Anchor text is left empty: it is optional in the store and reliably parsing it
// out of arbitrary HTML is not worth the fragility here (SPEC-0002 "Link
// Extraction"). A body with no URLs yields no inputs.
func extractLinks(body string) []store.LinkInput {
	matches := urlRE.FindAllString(body, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	var out []store.LinkInput
	for _, raw := range matches {
		u := html.UnescapeString(strings.TrimRight(raw, ".,;:!?)\"'"))
		if u == "" {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, store.LinkInput{URL: u})
	}
	return out
}

// renderPlaintext returns a plaintext rendering of a decrypted body suitable for
// the cache and FTS. An HTML body has its tags stripped and entities unescaped;
// a plaintext body is returned trimmed. This is deliberately simple (SPEC-0002
// notes MIME/HTML → text may be kept simple); a richer HTML-to-text pass can
// replace it without changing the stable hash (body is a mutable column).
func renderPlaintext(body, mimeType string) string {
	if strings.Contains(strings.ToLower(mimeType), "html") {
		stripped := tagRE.ReplaceAllString(body, " ")
		stripped = html.UnescapeString(stripped)
		stripped = wsRE.ReplaceAllString(stripped, "\n")
		return strings.TrimSpace(collapseSpaces(stripped))
	}
	return strings.TrimSpace(body)
}

// collapseSpaces squeezes runs of spaces/tabs down to single spaces without
// touching newlines, so tag-stripped HTML does not carry long whitespace gaps.
func collapseSpaces(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if prevSpace {
				continue
			}
			prevSpace = true
			b.WriteByte(' ')
			continue
		}
		prevSpace = false
		b.WriteRune(r)
	}
	return b.String()
}

// formatAddress renders a correspondent as the string stored in messages.sender.
// It prefers "Name <email>" when a display name is present, falling back to the
// bare email; an entirely empty address renders empty.
func formatAddress(a proton.Address) string {
	name := strings.TrimSpace(a.Name)
	email := strings.TrimSpace(a.Email)
	switch {
	case name != "" && email != "":
		return name + " <" + email + ">"
	case email != "":
		return email
	default:
		return name
	}
}

// folderResolver maps a message's Proton label ids to a single folder name for
// the cache. It is built once per run from the mailbox's label list so each
// message map is a cheap lookup rather than a per-message API call.
type folderResolver struct {
	// byID maps a label id to its resolved reduit Label. Only folder and system
	// labels are candidates for the folder column; user labels are not folders.
	byID map[string]proton.Label
}

// newFolderResolver indexes a mailbox's labels for folder resolution.
func newFolderResolver(labels []proton.Label) folderResolver {
	byID := make(map[string]proton.Label, len(labels))
	for _, l := range labels {
		byID[l.ID] = l
	}
	return folderResolver{byID: byID}
}

// resolve picks a folder name for a message from its label ids. A message can
// carry several labels (system mailboxes, user folders, user labels); the
// folder column wants the containing folder, so system mailboxes (Inbox, Sent,
// Archive, …) and user folders win over user labels. The first matching folder-
// class label in id order is used; when none matches (or labels are unknown),
// the folder is left empty rather than guessed.
func (r folderResolver) resolve(labelIDs []string) string {
	for _, id := range labelIDs {
		if l, ok := r.byID[id]; ok && (l.Type == proton.LabelTypeSystem || l.Type == proton.LabelTypeFolder) {
			return l.Name
		}
	}
	return ""
}
