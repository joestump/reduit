// /accounts dashboard handler.
//
// Renders the per-user account list (or empty state when the user
// owns zero accounts). Admins see every user's accounts grouped by
// owner. The /accounts/setup wizard target is referenced from the
// "Add account" CTA; the wizard handler itself lives in #24.
//
// Governing: ADR-0010 (multi-Proton-account per user), SPEC-0005 REQ
// "Account Dashboard".

package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/auth/session"
	"github.com/joestump/reduit/internal/users"
)

// accountsPageData composes the base pageData with dashboard-
// specific fields. The template branches on Empty vs Groups; admins
// also branch on IsAdmin to render the per-user grouping headers.
type accountsPageData struct {
	pageData
	Empty    bool
	Subtitle string
	Groups   []accountGroup
}

// accountGroup is a single owner-grouped slice of cards. For
// non-admin views there is exactly one group (the user's own); the
// Owner field is unused in that case.
type accountGroup struct {
	Owner    string
	Accounts []accountCard
}

// accountCard is the per-account view-model the template consumes.
// The conversion lives in the handler so templates stay logic-light.
type accountCard struct {
	ID              string
	Label           string // human-readable: email, falling back to "Account {id}"
	Email           string
	Initials        string
	State           string
	StateLabel      string // user-facing label ("Pending", "Active", ...)
	StateBadgeClass string // DaisyUI badge color class
	LastSync        string // formatted "X min ago" or "Never"
}

// handleAccountsDashboard renders /accounts.
//
// The session is guaranteed authenticated by the time we get here
// (the RequireSession middleware has gated us). For non-admin
// sessions we list accounts owned by the bound user; for admin
// sessions we list every account, grouped by owning user. The
// admin's own accounts appear in their own group like any other
// user's per the spec.
func (s *Server) handleAccountsDashboard(w http.ResponseWriter, r *http.Request) {
	if s.deps.SessionManager == nil || s.deps.AccountService == nil {
		http.Error(w, "dashboard not configured", http.StatusInternalServerError)
		return
	}

	id := session.GetIdentity(r.Context(), s.deps.SessionManager)
	if id.UserID == "" {
		// Belt-and-suspenders: RequireSession should have caught this,
		// but if a future caller wires a custom gate that lets a
		// Subject-only session through, fail closed rather than
		// silently render nothing.
		s.deps.Logger.Warn("dashboard: authenticated session has empty UserID",
			slog.String("subject", id.Subject))
		http.Error(w, "session missing user binding", http.StatusInternalServerError)
		return
	}

	data := accountsPageData{
		pageData: pageData{
			Title:    "Account Dashboard",
			Identity: newIdentityView(id),
			IsAdmin:  id.IsAdmin,
		},
	}

	if id.IsAdmin {
		groups, err := s.adminAllAccountsGrouped(r)
		if err != nil {
			s.deps.Logger.Error("dashboard: admin listing: " + err.Error())
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if len(groups) == 0 || allEmpty(groups) {
			data.Empty = true
		} else {
			data.Groups = groups
			data.Subtitle = adminSubtitle(groups)
		}
	} else {
		accounts, err := s.deps.AccountService.ListByUser(r.Context(), id.UserID)
		if err != nil {
			s.deps.Logger.Error("dashboard: user listing: " + err.Error())
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if len(accounts) == 0 {
			data.Empty = true
		} else {
			data.Groups = []accountGroup{{Accounts: toCards(accounts)}}
			data.Subtitle = userSubtitle(accounts)
		}
	}

	s.renderPage(w, r, "accounts", data)
}

// adminAllAccountsGrouped returns every account in the system,
// grouped by owning user. Display order is by user email, falling
// back to display name, then OIDC subject (per the spec).
func (s *Server) adminAllAccountsGrouped(r *http.Request) ([]accountGroup, error) {
	if s.deps.UsersService == nil {
		return nil, fmt.Errorf("admin dashboard: users service not wired")
	}
	allAccounts, err := s.deps.AccountService.List(r.Context())
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	if len(allAccounts) == 0 {
		return nil, nil
	}
	allUsers, err := s.deps.UsersService.List(r.Context())
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}

	byID := make(map[string]*users.User, len(allUsers))
	for _, u := range allUsers {
		byID[u.ID] = u
	}

	bucket := make(map[string][]accountCard)
	for _, a := range allAccounts {
		bucket[a.UserID] = append(bucket[a.UserID], toCard(a))
	}

	out := make([]accountGroup, 0, len(bucket))
	for userID, cards := range bucket {
		u := byID[userID]
		out = append(out, accountGroup{
			Owner:    ownerLabel(u, userID),
			Accounts: cards,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Owner < out[j].Owner })
	return out, nil
}

func ownerLabel(u *users.User, fallbackID string) string {
	if u == nil {
		return "User " + fallbackID
	}
	if u.Email != "" {
		return u.Email
	}
	if u.DisplayName != "" {
		return u.DisplayName
	}
	if u.OIDCSubject != "" {
		return u.OIDCSubject
	}
	return "User " + u.ID
}

func toCards(accounts []*account.Account) []accountCard {
	out := make([]accountCard, len(accounts))
	for i, a := range accounts {
		out[i] = toCard(a)
	}
	return out
}

func toCard(a *account.Account) accountCard {
	label := a.Email
	if label == "" {
		label = "Account " + a.ID[:min(8, len(a.ID))]
	}
	stateLabel, badge := stateBadge(a.State)
	return accountCard{
		ID:              a.ID,
		Label:           label,
		Email:           a.Email,
		Initials:        initialsFor(label),
		State:           string(a.State),
		StateLabel:      stateLabel,
		StateBadgeClass: badge,
		LastSync:        formatLastSync(a.UpdatedAt),
	}
}

func stateBadge(s account.State) (label, class string) {
	switch s {
	case account.StateActive:
		return "Up to date", "badge-success"
	case account.StatePendingProtonSetup:
		return "Pending setup", "badge-warning"
	case account.StateSuspended:
		return "Suspended", "badge-error"
	case account.StateSoftDeleted:
		return "Removed", "badge-ghost"
	default:
		return string(s), "badge-ghost"
	}
}

// formatLastSync renders an account's UpdatedAt as a coarse "X min
// ago" string. Used by the cards' "Last sync" stat. We use UpdatedAt
// rather than a dedicated last_sync_at column because the existing
// schema mutates updated_at on every sync-state advance (per
// internal/account.SetSyncState). When a per-account last_sync_at
// column lands, swap this over.
func formatLastSync(t time.Time) string {
	if t.IsZero() {
		return "Never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hr ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

func userSubtitle(accounts []*account.Account) string {
	n := len(accounts)
	switch n {
	case 1:
		return "1 account"
	default:
		return fmt.Sprintf("%d accounts", n)
	}
}

func adminSubtitle(groups []accountGroup) string {
	users := len(groups)
	total := 0
	for _, g := range groups {
		total += len(g.Accounts)
	}
	return fmt.Sprintf("%d account%s across %d user%s",
		total, pluralize(total),
		users, pluralize(users))
}

func pluralize(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func allEmpty(groups []accountGroup) bool {
	for _, g := range groups {
		if len(g.Accounts) > 0 {
			return false
		}
	}
	return true
}
