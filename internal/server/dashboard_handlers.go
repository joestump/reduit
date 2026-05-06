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
	"strconv"
	"time"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/auth/session"
	"github.com/joestump/reduit/internal/users"
)

// accountsPageData composes the base pageData with dashboard-
// specific fields. The template branches on Empty vs Groups; admins
// also branch on IsAdmin to render the per-user grouping headers.
//
// Pagination fields (Page, HasPrev, HasNext, PrevURL, NextURL) are
// populated only on the admin view when total accounts exceed the
// page size; non-admin views (which list one user's accounts) and
// admin views with a single short page leave them zeroed and the
// template skips the prev/next strip.
type accountsPageData struct {
	pageData
	Empty    bool
	Subtitle string
	Groups   []accountGroup

	// Pagination controls -- admin view only, non-zero when there is
	// more than one page of accounts. PrevURL / NextURL are pre-built
	// query strings ("/accounts?page=N") so the template doesn't have
	// to do arithmetic; HasPrev/HasNext gate rendering.
	//
	// Governing: SPEC-0005 REQ "Account Dashboard"; PR #72 review (N3).
	Page    int
	HasPrev bool
	HasNext bool
	PrevURL string
	NextURL string
}

// adminPageSize is the number of account cards rendered per admin
// dashboard page. The "Page size 20, basic prev/next" shape per the
// PR-72 N3 follow-up; comfortable for a multi-card grid at 1080p
// without spilling far below the fold, and small enough that even a
// 1000-account fleet pages in well under 100ms of in-memory join.
//
// Tracked-separately: a streaming-render approach (per-user `<details>`
// groups) for fleets > 1000 accounts. Present scope is the
// pre-alpha-friendly version.
const adminPageSize = 20

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
			// Subtitle reflects the unpaginated total -- "N accounts
			// across M users" should not change as the operator pages,
			// otherwise the count is meaningless.
			fullSubtitle := adminSubtitle(groups)
			page := parsePage(r.URL.Query().Get("page"))
			pageGroups, pg := paginateAdminGroups(groups, page, adminPageSize)
			data.Groups = pageGroups
			data.Subtitle = fullSubtitle
			data.Page = pg.page
			data.HasPrev = pg.hasPrev
			data.HasNext = pg.hasNext
			if pg.hasPrev {
				data.PrevURL = fmt.Sprintf("/accounts?page=%d", pg.page-1)
			}
			if pg.hasNext {
				data.NextURL = fmt.Sprintf("/accounts?page=%d", pg.page+1)
			}
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
		LastSync:        formatLastSync(a.LastSyncAt),
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

// formatLastSync renders an account's LastSyncAt as a coarse "X min
// ago" string. Used by the cards' "Last sync" stat.
//
// nil (and the zero value, defensively) renders as "Never": the sync
// worker has not yet committed a cursor for this account, which is
// the expected state on a fresh row -- and on every row until the
// sync worker (#19) lands and starts populating last_sync_at via
// account.SetSyncState. Showing "Never" until then is the correct,
// honest display; the previous implementation read account.UpdatedAt
// as a stand-in and showed misleadingly recent timestamps for any
// row touched by a non-sync write (suspend, alias change, IMAP-password
// rotation, ...).
//
// Governing: SPEC-0005 REQ "Account Dashboard"
// ("Last sync" stat reflects last cursor advance, not last row mutation).
func formatLastSync(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "Never"
	}
	d := time.Since(*t)
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

// paginationState collects the after-slicing pagination metadata the
// handler needs to render prev/next controls.
type paginationState struct {
	page    int
	hasPrev bool
	hasNext bool
}

// parsePage normalises the ?page= query parameter to a 1-indexed page
// number. Empty / non-numeric / non-positive values fall back to page
// 1; the handler does NOT 400 on a bad page so a stale browser tab
// pointed at /accounts?page=foo still renders the first page rather
// than an error.
func parsePage(raw string) int {
	if raw == "" {
		return 1
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 1
	}
	return n
}

// paginateAdminGroups slices the flat admin grouping into a single
// page worth of accountCards, preserving the per-owner grouping
// shape so the template renders identical card-grid markup. Inputs
// (groups) are assumed already-sorted by owner label per
// adminAllAccountsGrouped's contract.
//
// Strategy: flatten the (owner, card) pairs into a global slice, take
// the page's window, and re-bucket. This keeps the wire-format
// invariant (groups stay sorted; cards within a group keep their
// relative order) without requiring a paginated repository API. When
// fleet sizes outgrow this approach the SQL-side ListPaged from issue
// #75's "Suggested fix" becomes the natural next step.
//
// Page numbers beyond the last populated page snap to the last page
// rather than 404 -- the alternative would let a stale browser tab
// dead-end on a refresh after another admin's account-create that
// shifted boundaries.
//
// Governing: SPEC-0005 REQ "Account Dashboard"; PR #72 review (N3).
func paginateAdminGroups(groups []accountGroup, page, pageSize int) ([]accountGroup, paginationState) {
	if pageSize <= 0 {
		// Defensive: a misconfigured pageSize would otherwise divide
		// by zero below. Treat as "show everything, no controls".
		return groups, paginationState{page: 1}
	}
	type ownerCard struct {
		owner string
		card  accountCard
	}
	flat := make([]ownerCard, 0)
	for _, g := range groups {
		for _, c := range g.Accounts {
			flat = append(flat, ownerCard{owner: g.Owner, card: c})
		}
	}
	total := len(flat)
	if total <= pageSize {
		// Single-page case: render unmodified, no prev/next chrome.
		return groups, paginationState{page: 1}
	}
	totalPages := (total + pageSize - 1) / pageSize
	if page > totalPages {
		page = totalPages
	}
	start := (page - 1) * pageSize
	end := start + pageSize
	if end > total {
		end = total
	}
	window := flat[start:end]

	// Re-bucket the window. We walk in order so the rebuilt groups
	// preserve the same owner-sort order as the input; an owner that
	// straddles a page boundary appears in both pages with only their
	// in-window accounts -- matches what the operator expects from a
	// "next page" button.
	out := make([]accountGroup, 0)
	var (
		curOwner string
		curIdx   = -1
	)
	for _, oc := range window {
		if curIdx < 0 || oc.owner != curOwner {
			out = append(out, accountGroup{Owner: oc.owner})
			curOwner = oc.owner
			curIdx = len(out) - 1
		}
		out[curIdx].Accounts = append(out[curIdx].Accounts, oc.card)
	}
	return out, paginationState{
		page:    page,
		hasPrev: page > 1,
		hasNext: page < totalPages,
	}
}
