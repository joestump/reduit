// Test seams for the users package. Lives in `users` (not
// `users_test`) so external_test files can reach unexported
// constructors without widening the production API.
//
// Governing: this file exists purely to expose `newWithClock` for
// deterministic timestamp assertions in TestUpsertAdvancesLastLoginAt
// (issue #66). Production callers stick to users.New; the only
// thing this file should ever contain is reflection of unexported
// helpers up to the test binary.

package users

import (
	"time"

	"github.com/joestump/reduit/internal/store"
)

// NewWithClock is the test-only constructor that lets callers inject
// a deterministic clock. Returns the Service interface so tests
// don't depend on the unexported `*service` type.
func NewWithClock(s *store.Store, now func() time.Time) Service {
	return newWithClock(s, now)
}
