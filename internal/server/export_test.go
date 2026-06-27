package server

import (
	"context"

	"github.com/joestump/reduit/internal/account"
	authsession "github.com/joestump/reduit/internal/auth/session"
	"github.com/joestump/reduit/internal/users"
)

// PrincipalActiveChecker exposes the unexported principalActiveChecker
// to the external server_test package so issue #52's user-scoped
// re-check logic can be unit-tested directly.
func PrincipalActiveChecker(usersSvc users.Service, acctSvc account.Service) func(context.Context, authsession.Identity) (bool, error) {
	return principalActiveChecker(usersSvc, acctSvc)
}
