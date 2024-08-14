package middleware

import (
	"fmt"
	"net/http"
	"os"
	"slices"

	"github.com/wisdom-oss/common-go/types"
)

// RequireScope is a middleware restricts the access to a resource for users
// with the specified scope on the specified group. The values required by this
// middleware are inserted by the JWTValidator.Handler middleware.
// If the JWTValidator.Handler is not executed before this middleware, the
// request will automatically be allowed and a warning message will appear on
// the os.Stderr output.
func RequireScope(group string, requiredScope types.Scope) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			// access the request's context
			ctx := r.Context()

			// create variables to support goto
			var userGroups []string
			var scopeString string
			var staff, allowAccess bool

			if ctx.Value(validateActiveCtxKey) == nil {
				allowAccess = true
				_, _ = fmt.Fprint(os.Stderr, `! WARNING ! \t JWT Validator not in middleware chain. Please check your configuration.\n`)
				goto handleScopeResult
			}

			scopeString = fmt.Sprintf("%s:%s", group, requiredScope)
			userGroups, _ = ctx.Value(groupsCtxKey).([]string)
			if slices.Contains(userGroups, scopeString) {
				allowAccess = true
				goto handleScopeResult
			}

			staff, _ = ctx.Value(staffCtxKey).(bool)
			if staff {
				allowAccess = true
				goto handleScopeResult
			}

		handleScopeResult:
			if !allowAccess {
				Forbidden.Send(w)
				return
			}
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}
