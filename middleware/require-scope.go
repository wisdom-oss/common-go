package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"

	internal "github.com/wisdom-oss/common-go/v2/internal/validate-jwt"
	"github.com/wisdom-oss/common-go/v2/types"
)

type RequireScope struct{}

func (s RequireScope) Handler(scope string, level types.Scope) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			if ctx.Value(internal.KeyTokenValidated) == nil {
				next.ServeHTTP(w, r)
				return
			}

			permissions, permissionsSet := ctx.Value(internal.KeyPermissions).([]string)
			if !permissionsSet {
				panic("no permissions set, but validator passed")
			}

			requiredScope := fmt.Sprintf("%s:%s", scope, level)
			if slices.Contains(permissions, internal.ScopeAdministrator) || slices.Contains(permissions, requiredScope) {
				next.ServeHTTP(w, r)
				return
			}

			internal.Forbidden.Emit(w)
			return
		}
		return http.HandlerFunc(fn)
	}
}

func (s RequireScope) Gin(scope string, level types.Scope) gin.HandlerFunc {
	fn := func(c *gin.Context) {
		if !c.GetBool(internal.KeyTokenValidated) {
			c.Next()
			return
		}

		permissionsInterface, permissionsSet := c.Get(internal.KeyPermissions)
		if !permissionsSet {
			c.AbortWithError(http.StatusInternalServerError, errors.New("no permissions set, but validator passed"))
			return
		}
		permissions, _ := permissionsInterface.([]string)
		requiredScope := fmt.Sprintf("%s:%s", scope, level)

		if slices.Contains(permissions, internal.ScopeAdministrator) || slices.Contains(permissions, requiredScope) {
			c.Next()
			return
		}

		c.Abort()
		internal.Forbidden.Emit(c)
		return

	}
	return fn
}
