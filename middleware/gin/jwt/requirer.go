package jwt

import (
	"fmt"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/wisdom-oss/common-go/v3/internal/jwt"
	"github.com/wisdom-oss/common-go/v3/types"
)

type ScopeRequirer struct {
	jwt.ScopeRequirer
}

func (sr *ScopeRequirer) require(scope types.Scope, c *gin.Context) {
	isAdministrator := c.GetBool(KeyAdministrator)
	if isAdministrator {
		c.Next()
		return
	}

	scopes := c.GetStringSlice(KeyTokenPermissions)
	if len(scopes) == 0 {
		c.Abort()
		jwt.ErrForbidden.Emit(c)
		return

	}

	requiredScope := fmt.Sprintf(`%s:%s`, sr.Service, scope)

	if !slices.Contains(scopes, requiredScope) {
		c.Abort()
		jwt.ErrForbidden.Emit(c)
		return
	}

}

func (sr *ScopeRequirer) RequireRead(c *gin.Context) {
	sr.require(types.ScopeRead, c)
	if c.IsAborted() {
		return
	}
	c.Next()
}

func (sr *ScopeRequirer) RequireWrite(c *gin.Context) {
	sr.require(types.ScopeWrite, c)
	if c.IsAborted() {
		return
	}
	c.Next()
}

func (sr *ScopeRequirer) RequireDelete(c *gin.Context) {
	sr.require(types.ScopeDelete, c)
	if c.IsAborted() {
		return
	}
	c.Next()
}

func (sr *ScopeRequirer) RequireAdministrator(c *gin.Context) {
	isAdministrator := c.GetBool(KeyAdministrator)
	if isAdministrator {
		c.Next()
		return
	}

	c.Abort()
	jwt.ErrForbidden.Emit(c)
}
