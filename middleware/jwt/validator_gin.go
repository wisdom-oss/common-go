//go:build !wisdom_stdlib

package jwt

import (
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	internal "github.com/wisdom-oss/common-go/v3/internal/jwt"
)

func (r *Validator) Handler(c *gin.Context) {
	headers := c.Request.Header["Authorization"]
	switch {
	case len(headers) == 0:
		c.Abort()
		ErrMissingAuthorizationHeader.Emit(c)
		return
	case len(headers) > 1:
		c.Abort()
		ErrSingleAuthorizationHeaderOnly.Emit(c)
		return
	}

	val := strings.TrimSpace(headers[0])
	if !tokenSchemeRegexCompiled.MatchString(val) {
		c.Abort()
		ErrUnsupportedTokenScheme.Emit(c)
		return
	}

	jwt, err := r.parseHTTPRequest(c.Request)
	if err != nil {
		c.Abort()
		err.Emit(c)
		return
	}

	iface, _ := jwt.PrivateClaims()["scopes"]
	ifaceArray, isArray := iface.([]any)
	if !isArray {
		c.Abort()
		ErrJWTInvalidScopeType.Emit(c)
		return
	}
	var scopes []string
	for _, s := range ifaceArray {
		scope, ok := s.(string)
		if !ok {
			c.Abort()
			ErrJWTInvalidScopeType.Emit(c)
			return
		}
		scopes = append(scopes, scope)
	}

	c.Set(KeyTokenValidated, true)
	c.Set(KeyTokenPermissions, scopes)
	c.Set(KeyTokenSubject, jwt.Subject())
	c.Set(KeyAdministrator, slices.Contains(scopes, internal.ScopeAdministrator))

	c.Next()
}
