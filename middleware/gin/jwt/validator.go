package jwt

import (
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/wisdom-oss/common-go/v3/internal/jwt"
)

type Validator struct {
	jwt.Validator
}

func (r *Validator) Handler(c *gin.Context) {
	headers := c.Request.Header["Authorization"]
	switch {
	case len(headers) == 0:
		if r.IsOptional() {
			c.Next()
			return
		}
		c.Abort()
		jwt.ErrMissingAuthorizationHeader.Emit(c)
		return
	case len(headers) > 1:
		if r.IsOptional() {
			c.Next()
			return
		}
		c.Abort()
		jwt.ErrSingleAuthorizationHeaderOnly.Emit(c)
		return
	}

	val := strings.TrimSpace(headers[0])
	if !jwt.TokenSchemeRegexCompiled.MatchString(val) {
		if r.IsOptional() {
			c.Next()
			return
		}
		c.Abort()
		jwt.ErrUnsupportedTokenScheme.Emit(c)
		return
	}

	token, err := r.ParseHTTPRequest(c.Request)
	if err != nil {
		if r.IsOptional() {
			c.Next()
			return
		}
		c.Abort()
		err.Emit(c)
		return
	}

	iface := token.PrivateClaims()["scopes"]
	ifaceArray, isArray := iface.([]any)
	if !isArray {
		if r.IsOptional() {
			c.Next()
			return
		}
		c.Abort()
		jwt.ErrJWTInvalidScopeType.Emit(c)
		return
	}
	var scopes []string
	for _, s := range ifaceArray {
		scope, ok := s.(string)
		if !ok {
			if r.IsOptional() {
				c.Next()
				return
			}
			c.Abort()
			jwt.ErrJWTInvalidScopeType.Emit(c)
			return
		}
		scopes = append(scopes, scope)
	}

	c.Set(KeyTokenValidated, true)
	c.Set(KeyTokenPermissions, scopes)
	c.Set(KeyTokenSubject, token.Subject())
	c.Set(KeyAdministrator, slices.Contains(scopes, jwt.ScopeAdministrator))

	c.Next()
}
