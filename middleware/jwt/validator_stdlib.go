//go:build wisdom_stdlib

package jwt

import (
	"context"
	"net/http"
	"slices"
	"strings"

	internal "github.com/wisdom-oss/common-go/v3/internal/jwt"
)

func (v *Validator) Handler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		headers := r.Header["Authorization"]
		switch {
		case len(headers) == 0:
			ErrMissingAuthorizationHeader.Emit(w)
			return
		case len(headers) > 1:
			ErrSingleAuthorizationHeaderOnly.Emit(w)
			return
		}

		val := strings.TrimSpace(headers[0])
		if !tokenSchemeRegexCompiled.MatchString(val) {
			ErrUnsupportedTokenScheme.Emit(w)
			return
		}

		jwt, err := v.parseHTTPRequest(r)
		if err != nil {
			err.Emit(w)
			return
		}

		scopes, correctType := jwt.PrivateClaims()["scopes"].([]string)
		if !correctType {
			ErrJWTMalformed.Emit(w)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, KeyTokenValidated, true)
		ctx = context.WithValue(ctx, KeyTokenPermissions, scopes)
		ctx = context.WithValue(ctx, KeyAdministrator, slices.Contains(scopes, internal.ScopeAdministrator))
		ctx = context.WithValue(ctx, KeyTokenSubject, jwt.Subject())

		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(fn)

}
