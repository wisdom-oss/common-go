package jwt

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/wisdom-oss/common-go/v3/internal/jwt"
)

type Validator struct {
	jwt.Validator
}

func (v *Validator) Handler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		headers := r.Header["Authorization"]
		switch {
		case len(headers) == 0:
			jwt.ErrMissingAuthorizationHeader.Emit(w)
			return
		case len(headers) > 1:
			jwt.ErrSingleAuthorizationHeaderOnly.Emit(w)
			return
		}

		val := strings.TrimSpace(headers[0])
		if !jwt.TokenSchemeRegexCompiled.MatchString(val) {
			jwt.ErrUnsupportedTokenScheme.Emit(w)
			return
		}

		token, err := v.ParseHTTPRequest(r)
		if err != nil {
			err.Emit(w)
			return
		}

		scopes, correctType := token.PrivateClaims()["scopes"].([]string)
		if !correctType {
			jwt.ErrJWTMalformed.Emit(w)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, KeyTokenValidated, true)
		ctx = context.WithValue(ctx, KeyTokenPermissions, scopes)
		ctx = context.WithValue(ctx, KeyAdministrator, slices.Contains(scopes, jwt.ScopeAdministrator))
		ctx = context.WithValue(ctx, KeyTokenSubject, token.Subject())

		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(fn)

}
