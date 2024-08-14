package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// JWTValidator allows authenticating and deconstructing JSON Web Tokens.
// During configuration, it tries to use the OpenID Connect Discovery Protocol
// to resolve a JSON Web Key used to sign the JWT to increase the security.
type JWTValidator struct {
	issuer       string
	jwks         *jwk.Cache
	jwksUri      string
	validateJWKS bool
	verifyJWT    bool
}

// Configure uses the OpenID Connect Discovery Protocol to resolve and verify
// the issuer for the JWTs contained in a request and configures the
// JWTValidator.Handler
func (m *JWTValidator) Configure(issuer string) error {
	_, err := url.ParseRequestURI(issuer)
	if err != nil {
		m.issuer = issuer
		m.validateJWKS = false
		m.verifyJWT = false
		return nil
	}
	m.issuer = issuer
	openidDiscoveryUrl := fmt.Sprintf(`%s/.well-known/openid-configuration`, issuer)
	res, err := http.Get(openidDiscoveryUrl)
	if err != nil {
		m.validateJWKS = false
		m.verifyJWT = false

		return nil
	}
	var openidConfiguration map[string]interface{}
	err = json.NewDecoder(res.Body).Decode(&openidConfiguration)
	if err != nil {
		m.validateJWKS = false
		m.verifyJWT = false
		return nil
	}
	m.jwks = jwk.NewCache(context.Background())
	m.jwksUri = openidConfiguration["jwks_uri"].(string)
	err = m.jwks.Register(m.jwksUri, jwk.WithIgnoreParseError(true))
	if err != nil {
		m.validateJWKS = false
		m.verifyJWT = false
		return nil
	}
	jwks, err := m.jwks.Refresh(context.Background(), m.jwksUri)
	if err != nil {
		m.validateJWKS = false
		m.verifyJWT = false
		return nil
	}
	if jwks == nil {
		m.validateJWKS = false
		m.verifyJWT = false
		return nil
	}
	m.verifyJWT = true
	m.validateJWKS = true
	return nil
}

// Handler contains the actual middleware which analyzes the Authorization
// header contained in each request.
// It extracts the JWT and supplies the groups that have been assigned to the
// JWT to the request's context.
// This allows the usage of the RequireScope middleware to check the permissions
// for accessing a specific resource.
func (m *JWTValidator) Handler(next http.Handler) http.Handler {

	fn := func(w http.ResponseWriter, r *http.Request) {
		// retrieve all authorization headers from the request and check if the
		// token scheme is "Bearer" and if only a single header has been provided
		headers, set := r.Header["Authorization"]
		if !set || len(headers) == 0 {
			ErrMissingAuthorizationHeader.Send(w)
			return
		}
		if len(headers) != 1 {
			ErrSingleAuthorizationHeaderOnly.Send(w)
			return
		}

		// now ensure that the header uses the Bearer scheme to transmit the token
		header := strings.TrimSpace(headers[0])
		if !strings.HasPrefix(header, "Bearer ") {
			ErrUnsupportedTokenScheme.Send(w)
			return
		}
		jwtParseOptions := []jwt.ParseOption{
			jwt.WithValidate(true),
			jwt.WithIssuer(m.issuer),
			jwt.WithVerify(m.verifyJWT),
		}
		credential, err := jwt.ParseHeader(r.Header, "Authorization", jwtParseOptions...)
		if err != nil {
			switch {
			case strings.HasPrefix(err.Error(), `empty header`):
				ErrMissingAuthorizationHeader.Send(w)
				return
			case errors.Is(err, jwt.ErrInvalidJWT()):
				ErrJWTMalformed.Send(w)
				return
			case errors.Is(err, jwt.ErrTokenExpired()):
				ErrJWTExpired.Send(w)
				return
			case errors.Is(err, jwt.ErrTokenNotYetValid()):
				ErrJWTNotYetValid.Send(w)
				return
			case errors.Is(err, jwt.ErrInvalidIssuedAt()):
				ErrJWTNotCreatedYet.Send(w)
				return
			case errors.Is(err, jwt.ErrInvalidIssuer()):
				ErrJWTInvalidIssuer.Send(w)
				return
			default:
				e := InternalError
				e.Errors = []error{err}
				e.Send(w)
				return
			}
		}

		// now check the private claim "groups" for the groups that have been set
		groupsInterface, set := credential.PrivateClaims()["groups"].([]interface{})
		if !set {
			ErrJWTNoGroups.Send(w)
			return
		}

		// now iterate over the entries of the groups and append them all as strings
		// to the request's context
		ctx := r.Context()
		var groups []string
		for _, groupInterface := range groupsInterface {
			groups = append(groups, groupInterface.(string))
		}
		ctx = context.WithValue(ctx, groupsCtxKey, groups)
		ctx = context.WithValue(ctx, validateActiveCtxKey, "true")

		// now add the private claim "staff" to the request's context
		claimStaff := credential.PrivateClaims()["staff"]
		var isStaff bool
		if claimStaff != nil {
			isStaff, err = strconv.ParseBool(claimStaff.(string))
			if err != nil {
				goto serveRequest
			}
		}
		ctx = context.WithValue(ctx, staffCtxKey, isStaff || slices.Contains(groups, "*:*"))

		// now let the request continue to the next handler
	serveRequest:
		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(fn)
}
