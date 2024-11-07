package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	errorHandler "github.com/wisdom-oss/common-go/v2/internal/error-handler"
	internal "github.com/wisdom-oss/common-go/v2/internal/validate-jwt"
	"github.com/wisdom-oss/common-go/v2/types"
)

var (
	supportedSchemes = []string{"http", "https"}
)

// JWTValidator enables the gin router and the stdlib to validate a JWT passed
// in the request headers.
// It expects the OAuth 2.0 Bearer Token scheme as Authorization method.
// To apply the validator, use either the GinHandler or Handler function
// depending on the router you are using
type JWTValidator struct {
	// issuer contains the OAuth 2.0 issuer of the jwts
	issuer string

	// jwksCache is used to cache a once retrieved JWK to minimize network traffic
	// and optimize latency
	jwksCache *jwk.Cache

	// issuerJwksUri contains the uri pointing to the JWK for the issuer. It is
	// used as the cache key in the jwksCache.
	issuerJwksUri string

	// parserOptions contains the options used for parsing a JWT found in the
	// request headers
	parserOptions []jwt.ParseOption
}

func (v *JWTValidator) AddParserOption(options ...jwt.ParseOption) {
	v.parserOptions = append(v.parserOptions, options...)
}

// DiscoverAndConfigure uses the OpenID Connect discovery mechanism to discover
// the required variables and uris and configures them accordingly
func (v *JWTValidator) DiscoverAndConfigure(issuer string) error {
	if strings.TrimSpace(issuer) == "" {
		return ErrIssuerEmpty
	}
	uri, err := url.Parse(issuer)
	if err != nil {
		return errors.Join(ErrDiscoveryFailure, ErrIssuerUnsupportedScheme, err)
	}

	if !slices.Contains(supportedSchemes, uri.Scheme) {
		return errors.Join(ErrDiscoveryFailure, ErrIssuerUnsupportedScheme, ErrJWKSUriInvalid)
	}

	issuer = strings.TrimSpace(issuer)

	oidcDiscoveryUri := fmt.Sprintf("%s/.well-known/openid-configuration", strings.TrimSuffix(issuer, "/"))
	res, err := http.Get(oidcDiscoveryUri)
	if err != nil {
		return errors.Join(ErrDiscoveryFailure, err)
	}

	var discoveryResponse map[string]interface{}
	err = json.NewDecoder(res.Body).Decode(&discoveryResponse)
	if err != nil {
		return errors.Join(ErrDiscoveryFailure, ErrDiscoveryResponseParseFailed, err)
	}

	jwksUri, ok := discoveryResponse["jwks_uri"].(string)
	if !ok {
		return errors.Join(ErrDiscoveryFailure, errors.New("jwks_uri field not a string in response"))
	}
	if _, err = url.Parse(jwksUri); err != nil {
		return errors.Join(ErrDiscoveryFailure, ErrJWKSUriInvalid, err)
	}

	return v.Configure(issuer, jwksUri, false)
}

// Configure allows the manual configuration of an issuer and a JWKS uri
// (used to validate JWTs) but allows using incorrect JWKS uris to handle manual
// or missing JWKS
func (v *JWTValidator) Configure(issuer string, jwksUri string, allowFaultyJWKSUri bool) error {
	_, err := url.Parse(issuer)
	if err != nil {
		return errors.Join(ErrIssuerUnsupportedScheme, err)
	}
	v.issuer = strings.TrimSpace(issuer)

	_, err = url.Parse(jwksUri)
	if err != nil && !allowFaultyJWKSUri {
		return errors.Join(ErrJWKSUriInvalid, err)
	}
	v.issuerJwksUri = strings.TrimSpace(jwksUri)

	v.jwksCache = jwk.NewCache(context.Background())
	err = v.jwksCache.Register(v.issuerJwksUri)
	if err != nil && !allowFaultyJWKSUri {
		return errors.Join(ErrJWKSCacheRegisterFailed, err)
	}
	_, err = v.jwksCache.Refresh(context.Background(), v.issuerJwksUri)
	if err != nil && !allowFaultyJWKSUri {
		return errors.Join(ErrJWKSCacheRefreshFailed, err)
	}

	v.parserOptions = []jwt.ParseOption{
		jwt.WithIssuer(v.issuer),
		jwt.WithVerify(!allowFaultyJWKSUri),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(5 * time.Second),
	}

	return nil
}

// Handler is used to emit the correct handler method for using the middleware
// in requests.
// To get the correct handler function, please pass the router you are using
// as the router parameter.
// If the router is either not supported or doesn't require a special handler
// one compliant with the net/http package will be returned.
// Currently supported special-implementation routers:
//   - *gin.Engine
func (v *JWTValidator) Handler(router any) (any, error) {
	switch router.(type) {
	case *gin.Engine:
		return v.gin, nil
	default:
		return v.stdlib, nil
	}
}

func (v *JWTValidator) gin(c *gin.Context) {
	// get the value of the authorization header
	header := strings.TrimSpace(c.GetHeader("Authorization"))
	if header == "" {
		c.Abort()
		internal.ErrMissingAuthorizationHeader.Emit(c)
		return
	}
	if !strings.HasPrefix(header, `Bearer `) {
		c.Abort()
		internal.ErrUnsupportedTokenScheme.Emit(c)
		return
	}
	credential, err := v.parseRequest(c.Request)
	if err != nil {
		c.Abort()
		switch err.(type) {
		case error:
			response := internal.ErrJWTMalformed
			response.Errors = []error{err.(error)}
			response.Emit(c)
		case types.ServiceError:
			err.(types.ServiceError).Emit(c)
		default:
			panic(err)
		}
		return
	}
	scopesInterface, available := credential.Get("scopes")
	if !available {
		c.Abort()
		internal.ErrJWTNoScopeSet.Emit(c)
		return
	}
	scopeInterfacedArray, isCorrectType := scopesInterface.([]any)
	if !isCorrectType {
		c.Abort()
		internal.ErrJWTMalformed.Emit(c)
		return
	}
	var scopes []string
	for _, scopeInterface := range scopeInterfacedArray {
		if scope, ok := scopeInterface.(string); !ok {
			c.Abort()
			internal.ErrJWTMalformed.Emit(c)
			return
		} else {
			scopes = append(scopes, scope)
		}
	}
	c.Set(internal.KeyTokenValidated, true)
	c.Set(internal.KeyPermissions, scopes)
	c.Set(internal.KeyAdministrator, slices.Contains(scopes, internal.ScopeAdministrator))
	c.Set(internal.KeySubject, credential.Subject())
}

func (v *JWTValidator) stdlib(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		if header == "" {
			internal.ErrMissingAuthorizationHeader.Emit(w)
			return
		}
		if !strings.HasPrefix(header, `Bearer `) {
			internal.ErrUnsupportedTokenScheme.Emit(w)
			return
		}

		credential, err := v.parseRequest(r)
		if err != nil {
			switch err.(type) {
			case error:

				response := errorHandler.InternalError
				response.Errors = []error{err.(error)}
				response.Emit(w)
			case types.ServiceError:
				err.(types.ServiceError).Emit(w)
			default:
				panic(err)
			}
			return
		}

		scopesInterface, available := credential.Get("scopes")
		if !available {
			internal.ErrJWTNoScopeSet.Emit(w)
			return
		}
		scopeInterfacedArray, isCorrectType := scopesInterface.([]any)
		if !isCorrectType {
			internal.ErrJWTMalformed.Emit(w)
			return
		}
		var scopes []string
		for _, scopeInterface := range scopeInterfacedArray {
			if scope, ok := scopeInterface.(string); !ok {
				internal.ErrJWTMalformed.Emit(w)
				return
			} else {
				scopes = append(scopes, scope)
			}
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, internal.KeyTokenValidated, true)
		ctx = context.WithValue(ctx, internal.KeyPermissions, scopes)
		ctx = context.WithValue(ctx, internal.KeyAdministrator, slices.Contains(scopes, internal.ScopeAdministrator))
		ctx = context.WithValue(ctx, internal.KeySubject, credential.Subject())
		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(fn)
}

// parseRequest takes the incoming request and tries to parse the credential
// from the Authorization header.
// The credential is parsed with the parserOptions, and a basic error handling
// checks for different errors that may occur (e.g., expired jwt) and returns
// the correct types.ServiceError for those errors.
// If the error is not one of the known errors, the error will be returned for
// further handling.
func (v *JWTValidator) parseRequest(r *http.Request) (credential jwt.Token, error any) {
	parserOptions := v.parserOptions
	if v.jwksCache.IsRegistered(v.issuerJwksUri) {
		keySet, err := v.jwksCache.Get(r.Context(), v.issuerJwksUri)
		if err != nil && !strings.HasPrefix(err.Error(), "cached object is not a Set") {
			return nil, err
		}
		parserOptions = append(parserOptions, jwt.WithKeySet(keySet))
	}
	credential, err := jwt.ParseHeader(r.Header, "Authorization", parserOptions...)
	if err != nil {
		switch {
		case strings.HasPrefix(err.Error(), `empty header`):
			return nil, internal.ErrMissingAuthorizationHeader
		case errors.Is(err, jwt.ErrInvalidJWT()):
			return nil, internal.ErrJWTMalformed
		case errors.Is(err, jwt.ErrTokenExpired()):
			return nil, internal.ErrJWTExpired
		case errors.Is(err, jwt.ErrTokenNotYetValid()):
			return nil, internal.ErrJWTNotYetValid
		case errors.Is(err, jwt.ErrInvalidIssuedAt()):
			return nil, internal.ErrJWTNotCreatedYet
		case errors.Is(err, jwt.ErrInvalidIssuer()):
			return nil, internal.ErrJWTInvalidIssuer
		default:
			return nil, err
		}
	}
	return credential, nil
}
