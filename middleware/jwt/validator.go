package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/wisdom-oss/common-go/v3/types"

	errorHandler "github.com/wisdom-oss/common-go/v3/internal/error-handler"
)

type Validator struct {
	issuer        string
	jwksCache     *jwk.Cache
	jwkSet        jwk.Set
	parserOptions []jwt.ParseOption
}

var globalParserOptions = []jwt.ParseOption{
	jwt.WithAcceptableSkew(10 * time.Second),
	jwt.WithRequiredClaim("scopes"),
}

var tokenSchemeRegexCompiled *regexp.Regexp
var ErrDiscoverFailure = errors.New("validator configuration discovery failure")
var ErrIssuerEmtpy = errors.New("issuer empty")
var ErrIssuerNotHTTP = errors.New("issuer unrequestable")

const tokenSchemeRegex = `(?i)^Bearer .+$`

const KeyTokenValidated = "jwt.validated"
const KeyTokenPermissions = "jwt.permissions"
const KeyTokenSubject = "jwt.subject"
const KeyAdministrator = "jwt.administrator"

func init() {
	tokenSchemeRegexCompiled = regexp.MustCompile(tokenSchemeRegex)
}

// Discover uses the OpenID Connect Discovery mecahnism to discover the
// JWKS URI. It also sets the issuer based on the discovery response.
func (r *Validator) Discover(issuer string) error {
	if strings.TrimSpace(issuer) == "" {
		return errors.Join(ErrDiscoverFailure, ErrIssuerEmtpy)
	}

	uri, err := url.ParseRequestURI(issuer)
	if err != nil {
		return errors.Join(ErrDiscoverFailure, ErrIssuerNotHTTP, err)
	}

	discoveryUri := fmt.Sprintf("%s.well-known/openid-configuration", uri.String())
	res, err := http.Get(discoveryUri)
	if err != nil {
		return errors.Join(ErrDiscoverFailure, err)
	}

	var requiredDiscoveryResponseFields struct {
		Issuer  string `json:"issuer"`
		JWKSUri string `json:"jwks_uri"`
	}
	err = json.NewDecoder(res.Body).Decode(&requiredDiscoveryResponseFields)
	if err != nil {
		return errors.Join(ErrDiscoverFailure, err)
	}

	r.issuer = requiredDiscoveryResponseFields.Issuer
	err = r.configureJWKSCache(requiredDiscoveryResponseFields.JWKSUri)
	if err != nil {
		return errors.Join(ErrDiscoverFailure, err)
	}

	r.parserOptions = []jwt.ParseOption{
		jwt.WithIssuer(r.issuer),
		jwt.WithKeyProvider(r),
	}
	r.parserOptions = append(r.parserOptions, globalParserOptions...)

	return nil
}

var ErrUnsupportedManualJWKS = errors.New("unsupported jwks source type")

// Configure allows the manual configuration of the issuer and JWKS
//
// Please note that specifying a uri will not work with this function as it only
// accepts already retrieved data. The supported types for jwksSource are:
//   - jwk.Set
//   - io.Reader
//   - []byte
//   - string
//
// The parseOptions parameter allows configuring the parsing of the jwksSource,
// except when the actual type of jwksSource is jwk.Set as this will be a
// direct assignment of the supplied value
func (r *Validator) Configure(issuer string, jwksSource any, parseOptions []jwk.ParseOption) (err error) {
	r.issuer = issuer

	switch jwks := jwksSource.(type) {
	case jwk.Set:
		r.jwkSet = jwks
	case io.Reader:
		r.jwkSet, err = jwk.ParseReader(jwks, parseOptions...)
	case []byte:
		r.jwkSet, err = jwk.Parse(jwks, parseOptions...)
	case string:
		r.jwkSet, err = jwk.ParseString(jwks, parseOptions...)
	default:
		return ErrUnsupportedManualJWKS
	}
	r.parserOptions = []jwt.ParseOption{
		jwt.WithIssuer(r.issuer),
		jwt.WithKeySet(r.jwkSet),
	}
	r.parserOptions = append(r.parserOptions, globalParserOptions...)
	return err
}

func (r *Validator) configureJWKSCache(uri string) error {
	if r.jwksCache == nil {
		r.jwksCache = jwk.NewCache(context.Background())
	}

	r.jwkSet = jwk.NewCachedSet(r.jwksCache, uri)
	return nil
}

func (r *Validator) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
	kid := sig.ProtectedHeaders().KeyID()
	key, found := r.jwkSet.LookupKeyID(kid)
	if !found {
		return nil
	}

	sink.Key(sig.ProtectedHeaders().Algorithm(), key)
	return nil
}

// parseHTTPRequest parses the HTTP request for the token and returns the
// accessToken. If an error occurrs the function returns an outputtable
// *types.ServiceError
func (v *Validator) parseHTTPRequest(r *http.Request) (accessToken jwt.Token, res *types.ServiceError) {
	accessToken, err := jwt.ParseHeader(r.Header, "Authorization", v.parserOptions...)
	if err == nil {
		return accessToken, nil
	}

	switch {
	case strings.HasPrefix(err.Error(), `empty header`):
		return nil, &ErrMissingAuthorizationHeader
	case errors.Is(err, jwt.ErrInvalidJWT()):
		return nil, &ErrJWTMalformed
	case errors.Is(err, jwt.ErrRequiredClaim()):
		return nil, &ErrJWTMissingRequiredClaim
	case errors.Is(err, jwt.ErrInvalidAudience()):
		return nil, &ErrJWTInvalidAudience
	case errors.Is(err, jwt.ErrTokenExpired()):
		return nil, &ErrJWTExpired
	case errors.Is(err, jwt.ErrTokenNotYetValid()):
		return nil, &ErrJWTNotYetValid
	case errors.Is(err, jwt.ErrInvalidIssuedAt()):
		return nil, &ErrJWTNotCreatedYet
	case errors.Is(err, jwt.ErrInvalidIssuer()):
		return nil, &ErrJWTInvalidIssuer
	default:
		res = errorHandler.InternalError
		res.Errors = []error{err}
		return nil, res
	}
}
