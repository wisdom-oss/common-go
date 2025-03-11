package jwt

import (
	"context"
	"encoding/json"
	"errors"
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
)

const acceptableSkewSeconds = 10

type Validator struct {
	issuer        string
	jwksCache     *jwk.Cache
	jwkSet        jwk.Set
	parserOptions []jwt.ParseOption
	audiences     []string
	optional      bool
}

var globalParserOptions = []jwt.ParseOption{
	jwt.WithAcceptableSkew(acceptableSkewSeconds * time.Second),
	jwt.WithRequiredClaim(jwt.SubjectKey),
	jwt.WithRequiredClaim(jwt.IssuerKey),
	jwt.WithRequiredClaim(jwt.NotBeforeKey),
	jwt.WithRequiredClaim(jwt.AudienceKey),
	jwt.WithRequiredClaim(jwt.ExpirationKey),
	jwt.WithRequiredClaim(ScopesKey),
}

var TokenSchemeRegexCompiled *regexp.Regexp
var ErrDiscoverFailure = errors.New("validator configuration discovery failure")
var ErrIssuerEmtpy = errors.New("issuer empty")
var ErrIssuerNotHTTP = errors.New("issuer unrequestable")

const tokenSchemeRegex = `(?i)^Bearer .+$` //nolint:gosec

func init() {
	TokenSchemeRegexCompiled = regexp.MustCompile(tokenSchemeRegex)
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

	discoveryUri := uri.String() + ".well-known/openid-configuration"
	res, err := http.Get(discoveryUri) //nolint:gosec
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
		jwt.WithKeySet(r.jwkSet),
	}
	r.parserOptions = append(r.parserOptions, globalParserOptions...)

	return nil
}

var ErrUnsupportedManualJWKS = errors.New("unsupported jwks source type")

// direct assignment of the supplied value.
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

func (v *Validator) RequireAudiences(aud []string) {
	v.audiences = append(v.audiences, aud...)
}

func (v *Validator) DisableAudienceCheck() {
	v.audiences = nil
}

func (r *Validator) configureJWKSCache(uri string) error {
	if r.jwksCache == nil {
		r.jwksCache = jwk.NewCache(context.Background())
		err := r.jwksCache.Register(uri)
		if err != nil {
			return err
		}
		_, err = r.jwksCache.Refresh(context.Background(), uri)
		if err != nil {
			return err
		}
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

// *types.ServiceError.
func (v *Validator) ParseHTTPRequest(r *http.Request) (accessToken jwt.Token, res *types.ServiceError) {
	parserOptions := v.parserOptions
	for _, audience := range v.audiences {
		parserOptions = append(parserOptions, jwt.WithAudience(audience))
	}
	accessToken, err := jwt.ParseHeader(r.Header, "Authorization", parserOptions...)
	if err == nil {
		return accessToken, nil
	}

	switch {
	case strings.HasPrefix(err.Error(), `empty header`):
		return nil, &ErrMissingAuthorizationHeader

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
	case jws.IsVerificationError(err):
		if v.IsOptional() {
			return nil, &ErrNoOp
		}
		panic("unable to verify jwt")
	case errors.Is(err, jwt.ErrInvalidJWT()):
		res := ErrJWTMalformed
		res.Errors = []error{err}
		return nil, &res
	default:
		res = InternalError
		res.Errors = []error{err}
		return nil, res
	}
}

// that appear and still let the request pass.
func (r *Validator) EnableOptional() {
	r.optional = true
}

// let requests pass that are not optional.
func (r *Validator) DisableOptional() {
	r.optional = false
}

func (r *Validator) IsOptional() bool {
	return r.optional
}
