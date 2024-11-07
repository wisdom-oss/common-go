package middleware

import "errors"

var (
	ErrDiscoveryFailure             = errors.New("oidc discovery failure")
	ErrIssuerEmpty                  = errors.New("issuer is empty")
	ErrIssuerUnsupportedScheme      = errors.New("oidc issuer has unsupported scheme")
	ErrDiscoveryResponseParseFailed = errors.New("oidc discovery response parse failed")
	ErrJWKSCacheRegisterFailed      = errors.New("jwks cache register failed")
	ErrJWKSCacheRefreshFailed       = errors.New("mandatory jwks cache refresh failed")
	ErrJWKSUriInvalid               = errors.New("jwks uri is not a valid uri")
)
