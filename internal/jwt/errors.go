package jwt

import (
	"net/http"

	"github.com/wisdom-oss/common-go/v3/types"
)

var InternalError = &types.ServiceError{
	Type:   "https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1",
	Status: http.StatusInternalServerError,
	Title:  "Internal Server Error",
	Detail: "The service encountered an internal error during the handling of your request",
}

// the `Authorization` header.
var ErrMissingAuthorizationHeader = types.ServiceError{
	Type:   "https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1",
	Status: http.StatusUnauthorized,
	Title:  "Missing Authorization Header",
	Detail: "The request did not contain the 'Authorization' header. Please check your request.",
}

// multiple credentials.
var ErrSingleAuthorizationHeaderOnly = types.ServiceError{
	Type:   "https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1",
	Status: http.StatusBadRequest,
	Title:  "Multiple Credentials supplied",
	Detail: "The request contained multiple credentials. Due to security reasons, this is not supported and the request has been rejected", //nolint:lll
}

// ErrUnsupportedTokenScheme is returned if the request did not utilize the
// Bearer token scheme as documented in [RFC 6750].
//
// [RFC 6750]: https://www.rfc-editor.org/rfc/rfc6750
var ErrUnsupportedTokenScheme = types.ServiceError{
	Type:   "https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1",
	Status: http.StatusBadRequest,
	Title:  "Unsupported Token Scheme used",
	Detail: "The token scheme used in this request is not supported by the service. Please check your request.",
}

// ErrJWTMalformed is returned if the request did contain a JWT but is malformed.
var ErrJWTMalformed = types.ServiceError{
	Type:   "https://www.rfc-editor.org/rfc/rfc9110#section-15.5.1",
	Status: http.StatusBadRequest,
	Title:  "JSON Web Token Malformed",
	Detail: "The JSON Web Token presented as Bearer Token is not correctly formatted",
}

// ErrJWTExpired is returned if the JWT in the request is already expired.
var ErrJWTExpired = types.ServiceError{
	Type:   "https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1",
	Status: http.StatusUnauthorized,
	Title:  "JSON Web Token Expired",
	Detail: "The JSON Web Token used to access this resource has expired. Access has been denied",
}

// jwt is not valid contains a time in the future.
var ErrJWTNotYetValid = types.ServiceError{
	Type:   "https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1",
	Status: http.StatusUnauthorized,
	Title:  "JSON Web Token Used Before Validity",
	Detail: "The JSON Web Token used to access this resource has been used before it is permitted to be used. Access has been denied", //nolint:lll
}

// token has been issued is in the future.
var ErrJWTNotCreatedYet = types.ServiceError{
	Type:   "https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1",
	Status: http.StatusUnauthorized,
	Title:  "JSON Web Token Used Before Creation",
	Detail: "The JSON Web Token used to access this resource been created in the future, therefore it is invalid and the access has been denied. Please check your authentication provider.", //nolint:lll
}

// has not been issued by the API Gateway.
var ErrJWTInvalidIssuer = types.ServiceError{
	Type:   "https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1",
	Status: http.StatusUnauthorized,
	Title:  "JSON Web Token Issuer Wrong",
	Detail: "The JSON Web Token used to access this resource has not been issued by the correct issuer. Please check your authentication provider.", //nolint:lll
}

// therefore is not usable for the service.
var ErrJWTNoScopeSet = types.ServiceError{
	Type:   "https://www.rfc-editor.org/rfc/rfc9110#section-15.5.1",
	Status: http.StatusBadRequest,
	Title:  "No Scopes Set",
	Detail: "The JSON Web Token used to access this resource does not contain a scope to identify the permissions of the token", //nolint:lll
}

// therefore is not usable for the service.
var ErrJWTInvalidScopeType = types.ServiceError{
	Type:   "https://www.rfc-editor.org/rfc/rfc9110#section-15.5.1",
	Status: http.StatusBadRequest,
	Title:  "No Scopes Set",
	Detail: "The JSON Web Token used to access this resource does not contain a scope to identify the permissions of the token", //nolint:lll
}

// access the resource.
var ErrForbidden = types.ServiceError{
	Type:   "https://www.rfc-editor.org/rfc/rfc9110#section-15.5.4",
	Status: http.StatusForbidden,
	Title:  "Forbidden",
	Detail: "Access to this resource is not allowed for your user. Please check that you have been assigned to the required scope: %s", //nolint:lll
}

// ErrJWTMalformed is returned if the request did contain a JWT but is malformed.
var ErrJWTMissingRequiredClaim = types.ServiceError{
	Type:   "https://www.rfc-editor.org/rfc/rfc9110#section-15.5.1",
	Status: http.StatusBadRequest,
	Title:  "JSON Web Token Required Claim Missing",
	Detail: "The JSON Web Token is missing a required claim and therefore is invalid.",
}

// ErrJWTMalformed is returned if the request did contain a JWT but is malformed.
var ErrJWTInvalidAudience = types.ServiceError{
	Type:   "https://www.rfc-editor.org/rfc/rfc9110#section-15.5.2",
	Status: http.StatusUnauthorized,
	Title:  "JSON Web Token Invalid Audience",
	Detail: "The JSON Web Token has been issued for a different target audience",
}

var ErrNoOp = types.ServiceError{}
