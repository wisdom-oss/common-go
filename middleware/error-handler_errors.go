package middleware

import "github.com/wisdom-oss/common-go/types"

// Panic is the base types.ServiceError used if the ErrorHandler catches a panic
// during the handling of a request.
var Panic = &types.ServiceError{
	Type:   "https://pkg.go.dev/builtin#panic",
	Status: 500,
	Title:  "Internal Panic",
	Detail: "The service encountered a panic state during the handling of your request.",
}

// InternalError is the base types.ServiceError if the ErrorHandler only
// received objects implementing the Error() interface and no other errors were
// raised during the handling of the request
var InternalError = &types.ServiceError{
	Type:   "https://pkg.go.dev/builtin#panic",
	Status: 500,
	Title:  "Internal Server Error",
	Detail: "The service encountered an internal error during the handling of your request",
}

// InvalidTypeProvided is used in the case that an unsupported type has been
// passed to the ErrorHandler
var InvalidTypeProvided = &types.ServiceError{
	Type:   "https://pkg.go.dev/builtin#panic",
	Status: 999,
	Title:  "Invalid Error Supplied",
	Detail: "The content provided to the error handler is invalid",
}
