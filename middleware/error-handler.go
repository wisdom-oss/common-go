package middleware

import (
	"context"
	"fmt"
	"math"
	"net/http"

	"github.com/gin-gonic/gin"

	errorHandler "github.com/wisdom-oss/common-go/v2/internal/error-handler"
	"github.com/wisdom-oss/common-go/v2/types"
)

type ErrorHandler struct{}

// Handler is used to inject a channel into the request's context to enable
// a deferred handling of errors that may occur during handling of a request.
// The channel will be inserted using the ErrorChannelName variable which is
// generated automatically to circumvent possible name clashes.
// Furthermore, the ErrorHandler also recovers from internal panics and sends
// an error message about them as well.
//
// In case a [types.ServiceError] and multiple Errors are supplied to the
// ErrorHandler the errors are automatically added to the
// Errors field and sent together with the supplied types.ServiceError instance
//
// Usage Example:
//
//	r := chi.NewRouter()
//	r.Use(middleware.ErrorHandler)
//	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
//	    errorChannel := r.Context.Value(middleware.ErrorChannelName).(chan interface{})
//	    errorChannel <- errors.New("example error")
//	  })
//
// The ErrorHandler accepts objects implementing the Error interface and
// [types.ServiceError] objects.
// Using other types will result in a InvalidTypeProvided error being sent
// instead using the undocumented HTTP Status Code 999.
func (h ErrorHandler) Handler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		// create an error input which allows multiple errors to be collected
		errorInput := make(chan interface{}, math.MaxUint16)
		ctx := r.Context()
		ctx = context.WithValue(ctx, ErrorChannelName, errorInput)

		// defer the handling of errors and panics until the next handler has exited
		defer func() {
			var panics []any
			for {
				p := recover()
				if p != nil {
					if p == http.ErrAbortHandler {
						panic(p)
						return
					}
					panics = append(panics, p)
				} else {
					break
				}
			}
			if len(panics) > 0 {
				err := errorHandler.Panic
				err.Errors = []error{}
				for _, p := range panics {
					err.Errors = append(err.Errors, fmt.Errorf("%v", p))
				}
				err.Emit(w)
				return
			}
			var errs []error
			var serviceErr *types.ServiceError
			for len(errorInput) > 0 {
				obj := <-errorInput
				switch obj.(type) {
				case error:
					errs = append(errs, obj.(error))
				case types.ServiceError:
					if serviceErr == nil {
						err := obj.(types.ServiceError)
						serviceErr = &err
					}
				default:
					errorHandler.InvalidTypeProvided.Emit(w)
					return
				}
			}
			if serviceErr != nil {
				serviceErr.Errors = errs
				serviceErr.Emit(w)
				return
			}
			if len(errs) > 0 {
				serviceErr = errorHandler.InternalError
				serviceErr.Errors = errs
				serviceErr.Emit(w)
				return
			}
		}()
		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(fn)
}

// Gin catches all errors which occurred during the execution of a
// request and attaches them to the response object.
// If any errors are set using (gin.Context).Error(err) the handler aborts the
// context if that didn't already happen
func (h ErrorHandler) Gin(c *gin.Context) {
	c.Next()
	var errors []types.ServiceError
	for _, err := range c.Errors {
		errors = append(errors, types.ServiceError{
			Type:   "https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1",
			Status: 500,
			Title:  "Internal Server Error",
			Detail: "The service encountered an internal error during the handling of your request",
			Errors: []error{err.Err},
		})
	}
	if len(errors) > 0 {
		c.Abort()
		c.Header("Content-Type", "application/problem+json; charset=utf-8")
		c.JSON(500, errors)
	}
}
