package middleware

import (
	"context"
	"fmt"
	"math"
	"net/http"

	"github.com/wisdom-oss/common-go/types"
)

// ErrorHandler is used to inject a channel into the request's context to enable
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
func ErrorHandler(next http.Handler) http.Handler {
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
				err := Panic
				err.Errors = []error{}
				for _, p := range panics {
					err.Errors = append(err.Errors, fmt.Errorf("%v", p))
				}
				err.Send(w)
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
					InvalidTypeProvided.Send(w)
					return
				}
			}
			if serviceErr != nil {
				serviceErr.Errors = errs
				serviceErr.Send(w)
				return
			}
			if len(errs) > 0 {
				serviceErr = InternalError
				serviceErr.Errors = errs
				serviceErr.Send(w)
				return
			}
		}()
		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(fn)
}

func NotFoundError(w http.ResponseWriter, _ *http.Request) {
	NotFound.Send(w)
}
