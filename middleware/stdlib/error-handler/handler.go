package errorHandler

import (
	"context"
	"fmt"
	"math"
	"net/http"

	"github.com/wisdom-oss/common-go/v3/types"
)

func Handler(next http.Handler) http.Handler {
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
				err.Emit(w)
				return
			}
			var errs []error
			var serviceErr *types.ServiceError
			for len(errorInput) > 0 {
				obj := <-errorInput
				switch obj := obj.(type) {
				case error:
					errs = append(errs, obj)
				case types.ServiceError:
					if serviceErr == nil {
						err := obj
						serviceErr = &err
					}
				case *types.ServiceError:
					if serviceErr == nil {
						serviceErr = obj
					}
				default:
					InvalidTypeProvided.Emit(w)
					return
				}
			}
			if serviceErr != nil {
				serviceErr.Errors = errs
				serviceErr.Emit(w)
				return
			}
			if len(errs) > 0 {
				serviceErr = InternalError
				serviceErr.Errors = errs
				serviceErr.Emit(w)
				return
			}
		}()
		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(fn)
}
