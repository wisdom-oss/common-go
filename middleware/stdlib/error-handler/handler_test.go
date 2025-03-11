package errorHandler_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	errorHandler "github.com/wisdom-oss/common-go/v3/middleware/stdlib/error-handler"
	"github.com/wisdom-oss/common-go/v3/types"
)

func Test(t *testing.T) {
	t.Run("No_Error", _no_error)
	t.Run("Recover_Panic", _recover_panic)
	t.Run("Native_Error", _native_error)
	t.Run("Service_Error", _service_error)
	t.Run("Invalid_Type", _invalid_type)
}

func _no_error(t *testing.T) {
	r := http.NewServeMux()
	r.Handle("GET /", func() http.Handler {
		next := func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(200)
		}
		return errorHandler.Handler(http.HandlerFunc(next))
	}())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	res := rec.Result()

	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func _recover_panic(t *testing.T) {
	expectedError := errorHandler.Panic

	r := http.NewServeMux()
	r.Handle("GET /", func() http.Handler {
		next := func(w http.ResponseWriter, _ *http.Request) {
			panic("panic")
		}
		return errorHandler.Handler(http.HandlerFunc(next))
	}())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	res := rec.Result()

	assert.Equal(t, int(expectedError.Status), res.StatusCode) //nolint:gosec

	var receviedError types.ServiceError
	err := json.NewDecoder(res.Body).Decode(&receviedError)
	assert.NoError(t, err)

	assert.True(t, receviedError.Equals(*expectedError))
}

func _native_error(t *testing.T) {
	expectedError := errorHandler.InternalError

	r := http.NewServeMux()
	r.Handle("GET /", func() http.Handler {
		next := func(w http.ResponseWriter, r *http.Request) {
			errorChannel := r.Context().Value(errorHandler.ErrorChannelName).(chan interface{})
			errorChannel <- errors.New("test-error")
		}
		return errorHandler.Handler(http.HandlerFunc(next))
	}())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	res := rec.Result()

	assert.Equal(t, int(expectedError.Status), res.StatusCode) //nolint:gosec

	var receviedError types.ServiceError
	err := json.NewDecoder(res.Body).Decode(&receviedError)
	assert.NoError(t, err)

	assert.True(t, receviedError.Equals(*expectedError))
}

func _service_error(t *testing.T) {
	expectedError := errorHandler.NotFound

	r := http.NewServeMux()
	r.Handle("GET /", func() http.Handler {
		next := func(w http.ResponseWriter, r *http.Request) {
			errorChannel := r.Context().Value(errorHandler.ErrorChannelName).(chan interface{})
			errorChannel <- errorHandler.NotFound
		}
		return errorHandler.Handler(http.HandlerFunc(next))
	}())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	res := rec.Result()

	assert.Equal(t, int(expectedError.Status), res.StatusCode) //nolint:gosec

	var receviedError types.ServiceError
	err := json.NewDecoder(res.Body).Decode(&receviedError)
	assert.NoError(t, err)

	assert.True(t, receviedError.Equals(*expectedError))
}

func _invalid_type(t *testing.T) {
	expectedError := errorHandler.InvalidTypeProvided
	r := http.NewServeMux()
	r.Handle("GET /", func() http.Handler {
		next := func(w http.ResponseWriter, r *http.Request) {
			errorChannel := r.Context().Value(errorHandler.ErrorChannelName).(chan interface{})
			errorChannel <- "abcdefg"
		}
		return errorHandler.Handler(http.HandlerFunc(next))
	}())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	res := rec.Result()

	assert.Equal(t, int(expectedError.Status), res.StatusCode) //nolint:gosec

	var receviedError types.ServiceError
	err := json.NewDecoder(res.Body).Decode(&receviedError)
	assert.NoError(t, err)

	assert.True(t, receviedError.Equals(*expectedError))
}
