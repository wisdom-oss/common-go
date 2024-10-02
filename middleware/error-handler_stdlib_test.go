package middleware

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	errorHandler "github.com/wisdom-oss/common-go/v2/internal/error-handler"
	"github.com/wisdom-oss/common-go/v2/types"
)

func Test_ErrorHandler_stdlib_NoError(t *testing.T) {
	r := http.NewServeMux()
	r.Handle("GET /", func() http.Handler {
		nextFn := func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("success"))
		}
		return ErrorHandler{}.Handler(http.HandlerFunc(nextFn))
	}())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	res := rec.Result()

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "success", string(rec.Body.Bytes()))

	if t.Failed() {
		os.Stdout.Write([]byte("Authorization: " + req.Header.Get("Authorization") + "\n"))
		io.Copy(os.Stdout, res.Body)
	}
}

func Test_ErrorHandler_stdlib_RecoverPanic(t *testing.T) {
	r := http.NewServeMux()
	r.Handle("GET /", func() http.Handler {
		nextFn := func(w http.ResponseWriter, r *http.Request) {
			panic("panic")
		}
		return ErrorHandler{}.Handler(http.HandlerFunc(nextFn))
	}())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	res := rec.Result()

	assert.Equal(t, int(errorHandler.Panic.Status), res.StatusCode)

	var receivedError types.ServiceError
	err := json.Unmarshal(rec.Body.Bytes(), &receivedError)
	assert.NoError(t, err)
	assert.True(t, errorHandler.Panic.Equals(receivedError))

	if t.Failed() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("  ", "  ")
		enc.Encode(receivedError)

	}

}

func Test_ErrorHandler_stdlib_SendError(t *testing.T) {
	r := http.NewServeMux()
	r.Handle("GET /", func() http.Handler {
		nextFn := func(w http.ResponseWriter, r *http.Request) {
			errorChannel := r.Context().Value(ErrorChannelName).(chan interface{})
			errorChannel <- errors.New("test-error")
		}
		return ErrorHandler{}.Handler(http.HandlerFunc(nextFn))
	}())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	res := rec.Result()

	assert.Equal(t, int(errorHandler.InternalError.Status), res.StatusCode)

	var receivedError types.ServiceError
	err := json.Unmarshal(rec.Body.Bytes(), &receivedError)
	assert.NoError(t, err)
	assert.True(t, errorHandler.InternalError.Equals(receivedError))

	if t.Failed() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("  ", "  ")
		enc.Encode(receivedError)

	}
}

func Test_ErrorHandler_stdlib_SendServiceError(t *testing.T) {
	r := http.NewServeMux()
	r.Handle("GET /", func() http.Handler {
		nextFn := func(w http.ResponseWriter, r *http.Request) {
			errorChannel := r.Context().Value(ErrorChannelName).(chan interface{})
			errorChannel <- errorHandler.NotFound
		}
		return ErrorHandler{}.Handler(http.HandlerFunc(nextFn))
	}())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	res := rec.Result()

	assert.Equal(t, int(errorHandler.NotFound.Status), res.StatusCode)

	var receivedError types.ServiceError
	err := json.Unmarshal(rec.Body.Bytes(), &receivedError)
	assert.NoError(t, err)
	assert.True(t, errorHandler.NotFound.Equals(receivedError))

	if t.Failed() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("  ", "  ")
		enc.Encode(receivedError)

	}
}

func Test_ErrorHandler_stdlib_InvalidTypeSupplied(t *testing.T) {
	r := http.NewServeMux()
	r.Handle("GET /", func() http.Handler {
		nextFn := func(w http.ResponseWriter, r *http.Request) {
			errorChannel := r.Context().Value(ErrorChannelName).(chan interface{})
			errorChannel <- "this should result in an error 999"
		}
		return ErrorHandler{}.Handler(http.HandlerFunc(nextFn))
	}())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	res := rec.Result()

	assert.Equal(t, int(errorHandler.InvalidTypeProvided.Status), res.StatusCode)

	var receivedError types.ServiceError
	err := json.Unmarshal(rec.Body.Bytes(), &receivedError)
	assert.NoError(t, err)
	assert.True(t, errorHandler.InvalidTypeProvided.Equals(receivedError))

	if t.Failed() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("  ", "  ")
		enc.Encode(receivedError)

	}
}
