package middleware

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"

	"github.com/wisdom-oss/common-go/tests"
	"github.com/wisdom-oss/common-go/types"
)

var errorMap = map[string]types.ServiceError{
	"WISDOM_TEST": {
		Type:   "WISDOM_TEST",
		Status: 400,
		Title:  "Bad Request",
		Detail: "This is only a test",
	},
}

var nativeError = errors.New("this is a native error")
var r chi.Router
var request *http.Request

func TestMain(m *testing.M) {
	r = chi.NewRouter()
	r.Use(ErrorHandler)

	request = httptest.NewRequest(http.MethodGet, "/", nil)

	os.Exit(m.Run())
}

func TestErrorHandler_NativeError(t *testing.T) {
	recorder := httptest.NewRecorder()

	r.Get("/", func(writer http.ResponseWriter, r *http.Request) {
		errorChannel := r.Context().Value(ErrorChannelName).(chan interface{})
		errorChannel <- nativeError
	})

	r.ServeHTTP(recorder, request)
	res := recorder.Result()

	if res.StatusCode != http.StatusInternalServerError {
		t.Errorf("response status is incorrect, got %d, expected, %d", res.StatusCode, http.StatusInternalServerError)
	}

	if res.Header.Get("Content-Type") != types.ErrorContentType {
		t.Errorf("response content type is incorrect, got '%s', expected '%s'", res.Header.Get("Content-Type"), "application/problem+json")
	}

	var response map[string]interface{}
	err := json.NewDecoder(res.Body).Decode(&response)
	if err != nil {
		t.Errorf("response could not be decoded: %s", err.Error())
	}
	tests.ErrorRfc9457Compliant(response, t)
	tests.ErrorOriginatedFromHost(response, t)

	_, validType := response["errors"].([]interface{})
	assert.Truef(t, validType, `rfc9457 extension violated, expected 'errors' field to be '[]string', got '%T'`, response["errors"])
	assert.Contains(t, response["errors"].([]interface{}), nativeError.Error())
}

func TestErrorHandler_WISdoMError(t *testing.T) {
	recorder := httptest.NewRecorder()

	r.Get("/", func(writer http.ResponseWriter, r *http.Request) {
		errorChannel := r.Context().Value(ErrorChannelName).(chan interface{})

		errorChannel <- errorMap["WISDOM_TEST"]
	})

	r.ServeHTTP(recorder, request)
	res := recorder.Result()

	if res.StatusCode != int(errorMap["WISDOM_TEST"].Status) {
		t.Errorf("response is incorrect, got %d, expected %d", res.StatusCode, errorMap["WISDOM_TEST"].Status)
	}

	if res.Header.Get("Content-Type") != types.ErrorContentType {
		t.Errorf("response content type is incorrect, got '%s', expected '%s'", res.Header.Get("Content-Type"), "application/problem+json")
	}

	var response map[string]interface{}
	err := json.NewDecoder(res.Body).Decode(&response)
	if err != nil {
		t.Errorf("response could not be decoded: %s", err.Error())
	}

	tests.ErrorRfc9457Compliant(response, t)
	tests.ErrorOriginatedFromHost(response, t)

	if response["type"].(string) != errorMap["WISDOM_TEST"].Type {
		t.Errorf("type field wrong, got '%s', expected '%s'", response["type"].(string), errorMap["WISDOM_TEST"].Type)
	}

	if response["title"].(string) != errorMap["WISDOM_TEST"].Title {
		t.Errorf("title field wrong, got '%s', expected '%s'", response["title"].(string), errorMap["WISDOM_TEST"].Title)
	}

	if response["detail"].(string) != errorMap["WISDOM_TEST"].Detail {
		t.Errorf("detail field wrong, got '%s', expected '%s'", response["detail"].(string), errorMap["WISDOM_TEST"].Detail)
	}
}

func TestErrorHandler_InvalidTypeSupplied(t *testing.T) {
	recorder := httptest.NewRecorder()

	r.Get("/", func(writer http.ResponseWriter, r *http.Request) {
		errorChannel := r.Context().Value(ErrorChannelName).(chan interface{})

		errorChannel <- "invalid-type"
	})

	r.ServeHTTP(recorder, request)
	res := recorder.Result()

	if res.StatusCode != 999 {
		t.Errorf("response status is incorrect, got %d, expected, %d", res.StatusCode, http.StatusInternalServerError)
	}

	if res.Header.Get("Content-Type") != types.ErrorContentType {
		t.Errorf("response content type is incorrect, got '%s', expected '%s'", res.Header.Get("Content-Type"), "application/problem+json")
	}

	var response map[string]interface{}
	err := json.NewDecoder(res.Body).Decode(&response)
	if err != nil {
		t.Errorf("response could not be decoded: %s", err.Error())
	}
	tests.ErrorRfc9457Compliant(response, t)
	tests.ErrorOriginatedFromHost(response, t)

}

func TestErrorHandler_Panic(t *testing.T) {
	recorder := httptest.NewRecorder()

	r.Get("/", func(writer http.ResponseWriter, r *http.Request) {
		panic("test")
	})

	r.ServeHTTP(recorder, request)
	res := recorder.Result()

	if res.StatusCode != http.StatusInternalServerError {
		t.Errorf("response status is incorrect, got %d, expected, %d", res.StatusCode, http.StatusInternalServerError)
	}

	if res.Header.Get("Content-Type") != types.ErrorContentType {
		t.Errorf("response content type is incorrect, got '%s', expected '%s'", res.Header.Get("Content-Type"), "application/problem+json")
	}

	var response map[string]interface{}
	err := json.NewDecoder(res.Body).Decode(&response)
	if err != nil {
		t.Errorf("response could not be decoded: %s", err.Error())
	}
	tests.ErrorRfc9457Compliant(response, t)
	tests.ErrorOriginatedFromHost(response, t)

	_, validType := response["errors"].([]interface{})
	assert.Truef(t, validType, `rfc9457 extension violated, expected 'errors' field to be '[]string', got '%T'`, response["errors"])
	assert.Contains(t, response["errors"].([]interface{}), "test")

}

func TestErrorHandler_NoError(t *testing.T) {
	recorder := httptest.NewRecorder()

	r.Get("/", func(writer http.ResponseWriter, r *http.Request) {
		writer.Write([]byte("test"))
	})

	r.ServeHTTP(recorder, request)
	res := recorder.Result()

	if res.StatusCode != http.StatusOK {
		t.Errorf("response status is incorrect, got %d, expected, %d", res.StatusCode, http.StatusOK)
	}

	expected := "test"
	reponseContents, _ := io.ReadAll(res.Body)
	if string(reponseContents) != expected {
		t.Errorf("response content is incorrect, got '%s', expected '%s'", string(reponseContents), expected)
	}

}
