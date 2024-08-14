package middleware

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/wisdom-oss/common-go/types"
)

func handleRequest(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("success"))
}

func TestRequireScope_ValidatorInactive(t *testing.T) {
	r := chi.NewRouter()
	r.With(RequireScope("testing", types.ScopeRead)).Get("/", handleRequest)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, request)
	res := recorder.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, res.StatusCode)
	}
	if responseBody, _ := io.ReadAll(res.Body); string(responseBody) != "success" {
		t.Errorf("Expected response body %s, got %s", "success", responseBody)
	}
}

func TestRequireScope_MissingScope(t *testing.T) {
	r := prepareChi()
	r.With(RequireScope("testing", types.ScopeRead)).Get("/", handleRequest)

	serviceTokenBuilder := jwt.NewBuilder()
	serviceTokenBuilder.Issuer("tests")
	serviceTokenBuilder.Expiration(time.Now().Add(1 * time.Minute))
	serviceTokenBuilder.IssuedAt(time.Now().Add(-1 * time.Minute))
	serviceTokenBuilder.Claim("groups", []string{"testing:wrong"})
	serviceToken, _ := serviceTokenBuilder.Build()
	serializer := jwt.NewSerializer()
	token, _ := serializer.Serialize(serviceToken)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, request)
	res := recorder.Result()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("Expected status code %d, got %d", http.StatusForbidden, res.StatusCode)
	}
}

func TestRequireScope_CorrectScope(t *testing.T) {
	r := prepareChi()

	r.With(RequireScope("testing", types.ScopeRead)).Get("/", handleRequest)

	serviceTokenBuilder := jwt.NewBuilder()
	serviceTokenBuilder.Issuer("tests")
	serviceTokenBuilder.Expiration(time.Now().Add(1 * time.Minute))
	serviceTokenBuilder.IssuedAt(time.Now().Add(-1 * time.Minute))
	serviceTokenBuilder.Claim("groups", []string{"testing:read"})
	serviceToken, _ := serviceTokenBuilder.Build()
	serializer := jwt.NewSerializer()
	token, _ := serializer.Serialize(serviceToken)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, request)
	res := recorder.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, res.StatusCode)
	}
	if responseBody, _ := io.ReadAll(res.Body); string(responseBody) != "success" {
		t.Errorf("Expected response body %s, got %s", "success", responseBody)
	}
}

func TestRequireScope_StaffOverrideOnWrongScope(t *testing.T) {
	r := prepareChi()
	r.With(RequireScope("testing", types.ScopeRead)).Get("/", handleRequest)

	serviceTokenBuilder := jwt.NewBuilder()
	serviceTokenBuilder.Issuer("tests")
	serviceTokenBuilder.Expiration(time.Now().Add(1 * time.Minute))
	serviceTokenBuilder.IssuedAt(time.Now().Add(-1 * time.Minute))
	serviceTokenBuilder.Claim("groups", []string{"testing:wrong"})
	serviceTokenBuilder.Claim("staff", "true")
	serviceToken, _ := serviceTokenBuilder.Build()
	serializer := jwt.NewSerializer()
	token, _ := serializer.Serialize(serviceToken)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, request)
	res := recorder.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, res.StatusCode)
	}
	if responseBody, _ := io.ReadAll(res.Body); string(responseBody) != "success" {
		t.Errorf("Expected response body %s, got %s", "success", responseBody)
	}
}
