package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"

	"github.com/wisdom-oss/common-go/tests"
	"github.com/wisdom-oss/common-go/types"
)

func TestConfigurationIssuerInvalidURI(t *testing.T) {
	var validator JWTValidator
	err := validator.Configure("test")
	assert.Nil(t, err)
	assert.Equal(t, "test", validator.issuer)
	assert.False(t, validator.validateJWKS)
	assert.Nil(t, validator.jwks)
}

func TestConfigurationIssuerHTTP(t *testing.T) {
	var validator JWTValidator
	err := validator.Configure("http://auth.wisdom-demo.uol.de/application/o/oidc-tests/")
	assert.Nil(t, err)
	assert.NotNil(t, validator.jwks)
	assert.Equal(t, "http://auth.wisdom-demo.uol.de/application/o/oidc-tests/", validator.issuer)
}

func TestConfigurationIssuerHTTPS(t *testing.T) {
	var validator JWTValidator
	err := validator.Configure("https://auth.wisdom-demo.uol.de/application/o/oidc-tests/")
	assert.Nil(t, err)
	assert.NotNil(t, validator.jwks)
	assert.Equal(t, "https://auth.wisdom-demo.uol.de/application/o/oidc-tests/", validator.issuer)
}

func prepareChi() *chi.Mux {
	validator := JWTValidator{}
	_ = validator.Configure("tests")
	r := chi.NewRouter()
	r.Use(validator.Handler)
	r.Get("/", func(writer http.ResponseWriter, request *http.Request) {

	})
	return r
}

func TestAuthorization_MissingHeader(t *testing.T) {
	r := prepareChi()
	expectedError := &ErrMissingAuthorizationHeader

	request := httptest.NewRequest(http.MethodGet, "/", nil)

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, request)
	res := recorder.Result()

	if res.StatusCode != int(expectedError.Status) {
		t.Errorf("Expected status code %d, but got %d", int(expectedError.Status), res.StatusCode)
	}

	// now check if the response is RFC 9457 compliant
	var byteBuf bytes.Buffer
	body := io.TeeReader(res.Body, &byteBuf)

	var response map[string]interface{}
	err := json.NewDecoder(body).Decode(&response)
	if err != nil {
		t.Errorf("response could not be decoded: %s", err.Error())
	}

	tests.ErrorRfc9457Compliant(response, t)
	tests.ErrorOriginatedFromHost(response, t)

	var parsedError types.ServiceError
	err = json.NewDecoder(&byteBuf).Decode(&parsedError)
	if err != nil {
		t.Errorf("response could not be decoded: %s", err.Error())
	}

	if !parsedError.Equals(*expectedError) {
		t.Errorf("Expected error %v, but got %v", *expectedError, parsedError)
	}
}

func TestAuthorization_WrongSchema(t *testing.T) {
	r := prepareChi()
	expectedError := &ErrUnsupportedTokenScheme

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", fmt.Sprintf("WRONG_FORMAT abc"))

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, request)
	res := recorder.Result()

	if res.StatusCode != int(expectedError.Status) {
		t.Errorf("Expected status code %d, but got %d", int(expectedError.Status), res.StatusCode)
	}

	// now check if the response is RFC 9457 compliant
	var byteBuf bytes.Buffer
	body := io.TeeReader(res.Body, &byteBuf)

	var response map[string]interface{}
	err := json.NewDecoder(body).Decode(&response)
	if err != nil {
		t.Errorf("response could not be decoded: %s", err.Error())
	}

	tests.ErrorRfc9457Compliant(response, t)
	tests.ErrorOriginatedFromHost(response, t)

	var parsedError types.ServiceError
	err = json.NewDecoder(&byteBuf).Decode(&parsedError)
	if err != nil {
		t.Errorf("response could not be decoded to WISdoMError: %s", err.Error())
	}

	if !parsedError.Equals(*expectedError) {
		t.Errorf("Expected error %v, but got %v", *expectedError, parsedError)
	}
}

func TestAuthorization_MalformedJWT(t *testing.T) {
	r := prepareChi()
	expectedError := &ErrJWTMalformed

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer abc"))

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, request)
	res := recorder.Result()

	if res.StatusCode != int(expectedError.Status) {
		t.Errorf("Expected status code %d, but got %d", http.StatusUnauthorized, res.StatusCode)
	}

	// now check if the response is RFC 9457 compliant
	var byteBuf bytes.Buffer
	body := io.TeeReader(res.Body, &byteBuf)

	var response map[string]interface{}
	err := json.NewDecoder(body).Decode(&response)
	if err != nil {
		t.Errorf("response could not be decoded: %s", err.Error())
	}

	tests.ErrorRfc9457Compliant(response, t)
	tests.ErrorOriginatedFromHost(response, t)

	var parsedError types.ServiceError
	err = json.NewDecoder(&byteBuf).Decode(&parsedError)
	if err != nil {
		t.Errorf("response could not be decoded to WISdoMError: %s", err.Error())
	}

	if !parsedError.Equals(*expectedError) {
		t.Errorf("Expected error %v, but got %v", *expectedError, parsedError)
	}

}

func TestAuthorization_ExpiredJWT(t *testing.T) {
	r := prepareChi()
	expectedError := &ErrJWTExpired

	// generate a JWT which is only expired
	serviceTokenBuilder := jwt.NewBuilder()
	serviceTokenBuilder.Expiration(time.Now().Add(-1 * time.Minute))
	serviceToken, err := serviceTokenBuilder.Build()
	serializer := jwt.NewSerializer()
	token, _ := serializer.Serialize(serviceToken)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, request)
	res := recorder.Result()

	if res.StatusCode != int(expectedError.Status) {
		t.Errorf("Expected status code %d, but got %d", int(expectedError.Status), res.StatusCode)
	}

	// now check if the response is RFC 9457 compliant
	var byteBuf bytes.Buffer
	body := io.TeeReader(res.Body, &byteBuf)

	var response map[string]interface{}
	err = json.NewDecoder(body).Decode(&response)
	if err != nil {
		t.Errorf("response could not be decoded: %s", err.Error())
	}

	tests.ErrorRfc9457Compliant(response, t)
	tests.ErrorOriginatedFromHost(response, t)

	var parsedError types.ServiceError
	err = json.NewDecoder(&byteBuf).Decode(&parsedError)
	if err != nil {
		t.Errorf("response could not be decoded to WISdoMError: %s", err.Error())
	}

	if !parsedError.Equals(*expectedError) {
		t.Errorf("Expected error %v, but got %v", *expectedError, parsedError)
	}

}

func TestAuthorization_JWTNotValidYet(t *testing.T) {
	r := prepareChi()
	expectedError := &ErrJWTNotYetValid

	// generate a JWT which is only expired
	serviceTokenBuilder := jwt.NewBuilder()
	serviceTokenBuilder.NotBefore(time.Now().Add(1 * time.Minute))
	serviceToken, err := serviceTokenBuilder.Build()
	serializer := jwt.NewSerializer()
	token, _ := serializer.Serialize(serviceToken)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, request)
	res := recorder.Result()

	if res.StatusCode != int(expectedError.Status) {
		t.Errorf("Expected status code %d, but got %d", int(expectedError.Status), res.StatusCode)
	}

	var byteBuf bytes.Buffer
	body := io.TeeReader(res.Body, &byteBuf)

	var response map[string]interface{}
	err = json.NewDecoder(body).Decode(&response)
	if err != nil {
		t.Errorf("response could not be decoded: %s", err.Error())
	}

	tests.ErrorRfc9457Compliant(response, t)
	tests.ErrorOriginatedFromHost(response, t)

	var parsedError types.ServiceError
	err = json.NewDecoder(&byteBuf).Decode(&parsedError)
	if err != nil {
		t.Errorf("response could not be decoded to WISdoMError: %s", err.Error())
	}

	if !parsedError.Equals(*expectedError) {
		t.Errorf("Expected error %v, but got %v", *expectedError, parsedError)
	}

}

func TestAuthorization_JWTIssuedInFuture(t *testing.T) {
	r := prepareChi()
	expectedError := &ErrJWTNotCreatedYet

	// generate a JWT which is only expired
	serviceTokenBuilder := jwt.NewBuilder()
	serviceTokenBuilder.IssuedAt(time.Now().Add(1 * time.Minute))
	serviceToken, err := serviceTokenBuilder.Build()
	serializer := jwt.NewSerializer()
	token, _ := serializer.Serialize(serviceToken)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, request)
	res := recorder.Result()

	if res.StatusCode != int(expectedError.Status) {
		t.Errorf("Expected status code %d, but got %d", int(expectedError.Status), res.StatusCode)
	}

	var byteBuf bytes.Buffer
	body := io.TeeReader(res.Body, &byteBuf)

	var response map[string]interface{}
	err = json.NewDecoder(body).Decode(&response)
	if err != nil {
		t.Errorf("response could not be decoded: %s", err.Error())
	}

	tests.ErrorRfc9457Compliant(response, t)
	tests.ErrorOriginatedFromHost(response, t)

	var parsedError types.ServiceError
	err = json.NewDecoder(&byteBuf).Decode(&parsedError)
	if err != nil {
		t.Errorf("response could not be decoded to WISdoMError: %s", err.Error())
	}

	if !parsedError.Equals(*expectedError) {
		t.Errorf("Expected error %v, but got %v", *expectedError, parsedError)
	}

}

func TestAuthorization_JWTInvalidIssuer(t *testing.T) {
	r := prepareChi()
	expectedError := &ErrJWTInvalidIssuer

	// generate a JWT which is only expired
	serviceTokenBuilder := jwt.NewBuilder()
	serviceTokenBuilder.Issuer("wrong-issuer")
	serviceToken, err := serviceTokenBuilder.Build()
	serializer := jwt.NewSerializer()
	token, _ := serializer.Serialize(serviceToken)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, request)
	res := recorder.Result()

	if res.StatusCode != int(expectedError.Status) {
		t.Errorf("Expected status code %d, but got %d", int(expectedError.Status), res.StatusCode)
	}

	var byteBuf bytes.Buffer
	body := io.TeeReader(res.Body, &byteBuf)

	var response map[string]interface{}
	err = json.NewDecoder(body).Decode(&response)
	if err != nil {
		t.Errorf("response could not be decoded: %s", err.Error())
	}

	tests.ErrorRfc9457Compliant(response, t)
	tests.ErrorOriginatedFromHost(response, t)

	var parsedError types.ServiceError
	err = json.NewDecoder(&byteBuf).Decode(&parsedError)
	if err != nil {
		t.Errorf("response could not be decoded to WISdoMError: %s", err.Error())
	}

	if !parsedError.Equals(*expectedError) {
		t.Errorf("Expected error %v, but got %v", *expectedError, parsedError)
	}

}

func TestAuthorization_JWTNoGroups(t *testing.T) {
	r := prepareChi()
	expectedError := &ErrJWTNoGroups

	// generate a JWT which is only expired
	serviceTokenBuilder := jwt.NewBuilder()
	serviceTokenBuilder.Issuer("tests")
	serviceToken, err := serviceTokenBuilder.Build()
	serializer := jwt.NewSerializer()
	token, _ := serializer.Serialize(serviceToken)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, request)
	res := recorder.Result()

	if res.StatusCode != int(expectedError.Status) {
		t.Errorf("Expected status code %d, but got %d", int(expectedError.Status), res.StatusCode)
	}

	var byteBuf bytes.Buffer
	body := io.TeeReader(res.Body, &byteBuf)

	var response map[string]interface{}
	err = json.NewDecoder(body).Decode(&response)
	if err != nil {
		t.Errorf("response could not be decoded: %s", err.Error())
	}

	tests.ErrorRfc9457Compliant(response, t)
	tests.ErrorOriginatedFromHost(response, t)

	var parsedError types.ServiceError
	err = json.NewDecoder(&byteBuf).Decode(&parsedError)
	if err != nil {
		t.Errorf("response could not be decoded to WISdoMError: %s", err.Error())
	}

	if !parsedError.Equals(*expectedError) {
		t.Errorf("Expected error %v, but got %v", *expectedError, parsedError)
	}

}

func TestAuthorization_JWTWrongGroupStaffOverride(t *testing.T) {
	r := prepareChi()

	// generate a JWT which is only expired
	serviceTokenBuilder := jwt.NewBuilder()
	serviceTokenBuilder.Issuer("tests")
	serviceTokenBuilder.Claim("groups", []string{"wrong-group"})
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
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, res.StatusCode)
	}

	if ctxVal, _ := request.Context().Value(staffCtxKey).(string); ctxVal == "true" {
		t.Errorf("Expected auth.group to be %s, but got %v", "true", request.Context().Value(staffCtxKey))
	}

	if request.Context().Value(groupsCtxKey) != nil {
		t.Errorf("Expected auth.group to be nil, but got %v", request.Context().Value(groupsCtxKey))
	}

}

func TestAuthorization_JWTCorrectGroup(t *testing.T) {
	r := prepareChi()

	// generate a JWT which is only expired
	serviceTokenBuilder := jwt.NewBuilder()
	serviceTokenBuilder.Issuer("tests")
	serviceTokenBuilder.Claim("groups", []string{"testing"})
	serviceToken, _ := serviceTokenBuilder.Build()
	serializer := jwt.NewSerializer()
	token, _ := serializer.Serialize(serviceToken)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, request)
	res := recorder.Result()

	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, res.StatusCode)
	}

	if request.Context().Value(staffCtxKey) != nil {
		t.Errorf("Expected auth.admin to be nil, but got %v", request.Context().Value(staffCtxKey))
	}

	if ctxVal, _ := request.Context().Value(groupsCtxKey).(string); ctxVal == "testing" {
		t.Errorf("Expected auth.group to be %s, but got %v", "testing", request.Context().Value(staffCtxKey))
	}
}

func TestAuthorization_CompleteJWT(t *testing.T) {
	r := prepareChi()

	// generate a JWT which is only expired
	serviceTokenBuilder := jwt.NewBuilder()
	serviceTokenBuilder.Issuer("tests")
	serviceTokenBuilder.Expiration(time.Now().Add(1 * time.Minute))
	serviceTokenBuilder.IssuedAt(time.Now().Add(-1 * time.Minute))
	serviceTokenBuilder.Claim("groups", []string{"testing"})
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
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, res.StatusCode)
	}

	if ctxVal, _ := request.Context().Value(staffCtxKey).(bool); ctxVal == true {
		t.Errorf("Expected auth.group to be %s, but got %v", "true", request.Context().Value(staffCtxKey))
	}

	if ctxVal, _ := request.Context().Value(groupsCtxKey).(string); ctxVal == "testing" {
		t.Errorf("Expected auth.group to be %s, but got %v", "testing", request.Context().Value(staffCtxKey))
	}
}
