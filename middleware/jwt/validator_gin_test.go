//go:build !wisdom_stdlib

package jwt_test

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/thanhpk/randstr"
	"github.com/wisdom-oss/common-go/v3/middleware/jwt"
)

var r *gin.Engine
var jwkTestingKey = []byte("testing-key")
var keySet jwk.Set

func handler(t *testing.T) {
	r = gin.New()

	var err error
	keySet, err = jwk.Parse(jwkTestingKey)
	assert.NoError(t, err)

	var v jwt.Validator
	err = v.Configure("test", keySet, nil)
	assert.NoError(t, err)

	r.Use(v.Handler)

	t.Run("Missing_Authorization_Header", _missing_authorization_header)
	t.Run("Multiple_Authoritazion_Headers", _multiple_authorization_headers)
	t.Run("Unsupported_Token_Scheme", _unsupported_token_scheme)
	t.Run("Invalid_JWT", _invalid_jwt)
	t.Run("[MISSING_CLAIMS] Subject", _jwt_missing_sub_claim)
}

func _missing_authorization_header(t *testing.T) {

	expectedError := jwt.ErrMissingAuthorizationHeader
	expectedErrorBytes, err := json.Marshal(expectedError)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	r.Handler().ServeHTTP(res, req)

	bodyContents, err := io.ReadAll(res.Result().Body)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.JSONEq(t, string(expectedErrorBytes), string(bodyContents))
}

func _multiple_authorization_headers(t *testing.T) {
	expectedError := jwt.ErrSingleAuthorizationHeaderOnly
	expectedErrorBytes, err := json.Marshal(expectedError)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "header-1")
	req.Header.Add("Authorization", "header-2")
	req.Header.Add("Authorization", "header-3")
	r.Handler().ServeHTTP(res, req)

	bodyContents, err := io.ReadAll(res.Result().Body)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.JSONEq(t, string(expectedErrorBytes), string(bodyContents))
}

func _unsupported_token_scheme(t *testing.T) {
	expectedError := jwt.ErrUnsupportedTokenScheme
	expectedErrorBytes, err := json.Marshal(expectedError)
	assert.NoError(t, err)

	addition := randstr.Base64(48)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer"+addition)
	r.Handler().ServeHTTP(res, req)

	bodyContents, err := io.ReadAll(res.Result().Body)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.JSONEq(t, string(expectedErrorBytes), string(bodyContents))
}

func _invalid_jwt(t *testing.T) {
	expectedError := jwt.ErrJWTMalformed
	expectedErrorBytes, err := json.Marshal(expectedError)
	assert.NoError(t, err)

	addition := randstr.Base64(48)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+addition)
	r.Handler().ServeHTTP(res, req)

	bodyContents, err := io.ReadAll(res.Result().Body)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.JSONEq(t, string(expectedErrorBytes), string(bodyContents))
}

func _jwt_missing_sub_claim(t *testing.T) {
	expectedError := jwt.ErrJWTMissingRequiredClaim
	expectedErrorBytes, err := json.Marshal(expectedError)
	assert.NoError(t, err)

	

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+)
	r.Handler().ServeHTTP(res, req)

	bodyContents, err := io.ReadAll(res.Result().Body)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.JSONEq(t, string(expectedErrorBytes), string(bodyContents))
}
