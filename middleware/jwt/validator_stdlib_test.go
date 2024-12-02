//go:build wisdom_stdlib

package jwt_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwt2 "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/thanhpk/randstr"
	"github.com/wisdom-oss/common-go/v3/middleware/jwt"
	"github.com/wisdom-oss/common-go/v3/types"
)

var r *http.ServeMux
var jwkTestingKey = []byte("testing-key")
var key jwk.Key
var keySet jwk.Set
var v *jwt.Validator

func handler(t *testing.T) {
	r = http.NewServeMux()
	var err error
	key, err = jwk.FromRaw(jwkTestingKey)
	assert.NoError(t, err)

	jwk.AssignKeyID(key)
	key.Set(jwk.KeyUsageKey, "sig")
	key.Set(jwk.AlgorithmKey, jwa.HS256)

	keySet = jwk.NewSet()
	keySet.AddKey(key)

	v = &jwt.Validator{}
	err = v.Configure("test", keySet, nil)
	assert.NoError(t, err)

	r.Handle("GET /", func() http.Handler {
		nextFn := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
		}
		return v.Handler(http.HandlerFunc(nextFn))
	}())

	t.Run("Missing_Authorization_Header", _missing_authorization_header)
	t.Run("Multiple_Authoritazion_Headers", _multiple_authorization_headers)
	t.Run("Unsupported_Token_Scheme", _unsupported_token_scheme)
	t.Run("Invalid_JWT", _invalid_jwt)
	t.Run("Missing_Claims", _missing_jwt_claims)
	t.Run("Invalid_Claims", _invalid_claim_values)
}

func _missing_authorization_header(t *testing.T) {

	expectedError := jwt.ErrMissingAuthorizationHeader
	expectedErrorBytes, err := json.Marshal(expectedError)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	r.ServeHTTP(res, req)

	bodyContents, err := io.ReadAll(res.Result().Body)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.JSONEq(t, string(expectedErrorBytes), string(bodyContents))
}

func _multiple_authorization_headers(t *testing.T) {
	expectedError := jwt.ErrSingleAuthorizationHeaderOnly

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "header-1")
	req.Header.Add("Authorization", "header-2")
	req.Header.Add("Authorization", "header-3")
	r.ServeHTTP(res, req)

	var receviedError types.ServiceError
	err := json.NewDecoder(res.Body).Decode(&receviedError)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.True(t, receviedError.Equals(expectedError))
}

func _unsupported_token_scheme(t *testing.T) {
	expectedError := jwt.ErrUnsupportedTokenScheme

	addition := randstr.Base64(48)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer"+addition)
	r.ServeHTTP(res, req)

	var receviedError types.ServiceError
	err := json.NewDecoder(res.Body).Decode(&receviedError)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.True(t, receviedError.Equals(expectedError))
}

func _invalid_jwt(t *testing.T) {
	expectedError := jwt.ErrJWTMalformed

	addition := randstr.Base64(48)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+addition)
	r.ServeHTTP(res, req)

	var receviedError types.ServiceError
	err := json.NewDecoder(res.Body).Decode(&receviedError)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.True(t, receviedError.Equals(expectedError))
}

func _missing_jwt_claims(t *testing.T) {
	t.Run("Subject", _jwt_missing_sub_claim)
	t.Run("Issued_At", _jwt_missing_issued_at_claim)
	t.Run("Not_Before", _jwt_missing_not_before_claim)
	t.Run("Issuer", _jwt_missing_issuer_claim)
	t.Run("Audience", _jwt_missing_audience_claim)
	t.Run("Expiration", _jwt_missing_expiration_claim)
}

func _jwt_missing_sub_claim(t *testing.T) {
	expectedError := jwt.ErrJWTMissingRequiredClaim

	b := jwt2.NewBuilder()
	b.IssuedAt(time.Now())
	b.NotBefore(time.Now())
	b.Issuer("test")
	b.Audience([]string{"tests"})
	b.Claim("scopes", []string{"testing"})

	token, err := b.Build()
	assert.NoError(t, err)

	s := jwt2.NewSerializer()
	s.Sign(jwt2.WithKey(jwa.HS256, key))

	serializedToken, err := s.Serialize(token)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+string(serializedToken))
	r.ServeHTTP(res, req)

	var receviedError types.ServiceError
	err = json.NewDecoder(res.Body).Decode(&receviedError)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.True(t, receviedError.Equals(expectedError))

	if t.Failed() {
		t.Logf("==== Received Error ====\n\n%v", receviedError)
		t.Logf("==== Expected Error ====\n\n%v", expectedError)
	}
}

func _jwt_missing_issued_at_claim(t *testing.T) {
	expectedError := jwt.ErrJWTMissingRequiredClaim

	b := jwt2.NewBuilder()
	b.Subject(randstr.Base62(512))
	b.NotBefore(time.Now())
	b.Issuer("test")
	b.Audience([]string{"tests"})
	b.Claim("scopes", []string{"testing"})

	token, err := b.Build()
	assert.NoError(t, err)

	s := jwt2.NewSerializer()
	s.Sign(jwt2.WithKey(jwa.HS256, key))

	serializedToken, err := s.Serialize(token)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+string(serializedToken))
	r.ServeHTTP(res, req)

	var receviedError types.ServiceError
	err = json.NewDecoder(res.Body).Decode(&receviedError)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.True(t, receviedError.Equals(expectedError))

	if t.Failed() {
		t.Logf("==== Received Error ====\n\n%v", receviedError)
		t.Logf("==== Expected Error ====\n\n%v", expectedError)
	}
}

func _jwt_missing_not_before_claim(t *testing.T) {
	expectedError := jwt.ErrJWTMissingRequiredClaim

	b := jwt2.NewBuilder()
	b.Subject(randstr.Base62(512))
	b.IssuedAt(time.Now())
	b.Issuer("test")
	b.Audience([]string{"tests"})
	b.Claim("scopes", []string{"testing"})

	token, err := b.Build()
	assert.NoError(t, err)

	s := jwt2.NewSerializer()
	s.Sign(jwt2.WithKey(jwa.HS256, key))

	serializedToken, err := s.Serialize(token)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+string(serializedToken))
	r.ServeHTTP(res, req)

	var receviedError types.ServiceError
	err = json.NewDecoder(res.Body).Decode(&receviedError)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.True(t, receviedError.Equals(expectedError))

	if t.Failed() {
		t.Logf("==== Received Error ====\n\n%v", receviedError)
		t.Logf("==== Expected Error ====\n\n%v", expectedError)
	}
}

func _jwt_missing_issuer_claim(t *testing.T) {
	expectedError := jwt.ErrJWTInvalidIssuer

	b := jwt2.NewBuilder()
	b.Subject(randstr.Base62(512))
	b.NotBefore(time.Now())
	b.IssuedAt(time.Now())
	b.Audience([]string{"tests"})
	b.Claim("scopes", []string{"testing"})

	token, err := b.Build()
	assert.NoError(t, err)

	s := jwt2.NewSerializer()
	s.Sign(jwt2.WithKey(jwa.HS256, key))

	serializedToken, err := s.Serialize(token)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+string(serializedToken))
	r.ServeHTTP(res, req)

	var receviedError types.ServiceError
	err = json.NewDecoder(res.Body).Decode(&receviedError)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.True(t, receviedError.Equals(expectedError))

	if t.Failed() {
		t.Logf("==== Received Error ====\n\n%v", receviedError)
		t.Logf("==== Expected Error ====\n\n%v", expectedError)
	}
}

func _jwt_missing_audience_claim(t *testing.T) {
	expectedError := jwt.ErrJWTMissingRequiredClaim

	b := jwt2.NewBuilder()
	b.Subject(randstr.Base62(512))
	b.NotBefore(time.Now())
	b.IssuedAt(time.Now())
	b.Issuer("test")
	b.Claim("scopes", []string{"testing"})

	token, err := b.Build()
	assert.NoError(t, err)

	s := jwt2.NewSerializer()
	s.Sign(jwt2.WithKey(jwa.HS256, key))

	serializedToken, err := s.Serialize(token)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+string(serializedToken))
	r.ServeHTTP(res, req)

	var receviedError types.ServiceError
	err = json.NewDecoder(res.Body).Decode(&receviedError)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.True(t, receviedError.Equals(expectedError))

	if t.Failed() {
		t.Logf("==== Received Error ====\n\n%v", receviedError)
		t.Logf("==== Expected Error ====\n\n%v", expectedError)
	}
}

func _jwt_missing_expiration_claim(t *testing.T) {
	expectedError := jwt.ErrJWTMissingRequiredClaim

	b := jwt2.NewBuilder()
	b.Subject(randstr.Base62(512))
	b.NotBefore(time.Now())
	b.IssuedAt(time.Now())
	b.Issuer("test")
	b.Audience([]string{"wrong-audience"})
	b.Claim("scopes", []string{"testing"})

	token, err := b.Build()
	assert.NoError(t, err)

	s := jwt2.NewSerializer()
	s.Sign(jwt2.WithKey(jwa.HS256, key))

	serializedToken, err := s.Serialize(token)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+string(serializedToken))
	r.ServeHTTP(res, req)

	var receviedError types.ServiceError
	err = json.NewDecoder(res.Body).Decode(&receviedError)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.True(t, receviedError.Equals(expectedError))

	if t.Failed() {
		t.Logf("==== Received Error ====\n\n%v", receviedError)
		t.Logf("==== Expected Error ====\n\n%v", expectedError)
	}
}

func _invalid_claim_values(t *testing.T) {
	v.RequireAudiences([]string{"correct-audience"})

	t.Run("Audience", _jwt_invalid_audience_claim)
	t.Run("Issuer", _jwt_invalid_issuer_claim)
	t.Run("Expiration", _jwt_invalid_expiration_claim)
	t.Run("Issued_At", _jwt_invalid_issued_at_claim)
	t.Run("Not_Before", _jwt_invalid_not_before_claim)

	v.DisableAudienceCheck()
}

func _jwt_invalid_audience_claim(t *testing.T) {
	expectedError := jwt.ErrJWTInvalidAudience

	b := jwt2.NewBuilder()
	b.Subject(randstr.Base62(512))
	b.NotBefore(time.Now())
	b.IssuedAt(time.Now())
	b.Issuer("test")
	b.Audience([]string{"wrong-audience"})
	b.Expiration(time.Now().Add(5 * time.Minute))
	b.Claim("scopes", []string{"testing"})

	token, err := b.Build()
	assert.NoError(t, err)

	s := jwt2.NewSerializer()
	s.Sign(jwt2.WithKey(jwa.HS256, key))

	serializedToken, err := s.Serialize(token)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+string(serializedToken))
	r.ServeHTTP(res, req)

	var receviedError types.ServiceError
	err = json.NewDecoder(res.Body).Decode(&receviedError)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.True(t, receviedError.Equals(expectedError))

	if t.Failed() {
		t.Logf("==== Received Error ====\n\n%v", receviedError)
		t.Logf("==== Expected Error ====\n\n%v", expectedError)
	}
}

func _jwt_invalid_issuer_claim(t *testing.T) {
	expectedError := jwt.ErrJWTInvalidIssuer

	b := jwt2.NewBuilder()
	b.Subject(randstr.Base62(512))
	b.NotBefore(time.Now())
	b.IssuedAt(time.Now())
	b.Issuer("wrong-issuer")
	b.Audience([]string{"correct-audience"})
	b.Expiration(time.Now().Add(5 * time.Minute))
	b.Claim("scopes", []string{"testing"})

	token, err := b.Build()
	assert.NoError(t, err)

	s := jwt2.NewSerializer()
	s.Sign(jwt2.WithKey(jwa.HS256, key))

	serializedToken, err := s.Serialize(token)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+string(serializedToken))
	r.ServeHTTP(res, req)

	var receviedError types.ServiceError
	err = json.NewDecoder(res.Body).Decode(&receviedError)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.True(t, receviedError.Equals(expectedError))

	if t.Failed() {
		t.Logf("==== Received Error ====\n\n%v", receviedError)
		t.Logf("==== Expected Error ====\n\n%v", expectedError)
	}
}

func _jwt_invalid_expiration_claim(t *testing.T) {
	expectedError := jwt.ErrJWTExpired

	b := jwt2.NewBuilder()
	b.Subject(randstr.Base62(512))
	b.NotBefore(time.Now())
	b.IssuedAt(time.Now())
	b.Issuer("test")
	b.Audience([]string{"correct-audience"})
	b.Expiration(time.Now().Add(-5 * time.Minute))
	b.Claim("scopes", []string{"testing"})

	token, err := b.Build()
	assert.NoError(t, err)

	s := jwt2.NewSerializer()
	s.Sign(jwt2.WithKey(jwa.HS256, key))

	serializedToken, err := s.Serialize(token)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+string(serializedToken))
	r.ServeHTTP(res, req)

	var receviedError types.ServiceError
	err = json.NewDecoder(res.Body).Decode(&receviedError)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.True(t, receviedError.Equals(expectedError))

	if t.Failed() {
		t.Logf("==== Received Error ====\n\n%v", receviedError)
		t.Logf("==== Expected Error ====\n\n%v", expectedError)
	}
}

func _jwt_invalid_issued_at_claim(t *testing.T) {
	expectedError := jwt.ErrJWTNotCreatedYet

	b := jwt2.NewBuilder()
	b.Subject(randstr.Base62(512))
	b.NotBefore(time.Now())
	b.IssuedAt(time.Now().Add(5 * time.Minute))
	b.Issuer("test")
	b.Audience([]string{"correct-audience"})
	b.Expiration(time.Now().Add(5 * time.Minute))
	b.Claim("scopes", []string{"testing"})

	token, err := b.Build()
	assert.NoError(t, err)

	s := jwt2.NewSerializer()
	s.Sign(jwt2.WithKey(jwa.HS256, key))

	serializedToken, err := s.Serialize(token)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+string(serializedToken))
	r.ServeHTTP(res, req)

	var receviedError types.ServiceError
	err = json.NewDecoder(res.Body).Decode(&receviedError)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.True(t, receviedError.Equals(expectedError))

	if t.Failed() {
		t.Logf("==== Received Error ====\n\n%v", receviedError)
		t.Logf("==== Expected Error ====\n\n%v", expectedError)
	}
}

func _jwt_invalid_not_before_claim(t *testing.T) {
	expectedError := jwt.ErrJWTNotYetValid

	b := jwt2.NewBuilder()
	b.Subject(randstr.Base62(512))
	b.NotBefore(time.Now().Add(5 * time.Minute))
	b.IssuedAt(time.Now())
	b.Issuer("test")
	b.Audience([]string{"correct-audience"})
	b.Expiration(time.Now().Add(5 * time.Minute))
	b.Claim("scopes", []string{"testing"})

	token, err := b.Build()
	assert.NoError(t, err)

	s := jwt2.NewSerializer()
	s.Sign(jwt2.WithKey(jwa.HS256, key))

	serializedToken, err := s.Serialize(token)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+string(serializedToken))
	r.ServeHTTP(res, req)

	var receviedError types.ServiceError
	err = json.NewDecoder(res.Body).Decode(&receviedError)
	assert.NoError(t, err)

	assert.Equal(t, int(expectedError.Status), res.Code)
	assert.True(t, receviedError.Equals(expectedError))

	if t.Failed() {
		t.Logf("==== Received Error ====\n\n%v", receviedError)
		t.Logf("==== Expected Error ====\n\n%v", expectedError)
	}
}
