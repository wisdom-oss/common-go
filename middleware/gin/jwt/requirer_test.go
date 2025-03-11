// nolint
package jwt

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/thanhpk/randstr"

	jwt2 "github.com/lestrrat-go/jwx/v2/jwt"

	internal "github.com/wisdom-oss/common-go/v3/internal/jwt"
	"github.com/wisdom-oss/common-go/v3/types"
)

const scopePrefix = "testing"

func _require_read_no_scope(t *testing.T) {
	expectedError := internal.ErrForbidden

	b := jwt.NewBuilder()
	b.Subject(randstr.Base62(512))
	b.NotBefore(time.Now().Add(-1 * time.Minute))
	b.IssuedAt(time.Now())
	b.Issuer("test")
	b.Audience([]string{"correct-audience"})
	b.Expiration(time.Now().Add(5 * time.Minute))
	b.Claim("scopes", []string{})

	token, err := b.Build()
	assert.NoError(t, err)

	s := jwt2.NewSerializer()
	s.Sign(jwt2.WithKey(jwa.HS256, key))

	serializedToken, err := s.Serialize(token)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+string(serializedToken))
	r.Handler().ServeHTTP(res, req)

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

func _require_read(t *testing.T) {

	b := jwt.NewBuilder()
	b.Subject(randstr.Base62(512))
	b.NotBefore(time.Now().Add(-1 * time.Minute))
	b.IssuedAt(time.Now())
	b.Issuer("test")
	b.Audience([]string{"correct-audience"})
	b.Expiration(time.Now().Add(5 * time.Minute))
	b.Claim("scopes", []string{scopePrefix + ":read"})

	token, err := b.Build()
	assert.NoError(t, err)

	s := jwt2.NewSerializer()
	s.Sign(jwt2.WithKey(jwa.HS256, key))

	serializedToken, err := s.Serialize(token)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+string(serializedToken))
	r.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
}

func _require_write_no_scope(t *testing.T) {
	expectedError := internal.ErrForbidden

	b := jwt.NewBuilder()
	b.Subject(randstr.Base62(512))
	b.NotBefore(time.Now().Add(-1 * time.Minute))
	b.IssuedAt(time.Now())
	b.Issuer("test")
	b.Audience([]string{"correct-audience"})
	b.Expiration(time.Now().Add(5 * time.Minute))
	b.Claim("scopes", []string{})

	token, err := b.Build()
	assert.NoError(t, err)

	s := jwt2.NewSerializer()
	s.Sign(jwt2.WithKey(jwa.HS256, key))

	serializedToken, err := s.Serialize(token)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+string(serializedToken))
	r.Use(sr.RequireWrite)
	r.Handler().ServeHTTP(res, req)

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

func _require_write(t *testing.T) {

	b := jwt.NewBuilder()
	b.Subject(randstr.Base62(512))
	b.NotBefore(time.Now().Add(-1 * time.Minute))
	b.IssuedAt(time.Now())
	b.Issuer("test")
	b.Audience([]string{"correct-audience"})
	b.Expiration(time.Now().Add(5 * time.Minute))
	b.Claim("scopes", []string{scopePrefix + ":write"})

	token, err := b.Build()
	assert.NoError(t, err)

	s := jwt2.NewSerializer()
	s.Sign(jwt2.WithKey(jwa.HS256, key))

	serializedToken, err := s.Serialize(token)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+string(serializedToken))
	r.Use(sr.RequireWrite)
	r.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
}

func _require_delete_no_scope(t *testing.T) {
	expectedError := internal.ErrForbidden

	b := jwt.NewBuilder()
	b.Subject(randstr.Base62(512))
	b.NotBefore(time.Now().Add(-1 * time.Minute))
	b.IssuedAt(time.Now())
	b.Issuer("test")
	b.Audience([]string{"correct-audience"})
	b.Expiration(time.Now().Add(5 * time.Minute))
	b.Claim("scopes", []string{})

	token, err := b.Build()
	assert.NoError(t, err)

	s := jwt2.NewSerializer()
	s.Sign(jwt2.WithKey(jwa.HS256, key))

	serializedToken, err := s.Serialize(token)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+string(serializedToken))
	r.Use(sr.RequireDelete)
	r.Handler().ServeHTTP(res, req)

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

func _require_delete(t *testing.T) {

	b := jwt.NewBuilder()
	b.Subject(randstr.Base62(512))
	b.NotBefore(time.Now().Add(-1 * time.Minute))
	b.IssuedAt(time.Now())
	b.Issuer("test")
	b.Audience([]string{"correct-audience"})
	b.Expiration(time.Now().Add(5 * time.Minute))
	b.Claim("scopes", []string{scopePrefix + ":delete"})

	token, err := b.Build()
	assert.NoError(t, err)

	s := jwt2.NewSerializer()
	s.Sign(jwt2.WithKey(jwa.HS256, key))

	serializedToken, err := s.Serialize(token)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+string(serializedToken))
	r.Use(sr.RequireDelete)
	r.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
}

func _require_admin_no_scope(t *testing.T) {
	expectedError := internal.ErrForbidden

	b := jwt.NewBuilder()
	b.Subject(randstr.Base62(512))
	b.NotBefore(time.Now().Add(-1 * time.Minute))
	b.IssuedAt(time.Now())
	b.Issuer("test")
	b.Audience([]string{"correct-audience"})
	b.Expiration(time.Now().Add(5 * time.Minute))
	b.Claim("scopes", []string{})

	token, err := b.Build()
	assert.NoError(t, err)

	s := jwt2.NewSerializer()
	s.Sign(jwt2.WithKey(jwa.HS256, key))

	serializedToken, err := s.Serialize(token)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+string(serializedToken))
	r.Use(sr.RequireAdministrator)
	r.Handler().ServeHTTP(res, req)

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

func _require_admin(t *testing.T) {

	b := jwt.NewBuilder()
	b.Subject(randstr.Base62(512))
	b.NotBefore(time.Now().Add(-1 * time.Minute))
	b.IssuedAt(time.Now())
	b.Issuer("test")
	b.Audience([]string{"correct-audience"})
	b.Expiration(time.Now().Add(5 * time.Minute))
	b.Claim("scopes", []string{"*:*"})

	token, err := b.Build()
	assert.NoError(t, err)

	s := jwt2.NewSerializer()
	s.Sign(jwt2.WithKey(jwa.HS256, key))

	serializedToken, err := s.Serialize(token)
	assert.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+string(serializedToken))
	r.Use(sr.RequireAdministrator)
	r.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
}
