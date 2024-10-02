package middleware

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"

	internal "github.com/wisdom-oss/common-go/v2/internal/validate-jwt"
	"github.com/wisdom-oss/common-go/v2/types"
)

func Fuzz_RequireScope_gin_NoValidator(f *testing.F) {
	f.Add("")
	f.Add("panic")
	f.Add("nope")
	f.Fuzz(func(t *testing.T, scopeName string) {
		r := gin.New()
		r.Use(RequireScopeGin(scopeName, types.ScopeRead)).GET("/", func(context *gin.Context) {
			context.String(200, "success")
		})

		serializer := jwt.NewSerializer()
		serializer.Sign(jwt.WithInsecureNoSignature())

		tokenBuilder := jwt.NewBuilder()
		tokenBuilder.Issuer("wisdom-tests")
		tokenBuilder.Expiration(time.Now().Add(15 * time.Second))
		tokenBuilder.Claim("scopes", []string{"scope1:test"})
		token, err := tokenBuilder.Build()
		assert.NoError(t, err)

		serializedToken, err := serializer.Serialize(token)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", `Bearer `+string(serializedToken))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		res := rec.Result()

		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, "success", string(rec.Body.Bytes()))

		if t.Failed() {
			os.Stdout.Write([]byte("Authorization: " + req.Header.Get("Authorization") + "\n"))
			io.Copy(os.Stdout, res.Body)
		}
	})
}

func Test_RequireScope_gin_InvalidScope(t *testing.T) {
	var validator JWTValidator
	_ = validator.Configure("wisdom-tests", "", true)
	r := gin.New()
	r.Use(validator.GinHandler)
	r.Handle("GET", "/", RequireScopeGin("correct-scope", types.ScopeWrite), func(context *gin.Context) {
		context.String(200, "success")
	})
	serializer := jwt.NewSerializer()
	serializer.Sign(jwt.WithInsecureNoSignature())

	tokenBuilder := jwt.NewBuilder()
	tokenBuilder.Issuer("wisdom-tests")
	tokenBuilder.Expiration(time.Now().Add(15 * time.Second))
	tokenBuilder.Claim("scopes", []string{"wrong-scope:write"})
	token, err := tokenBuilder.Build()
	assert.NoError(t, err)

	serializedToken, err := serializer.Serialize(token)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", `Bearer `+string(serializedToken))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	res := rec.Result()

	var receivedError types.ServiceError
	err = json.NewDecoder(res.Body).Decode(&receivedError)
	assert.NoError(t, err)
	assert.True(t, internal.Forbidden.Equals(receivedError))

	assert.Equal(t, int(internal.Forbidden.Status), res.StatusCode)
	assert.Equal(t, types.ErrorContentType, res.Header.Get("Content-Type"))

	if t.Failed() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("  ", "  ")
		enc.Encode(receivedError)
	}
}

func Test_RequireScope_gin_InvalidLevel(t *testing.T) {
	var validator JWTValidator
	_ = validator.Configure("wisdom-tests", "", true)
	r := gin.New()
	r.Use(validator.GinHandler)
	r.Handle("GET", "/", RequireScopeGin("correct-scope", types.ScopeWrite), func(context *gin.Context) {
		context.String(200, "success")
	})
	serializer := jwt.NewSerializer()
	serializer.Sign(jwt.WithInsecureNoSignature())

	tokenBuilder := jwt.NewBuilder()
	tokenBuilder.Issuer("wisdom-tests")
	tokenBuilder.Expiration(time.Now().Add(15 * time.Second))
	tokenBuilder.Claim("scopes", []string{"correct-scope:read"})
	token, err := tokenBuilder.Build()
	assert.NoError(t, err)

	serializedToken, err := serializer.Serialize(token)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", `Bearer `+string(serializedToken))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	res := rec.Result()

	var receivedError types.ServiceError
	err = json.NewDecoder(res.Body).Decode(&receivedError)
	assert.NoError(t, err)
	assert.True(t, internal.Forbidden.Equals(receivedError))

	assert.Equal(t, int(internal.Forbidden.Status), res.StatusCode)
	assert.Equal(t, types.ErrorContentType, res.Header.Get("Content-Type"))

	if t.Failed() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("  ", "  ")
		enc.Encode(receivedError)
	}
}

func Test_RequireScope_gin_AdministratorOverrride(t *testing.T) {
	var validator JWTValidator
	_ = validator.Configure("wisdom-tests", "", true)
	r := gin.New()
	r.Use(validator.GinHandler)
	r.Handle("GET", "/", RequireScopeGin("correct-scope", types.ScopeWrite), func(context *gin.Context) {
		context.String(200, "success")
	})
	serializer := jwt.NewSerializer()
	serializer.Sign(jwt.WithInsecureNoSignature())

	tokenBuilder := jwt.NewBuilder()
	tokenBuilder.Issuer("wisdom-tests")
	tokenBuilder.Expiration(time.Now().Add(15 * time.Second))
	tokenBuilder.Claim("scopes", []string{"wrong-scope:read", internal.ScopeAdministrator})
	token, err := tokenBuilder.Build()
	assert.NoError(t, err)

	serializedToken, err := serializer.Serialize(token)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", `Bearer `+string(serializedToken))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	res := rec.Result()

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "success", string(rec.Body.Bytes()))
}

func Test_RequireScope_gin_CorrectData(t *testing.T) {
	var validator JWTValidator
	_ = validator.Configure("wisdom-tests", "", true)
	r := gin.New()
	r.Use(validator.GinHandler)
	r.Handle("GET", "/", RequireScopeGin("correct-scope", types.ScopeWrite), func(context *gin.Context) {
		context.String(200, "success")
	})
	serializer := jwt.NewSerializer()
	serializer.Sign(jwt.WithInsecureNoSignature())

	tokenBuilder := jwt.NewBuilder()
	tokenBuilder.Issuer("wisdom-tests")
	tokenBuilder.Expiration(time.Now().Add(15 * time.Second))
	tokenBuilder.Claim("scopes", []string{"correct-scope:write"})
	token, err := tokenBuilder.Build()
	assert.NoError(t, err)

	serializedToken, err := serializer.Serialize(token)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", `Bearer `+string(serializedToken))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	res := rec.Result()

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "success", string(rec.Body.Bytes()))

}
