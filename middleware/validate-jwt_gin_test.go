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

func Test_JWTValidator_GIN_DenyMissingHeader(t *testing.T) {
	var validator JWTValidator
	_ = validator.DiscoverAndConfigure("https://samples.auth0.com/")
	r := gin.New()
	r.Use(validator.GinHandler)
	r.GET("/", func(context *gin.Context) {
		context.String(200, "success")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	res := rec.Result()

	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	assert.Equal(t, res.Header.Get("Content-Type"), types.ErrorContentType)

	var receivedError types.ServiceError
	err := json.Unmarshal(rec.Body.Bytes(), &receivedError)
	assert.NoError(t, err)
	assert.True(t, internal.ErrMissingAuthorizationHeader.Equals(receivedError))

	if t.Failed() {
		os.Stdout.Write([]byte("Authorization: " + req.Header.Get("Authorization") + "\n"))
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("  ", "  ")
		enc.Encode(receivedError)

	}
}

func Test_JWTValidator_gin_DenyEmptyHeader(t *testing.T) {
	r := _prepareGinRouter()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	res := rec.Result()

	assert.Equal(t, int(internal.ErrMissingAuthorizationHeader.Status), res.StatusCode)
	assert.Equal(t, res.Header.Get("Content-Type"), types.ErrorContentType)

	var receivedError types.ServiceError
	err := json.Unmarshal(rec.Body.Bytes(), &receivedError)
	assert.NoError(t, err)
	assert.True(t, internal.ErrMissingAuthorizationHeader.Equals(receivedError))

	if t.Failed() {
		os.Stdout.Write([]byte("Authorization: " + req.Header.Get("Authorization") + "\n"))
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("  ", "  ")
		enc.Encode(receivedError)

	}
}

func Fuzz_JWTValidator_gin_WrongTokenScheme(f *testing.F) {
	r := _prepareGinRouter()

	f.Add("HMAC")
	f.Add("Token")
	f.Add("Bearera")
	f.Add("Bearers")
	f.Fuzz(func(t *testing.T, tokenScheme string) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", tokenScheme+" abc")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		res := rec.Result()

		assert.Equal(t, int(internal.ErrUnsupportedTokenScheme.Status), res.StatusCode)
		assert.Equal(t, res.Header.Get("Content-Type"), types.ErrorContentType)

		var receivedError types.ServiceError
		err := json.Unmarshal(rec.Body.Bytes(), &receivedError)
		assert.NoError(t, err)
		assert.True(t, internal.ErrUnsupportedTokenScheme.Equals(receivedError))

		if t.Failed() {
			os.Stdout.Write([]byte("Authorization: " + req.Header.Get("Authorization") + "\n"))
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("  ", "  ")
			enc.Encode(receivedError)

		}
	})

}

func Fuzz_JWTValidator_gin_InvalidJWT(f *testing.F) {
	r := _prepareGinRouter()

	f.Fuzz(func(t *testing.T, jwt string) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", `Bearer `+jwt)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		res := rec.Result()

		assert.Equal(t, int(internal.ErrJWTMalformed.Status), res.StatusCode)
		assert.Equal(t, types.ErrorContentType, res.Header.Get("Content-Type"))

		var receivedError types.ServiceError
		err := json.Unmarshal(rec.Body.Bytes(), &receivedError)
		assert.NoError(t, err)
		assert.True(t, internal.ErrJWTMalformed.Equals(receivedError))

		if t.Failed() {
			os.Stdout.Write([]byte("Authorization: " + req.Header.Get("Authorization") + "\n"))
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("  ", "  ")
			enc.Encode(receivedError)

		}
	})
}

func Fuzz_JWTValidator_gin_JWTIncorrectIssuer(f *testing.F) {
	var validator JWTValidator
	_ = validator.Configure("wisdom-tests", "", true)
	r := gin.New()
	r.Use(validator.GinHandler)
	r.GET("/", func(context *gin.Context) {
		context.String(200, "success")
	})
	serializer := jwt.NewSerializer()
	serializer.Sign(jwt.WithInsecureNoSignature())

	f.Add("wrong-issuer")
	f.Add("")
	f.Add("localhost")

	f.Fuzz(func(t *testing.T, issuer string) {
		tokenBuilder := jwt.NewBuilder()
		tokenBuilder.Issuer(issuer)
		tokenBuilder.Claim("kid", "NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg")
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
		assert.True(t, internal.ErrJWTInvalidIssuer.Equals(receivedError))

		assert.Equal(t, int(internal.ErrJWTInvalidIssuer.Status), res.StatusCode)
		assert.Equal(t, types.ErrorContentType, res.Header.Get("Content-Type"))

		if t.Failed() {
			os.Stdout.Write([]byte("Authorization: " + req.Header.Get("Authorization") + "\n"))
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("  ", "  ")
			enc.Encode(receivedError)
		}
	})

}

func Test_JWTValidator_gin_JWTExpired(t *testing.T) {
	var validator JWTValidator
	_ = validator.Configure("wisdom-tests", "", true)
	r := gin.New()
	r.Use(validator.GinHandler)
	r.GET("/", func(context *gin.Context) {
		context.String(200, "success")
	})
	serializer := jwt.NewSerializer()
	serializer.Sign(jwt.WithInsecureNoSignature())

	tokenBuilder := jwt.NewBuilder()
	tokenBuilder.Issuer("wisdom-tests")
	tokenBuilder.Expiration(time.Now().Add(-15 * time.Second))
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
	assert.True(t, internal.ErrJWTExpired.Equals(receivedError))

	assert.Equal(t, int(internal.ErrJWTExpired.Status), res.StatusCode)
	assert.Equal(t, types.ErrorContentType, res.Header.Get("Content-Type"))

	if t.Failed() {
		os.Stdout.Write([]byte("Authorization: " + req.Header.Get("Authorization") + "\n"))
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("  ", "  ")
		enc.Encode(receivedError)
	}

}

func Test_JWTValidator_gin_JWTUsedTooEarly(t *testing.T) {
	var validator JWTValidator
	_ = validator.Configure("wisdom-tests", "", true)
	r := gin.New()
	r.Use(validator.GinHandler)
	r.GET("/", func(context *gin.Context) {
		context.String(200, "success")
	})
	serializer := jwt.NewSerializer()
	serializer.Sign(jwt.WithInsecureNoSignature())

	tokenBuilder := jwt.NewBuilder()
	tokenBuilder.Issuer("wisdom-tests")
	tokenBuilder.NotBefore(time.Now().Add(15 * time.Second))
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
	assert.True(t, internal.ErrJWTNotYetValid.Equals(receivedError))

	assert.Equal(t, int(internal.ErrJWTNotYetValid.Status), res.StatusCode)
	assert.Equal(t, types.ErrorContentType, res.Header.Get("Content-Type"))

	if t.Failed() {
		os.Stdout.Write([]byte("Authorization: " + req.Header.Get("Authorization") + "\n"))
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("  ", "  ")
		enc.Encode(receivedError)
	}

}

func Test_JWTValidator_gin_JWTNotIssuedYet(t *testing.T) {
	var validator JWTValidator
	_ = validator.Configure("wisdom-tests", "", true)
	r := gin.New()
	r.Use(validator.GinHandler)
	r.GET("/", func(context *gin.Context) {
		context.String(200, "success")
	})
	serializer := jwt.NewSerializer()
	serializer.Sign(jwt.WithInsecureNoSignature())

	tokenBuilder := jwt.NewBuilder()
	tokenBuilder.Issuer("wisdom-tests")
	tokenBuilder.IssuedAt(time.Now().Add(15 * time.Second))
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
	assert.True(t, internal.ErrJWTNotCreatedYet.Equals(receivedError))

	assert.Equal(t, int(internal.ErrJWTNotCreatedYet.Status), res.StatusCode)
	assert.Equal(t, types.ErrorContentType, res.Header.Get("Content-Type"))

	if t.Failed() {
		os.Stdout.Write([]byte("Authorization: " + req.Header.Get("Authorization") + "\n"))
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("  ", "  ")
		enc.Encode(receivedError)
	}

}

func Test_JWTValidator_gin_JWTNoScopesSet(t *testing.T) {
	var validator JWTValidator
	_ = validator.Configure("wisdom-tests", "", true)
	r := gin.New()
	r.Use(validator.GinHandler)
	r.GET("/", func(context *gin.Context) {
		context.String(200, "success")
	})
	serializer := jwt.NewSerializer()
	serializer.Sign(jwt.WithInsecureNoSignature())

	tokenBuilder := jwt.NewBuilder()
	tokenBuilder.Issuer("wisdom-tests")
	tokenBuilder.Expiration(time.Now().Add(15 * time.Second))
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
	assert.True(t, internal.ErrJWTNoScopeSet.Equals(receivedError))

	assert.Equal(t, int(internal.ErrJWTNoScopeSet.Status), res.StatusCode)
	assert.Equal(t, types.ErrorContentType, res.Header.Get("Content-Type"))

	if t.Failed() {
		os.Stdout.Write([]byte("Authorization: " + req.Header.Get("Authorization") + "\n"))
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("  ", "  ")
		enc.Encode(receivedError)
	}

}

func Test_JWTValidator_gin_JWTValid(t *testing.T) {
	var validator JWTValidator
	_ = validator.Configure("wisdom-tests", "", true)
	r := gin.New()
	r.Use(validator.GinHandler)
	r.GET("/", func(context *gin.Context) {
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
}
