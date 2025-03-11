// nolint
package jwt

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
)

var r *gin.Engine
var jwkTestingKey = []byte("testing-key")
var key jwk.Key
var keySet jwk.Set
var v *Validator
var sr *ScopeRequirer

func Test(t *testing.T) {
	r = gin.New()

	var err error
	key, err = jwk.FromRaw(jwkTestingKey)
	assert.NoError(t, err)

	jwk.AssignKeyID(key)                 //nolint:errcheck
	key.Set(jwk.KeyUsageKey, "sig")      //nolint:errcheck
	key.Set(jwk.AlgorithmKey, jwa.HS256) //nolint:errcheck

	keySet = jwk.NewSet()
	keySet.AddKey(key) //nolint:errcheck

	v = &Validator{}
	err = v.Configure("test", keySet, nil)
	assert.NoError(t, err)

	sr = &ScopeRequirer{}
	sr.Configure(scopePrefix)

	r.Use(v.Handler)
	r.GET("/", func(ctx *gin.Context) {
		ctx.Status(200)
	})

	t.Run("Validator", func(t *testing.T) {
		t.Run("Missing_Authorization_Header", _missing_authorization_header)
		t.Run("Multiple_Authoritazion_Headers", _multiple_authorization_headers)
		t.Run("Unsupported_Token_Scheme", _unsupported_token_scheme)
		t.Run("Invalid_JWT", _invalid_jwt)
		t.Run("Missing_Claims", _missing_jwt_claims)
		t.Run("Invalid_Claims", _invalid_claim_values)
		t.Run("Empty_Scopes", _jwt_empty_scopes)
		t.Run("Valid_JWT", _jwt_valid)
		t.Run("Valid_Admin_JWT", _jwt_admin_valid)
	})

	r = gin.New()
	r.Use(v.Handler)

	t.Run("Requirer", func(t *testing.T) {
		t.Run("Read", func(t *testing.T) {

			r.GET("/", sr.RequireRead, func(ctx *gin.Context) {
				ctx.Status(200)
			})
			t.Run("No_Scope", _require_read_no_scope)
			t.Run("Scope", _require_read)

			t.Cleanup(func() {
				r = gin.New()
				r.Use(v.Handler)
			})
		})
		t.Run("Write", func(t *testing.T) {
			r.GET("/", sr.RequireWrite, func(ctx *gin.Context) {
				ctx.Status(200)
			})
			t.Run("No_Scope", _require_write_no_scope)
			t.Run("Scope", _require_write)
			t.Cleanup(func() {
				r = gin.New()
				r.Use(v.Handler)
			})
		})
		t.Run("Delete", func(t *testing.T) {
			r.GET("/", sr.RequireDelete, func(ctx *gin.Context) {
				ctx.Status(200)
			})
			t.Run("No_Scope", _require_delete_no_scope)
			t.Run("Scope", _require_delete)
			t.Cleanup(func() {
				r = gin.New()
				r.Use(v.Handler)
			})
		})
		t.Run("Admin", func(t *testing.T) {
			r.GET("/", sr.RequireAdministrator, func(ctx *gin.Context) {
				ctx.Status(200)
			})
			t.Run("No_Scope", _require_admin_no_scope)
			t.Run("Scope", _require_admin)
			t.Cleanup(func() {
				r = gin.New()
				r.Use(v.Handler)
			})
		})
	})
}
