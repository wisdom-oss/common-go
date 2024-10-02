package middleware

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

var validator JWTValidator
var validatorConfigured bool

func _prepareGinRouter() *gin.Engine {
	if !validatorConfigured {
		_ = validator.DiscoverAndConfigure("https://samples.auth0.com/")
		validatorConfigured = true
	}
	r := gin.New()
	r.Use(validator.GinHandler)
	r.GET("/", func(context *gin.Context) {
		context.String(200, "success")
	})
	return r
}

func Test_JWTValidator_Discovery_EmptyIssuer(t *testing.T) {
	var validator JWTValidator
	err := validator.DiscoverAndConfigure("")
	assert.Error(t, err)
	assert.EqualError(t, err, ErrIssuerEmpty.Error())
}

func Test_JWTValidator_Discovery_InvalidIssuer(t *testing.T) {
	var validator JWTValidator
	err := validator.DiscoverAndConfigure(":")
	assert.Error(t, err)
	assert.ErrorContains(t, err, ErrDiscoveryFailure.Error())
	assert.ErrorContains(t, err, ErrIssuerUnsupportedScheme.Error())
}

func Test_JWTValidator_Discovery_InvalidDiscoveryContent(t *testing.T) {
	var validator JWTValidator
	err := validator.DiscoverAndConfigure("https://example.com")
	assert.Error(t, err)
	assert.ErrorContains(t, err, ErrDiscoveryFailure.Error())
	assert.ErrorContains(t, err, ErrDiscoveryResponseParseFailed.Error())
}

func Test_JWTValidator_Discovery_Valid(t *testing.T) {
	var validator JWTValidator
	err := validator.DiscoverAndConfigure("https://samples.auth0.com/")
	assert.NoError(t, err)
}

func Test_JWTValidator_JWKS_Registry(t *testing.T) {
	var validator JWTValidator
	err := validator.DiscoverAndConfigure("https://samples.auth0.com/")
	assert.NoError(t, err)
	assert.NotEmpty(t, validator.issuerJwksUri)
	assert.True(t, validator.jwksCache.IsRegistered(validator.issuerJwksUri))
}
