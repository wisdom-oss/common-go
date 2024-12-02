package jwt_test

import (
	"strings"
	"testing"

	"github.com/wisdom-oss/common-go/v3/middleware/jwt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
)

const validJWKS = `{"keys":[{"alg":"ES256","crv":"P-256","kid":"Hwl5I6Y6J5QJ0DDyESWWHHdbkf3Sa2VgA7OkjFK3-Os","kty":"EC","use":"enc","x":"TwEAW1ogulU9XEMXIzPJ8dbLk-vYVBr-qu7K9kVeTtE","y":"oMsIDwNmfBKx7wXndd2dSA9VhwX-sgdvciNcjJy3i24"},{"alg":"ES256","crv":"P-256","kid":"DIGpDRD4Majl8Qywos-6InFy7bKdz3mL_rxRt9ud-p0","kty":"EC","use":"sig","x":"t_w7EEVzsk5DoYeYuEx1S77SRO5jmJXtrytUyl3fJHs","y":"WQWEXP-i18dTa2WX3iofTyiPoEyDCyItkIuGmSDttlE"}]}`

func Test_JWT_Validator(t *testing.T) {
	t.Run("Configuration", configuration)
	t.Run("Handler", handler)
}

func configuration(t *testing.T) {
	t.Run("Automatic", _automatic_configuration)
	t.Run("Manual", _manual_configuration)
}

func _automatic_configuration(t *testing.T) {
	t.Run("Empty_Issuer", _config_auto_empty_issuer)
	t.Run("Non_HTTP_Issuer", _config_auto_non_http_issuer)
	t.Run("Invalid_Issuer", _config_auto_invalid_issuer)
	t.Run("Valid Issuer", _config_auto_valid_issuer)
}

func _config_auto_empty_issuer(t *testing.T) {
	var v jwt.Validator
	err := v.Discover("")
	assert.ErrorAs(t, err, &jwt.ErrDiscoverFailure)
	assert.ErrorAs(t, err, &jwt.ErrIssuerEmtpy)
}

func _config_auto_non_http_issuer(t *testing.T) {
	var v jwt.Validator
	err := v.Discover("/")
	assert.ErrorAs(t, err, &jwt.ErrDiscoverFailure)
	assert.ErrorAs(t, err, &jwt.ErrIssuerNotHTTP)
}

func _config_auto_invalid_issuer(t *testing.T) {
	var v jwt.Validator
	err := v.Discover("https://example.com/")
	assert.ErrorAs(t, err, &jwt.ErrDiscoverFailure)
}

func _config_auto_valid_issuer(t *testing.T) {
	var v jwt.Validator
	err := v.Discover("https://samples.auth0.com/")
	assert.NoError(t, err)
}

func _manual_configuration(t *testing.T) {
	t.Run("JWKS_from_String", _config_manual_string_jwks)
	t.Run("JWKS_from_[]byte", _config_manual_byte_jwks)
	t.Run("JWKS_from_io.Reader", _config_manual_reader_jwks)
	t.Run("JWKS_from_jwk.Set", _config_manual_set_jwks)
	t.Run("Invalid_JWKS_from_String", _config_manual_invalid_jwks_string)
	t.Run("Invalid_JWKS_from_[]byte", _config_manual_invalid_jwks_byte)
	t.Run("Invalid_JWKS_from_io.Reader", _config_manual_invalid_jwks_reader)
}

func _config_manual_string_jwks(t *testing.T) {
	var v jwt.Validator
	err := v.Configure("", validJWKS, nil)
	assert.NoError(t, err)
}

func _config_manual_byte_jwks(t *testing.T) {
	var v jwt.Validator
	err := v.Configure("", []byte(validJWKS), nil)
	assert.NoError(t, err)
}

func _config_manual_reader_jwks(t *testing.T) {
	var v jwt.Validator
	reader := strings.NewReader(validJWKS)
	err := v.Configure("", reader, nil)
	assert.NoError(t, err)
}

func _config_manual_set_jwks(t *testing.T) {
	var v jwt.Validator
	set, err := jwk.ParseString(validJWKS)
	assert.NoError(t, err)
	err = v.Configure("", set, nil)
	assert.NoError(t, err)
}

func _config_manual_unsupported_jwks_type(t *testing.T) {
	var v jwt.Validator
	err := v.Configure("", 12345, nil)
	assert.ErrorAs(t, err, &jwt.ErrUnsupportedManualJWKS)
}

func _config_manual_invalid_jwks_string(t *testing.T) {
	var v jwt.Validator
	s := validJWKS[1:]
	err := v.Configure("", s, nil)
	assert.Error(t, err)
}
func _config_manual_invalid_jwks_byte(t *testing.T) {
	var v jwt.Validator
	s := validJWKS[1:]
	err := v.Configure("", []byte(s), nil)
	assert.Error(t, err)
}

func _config_manual_invalid_jwks_reader(t *testing.T) {
	var v jwt.Validator
	s := validJWKS[1:]
	err := v.Configure("", strings.NewReader(s), nil)
	assert.Error(t, err)
}
