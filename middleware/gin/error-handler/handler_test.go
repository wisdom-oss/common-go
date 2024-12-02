package errorHandler_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	errorHandler "github.com/wisdom-oss/common-go/v3/middleware/gin/error-handler"
)

var r *gin.Engine

func Test(t *testing.T) {
	r = gin.New()
	r.Use(errorHandler.Handler)

	t.Run("Native_Error", _native_error)
}

func _native_error(t *testing.T) {
	r.GET("/", func(c *gin.Context) {
		c.Abort()
		_ = c.Error(errors.New("testing"))
	})

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	r.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusInternalServerError, res.Code)
	assert.Equal(t, "application/problem+json; charset=utf-8", res.Header().Get("Content-Type"))
}
