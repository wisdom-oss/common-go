package middleware

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	errorHandler "github.com/wisdom-oss/common-go/v2/internal/error-handler"
	"github.com/wisdom-oss/common-go/v2/types"
)

func Test_ErrorHandler_gin_NoError(t *testing.T) {
	r := gin.New()
	r.Use(ErrorHandler{}.Gin)
	r.GET("/", func(context *gin.Context) {
		context.String(200, "success")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	res := rec.Result()

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "success", string(rec.Body.Bytes()))

}

func Test_ErrorHandler_gin_Error(t *testing.T) {
	r := gin.New()
	r.Use(ErrorHandler{}.Gin)
	r.GET("/", func(context *gin.Context) {
		context.Error(errors.New("test"))
		context.Abort()
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	res := rec.Result()

	var receivedErrors []types.ServiceError
	err := json.NewDecoder(res.Body).Decode(&receivedErrors)
	assert.NoError(t, err)

	assert.Equal(t, int(errorHandler.InternalError.Status), res.StatusCode)
	assert.Equal(t, types.ErrorContentType, res.Header.Get("Content-Type"))

	if t.Failed() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("  ", "  ")
		enc.Encode(receivedErrors)
	}

}
