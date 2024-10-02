package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	errorHandler "github.com/wisdom-oss/common-go/v2/internal/error-handler"
	"github.com/wisdom-oss/common-go/v2/types"
)

func Test_Recoverer(t *testing.T) {
	r := gin.New()
	r.Use(gin.CustomRecovery(RecoveryHandler))
	r.GET("/", func(c *gin.Context) {
		panic("test")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	res := rec.Result()

	assert.Equal(t, int(errorHandler.Panic.Status), res.StatusCode)
	assert.Equal(t, res.Header.Get("Content-Type"), types.ErrorContentType)

	var receivedError types.ServiceError
	err := json.Unmarshal(rec.Body.Bytes(), &receivedError)
	assert.NoError(t, err)
	assert.True(t, errorHandler.Panic.Equals(receivedError))

	if t.Failed() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("  ", "  ")
		enc.Encode(receivedError)
	}
}
