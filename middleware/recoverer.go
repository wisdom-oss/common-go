package middleware

import (
	"fmt"

	"github.com/gin-gonic/gin"

	errorHandler "github.com/wisdom-oss/common-go/v2/internal/error-handler"
	"github.com/wisdom-oss/common-go/v2/types"
)

func RecoveryHandler(c *gin.Context, err any) {
	response := errorHandler.Panic
	response.Errors = []error{fmt.Errorf("%v", err)}
	c.Header("Content-Type", types.ErrorContentType)
	c.AbortWithStatusJSON(500, response)
}
