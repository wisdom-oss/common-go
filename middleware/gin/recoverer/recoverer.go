package recoverer

import (
	"fmt"

	"github.com/gin-gonic/gin"
	errorHandler "github.com/wisdom-oss/common-go/v3/middleware/stdlib/error-handler"
)

func RecoveryHandler(c *gin.Context, err any) {
	response := errorHandler.Panic
	response.Errors = []error{fmt.Errorf("%v", err)}
	c.Header("Content-Type", "application/problem+json; charset=utf-8")
	c.AbortWithStatusJSON(500, response)
}
