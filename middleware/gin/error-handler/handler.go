package errorHandler

import (
	"github.com/gin-gonic/gin"
	"github.com/wisdom-oss/common-go/v3/types"
)

var InternalError = &types.ServiceError{
	Type:   "https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1",
	Status: 500,
	Title:  "Internal Server Error",
	Detail: "The service encountered an internal error during the handling of your request",
}

func Handler(c *gin.Context) {
	c.Next()
	errorResponse := InternalError
	var errors []error
	for _, err := range c.Errors {
		errors = append(errors, err.Err)
	}
	errorResponse.Errors = errors
	if len(errors) > 0 && c.IsAborted() {
		c.Header("Content-Type", "application/problem+json; charset=utf-8")
		c.JSON(500, errorResponse)
	}
}
