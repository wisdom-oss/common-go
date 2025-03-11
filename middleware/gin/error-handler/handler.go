package errorHandler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/wisdom-oss/common-go/v3/types"
)

var InternalError = &types.ServiceError{
	Type:   "https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1",
	Status: http.StatusInternalServerError,
	Title:  "Internal Server Error",
	Detail: "The service encountered an internal error during the handling of your request",
}

func Handler(c *gin.Context) {
	c.Next()
	errorResponse := InternalError
	errs := make([]error, len(c.Errors))
	for idx, err := range c.Errors {
		errs[idx] = err.Err
	}
	errorResponse.Errors = errs
	if len(errs) > 0 && c.IsAborted() {
		c.Header("Content-Type", "application/problem+json; charset=utf-8")
		c.JSON(http.StatusInternalServerError, errorResponse)
	}
}
