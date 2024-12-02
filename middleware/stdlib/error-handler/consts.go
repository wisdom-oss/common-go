package errorHandler

import internal "github.com/wisdom-oss/common-go/v3/internal/error-handler"

type contextKey string

var ErrorChannelName = contextKey(internal.ErrorChannelName)
