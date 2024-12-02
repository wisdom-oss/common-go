package jwt

import "github.com/wisdom-oss/common-go/v3/internal/jwt"

type ContextKey string

const KeyTokenValidated = ContextKey(jwt.KeyTokenValidated)
const KeyTokenPermissions = ContextKey(jwt.KeyTokenPermissions)
const KeyTokenSubject = ContextKey(jwt.KeyTokenSubject)
const KeyAdministrator = ContextKey(jwt.KeyAdministrator)
