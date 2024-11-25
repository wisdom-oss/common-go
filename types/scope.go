package types

import "errors"

type Scope uint8

const (
	ScopeRead Scope = iota
	ScopeWrite
	ScopeDelete
	ScopeAdmin
)

func (s Scope) String() string {
	switch s {
	case ScopeRead:
		return "read"
	case ScopeWrite:
		return "write"
	case ScopeDelete:
		return "delete"
	case ScopeAdmin:
		return "*"
	default:
		return "<unknown>"
	}
}

func (s *Scope) Parse(input any) error {
	var scope string
	switch val := input.(type) {
	case string:
		scope = val
	case []byte:
		scope = string(val)
	default:
		return errors.New("invalid input data type, expected []byte or string")
	}

	switch scope {
	case "read":
		*s = ScopeRead
	case "write":
		*s = ScopeWrite
	case "delete":
		*s = ScopeDelete
	case "admin", "*":
		*s = ScopeAdmin
	default:
		return errors.New("unknown scope passed as input")
	}
	return nil
}
