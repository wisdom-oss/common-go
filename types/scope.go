package types

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
