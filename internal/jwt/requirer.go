package jwt

type ScopeRequirer struct {
	Service string
}

func (sr *ScopeRequirer) Configure(serviceName string) {
	sr.Service = serviceName
}
