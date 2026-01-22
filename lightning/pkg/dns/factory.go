package dns

// NewDefaultRegistry creates a registry with all default DNS scanners
func NewDefaultRegistry(testDomains []string) *Registry {
	registry := NewRegistry()
	opts := DefaultQueryOptions()

	// Register all scanners
	registry.Register(NewUDPScanner(opts, testDomains))
	registry.Register(NewTCPScanner(opts, testDomains))
	registry.Register(NewDoTScanner(opts, testDomains))
	registry.Register(NewDoHScanner(opts, testDomains))

	return registry
}
