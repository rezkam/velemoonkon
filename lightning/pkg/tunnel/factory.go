package tunnel

// NewDefaultRegistry creates a registry with all default tunnel detectors
func NewDefaultRegistry() *Registry {
	registry := NewRegistry()

	// Register all detectors
	registry.Register(NewDNSTTDetector())
	registry.Register(NewIodineDetector())
	registry.Register(NewDNScat2Detector())
	registry.Register(NewDNS2TCPDetector())

	return registry
}
