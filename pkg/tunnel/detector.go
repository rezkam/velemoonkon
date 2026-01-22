package tunnel

import (
	"context"
)

// Detector defines the interface for tunnel detectors
type Detector interface {
	// Name returns the detector name (dnstt, iodine, dnscat2, dns2tcp)
	Name() string

	// Detect performs tunnel detection on the given IP
	Detect(ctx context.Context, ip string, domain string) (*DetectionResult, error)
}

// DetectionResult contains results from a single tunnel detector
type DetectionResult struct {
	DetectorName string   `json:"detector_name"`
	IsTunnel     bool     `json:"is_tunnel"`
	Confidence   string   `json:"confidence"` // high, medium, low
	Indicators   []string `json:"indicators"`
	RawData      interface{} `json:"raw_data,omitempty"` // Detector-specific data
	Error        string   `json:"error,omitempty"`
}

// Registry manages available tunnel detectors
type Registry struct {
	detectors map[string]Detector
}

// NewRegistry creates a new detector registry
func NewRegistry() *Registry {
	return &Registry{
		detectors: make(map[string]Detector),
	}
}

// Register adds a detector to the registry
func (r *Registry) Register(detector Detector) {
	r.detectors[detector.Name()] = detector
}

// Get retrieves a detector by name
func (r *Registry) Get(name string) (Detector, bool) {
	detector, ok := r.detectors[name]
	return detector, ok
}

// All returns all registered detectors
func (r *Registry) All() []Detector {
	detectors := make([]Detector, 0, len(r.detectors))
	for _, detector := range r.detectors {
		detectors = append(detectors, detector)
	}
	return detectors
}

// GetByNames returns detectors by their names
func (r *Registry) GetByNames(names []string) []Detector {
	detectors := make([]Detector, 0, len(names))
	for _, name := range names {
		if detector, ok := r.detectors[name]; ok {
			detectors = append(detectors, detector)
		}
	}
	return detectors
}
