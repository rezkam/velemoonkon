package scanner

import (
	"context"
)

// Probe defines the interface for scanner modules (DNS, ICMP, Tunnel, etc.)
// Each probe is responsible for one type of scanning against an IP
type Probe interface {
	// Name returns the probe identifier (e.g., "icmp", "dns", "tunnel")
	Name() string

	// Scan performs the probe on the given IP and populates the result
	// The result parameter is shared across all probes for the same IP
	Scan(ctx context.Context, ip string, result *ScanResult) error
}

// ProbeFunc is a function adapter for Probe interface
// Allows using simple functions as probes without creating a struct
type ProbeFunc struct {
	name    string
	scanFn  func(ctx context.Context, ip string, result *ScanResult) error
}

// NewProbeFunc creates a Probe from a function
func NewProbeFunc(name string, fn func(ctx context.Context, ip string, result *ScanResult) error) Probe {
	return &ProbeFunc{name: name, scanFn: fn}
}

func (p *ProbeFunc) Name() string {
	return p.name
}

func (p *ProbeFunc) Scan(ctx context.Context, ip string, result *ScanResult) error {
	return p.scanFn(ctx, ip, result)
}

// ProbeRegistry manages available probes
type ProbeRegistry struct {
	probes []Probe
}

// NewProbeRegistry creates an empty probe registry
func NewProbeRegistry() *ProbeRegistry {
	return &ProbeRegistry{
		probes: make([]Probe, 0),
	}
}

// Register adds a probe to the registry
func (r *ProbeRegistry) Register(probe Probe) {
	r.probes = append(r.probes, probe)
}

// All returns all registered probes
func (r *ProbeRegistry) All() []Probe {
	return r.probes
}

// Count returns the number of registered probes
func (r *ProbeRegistry) Count() int {
	return len(r.probes)
}
