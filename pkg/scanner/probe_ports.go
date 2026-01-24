package scanner

import (
	"context"
)

// PortsProbe implements the Probe interface for port scanning
type PortsProbe struct{}

// NewPortsProbe creates a new port scanning probe
func NewPortsProbe() *PortsProbe {
	return &PortsProbe{}
}

// Name returns the probe identifier
func (p *PortsProbe) Name() string {
	return "ports"
}

// Scan performs port scanning on the given IP and populates the result
func (p *PortsProbe) Scan(ctx context.Context, ip string, result *ScanResult) error {
	openPorts := ScanDNSPorts(ctx, ip)
	result.OpenPorts = openPorts
	return nil
}
