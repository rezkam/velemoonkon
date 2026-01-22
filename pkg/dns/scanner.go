package dns

import (
	"context"
	"time"
)

// Scanner defines the interface for DNS scanners
type Scanner interface {
	// Name returns the scanner name (udp, tcp, dot, doh)
	Name() string

	// Scan performs the DNS scan on the given IP
	Scan(ctx context.Context, ip string) (*ScanResult, error)
}

// ScanResult contains results from a single DNS scanner
type ScanResult struct {
	ScannerName     string        `json:"scanner_name"`
	Success         bool          `json:"success"`
	ResponseTime    time.Duration `json:"response_time_ms"`
	SupportsEDNS    bool          `json:"supports_edns,omitempty"`
	Recursive       bool          `json:"recursive,omitempty"`
	Endpoint        string        `json:"endpoint,omitempty"` // For DoH
	DomainsResolved []string      `json:"domains_resolved,omitempty"`
	Error           string        `json:"error,omitempty"`
}

// Registry manages available DNS scanners
type Registry struct {
	scanners map[string]Scanner
}

// NewRegistry creates a new scanner registry
func NewRegistry() *Registry {
	return &Registry{
		scanners: make(map[string]Scanner),
	}
}

// Register adds a scanner to the registry
func (r *Registry) Register(scanner Scanner) {
	r.scanners[scanner.Name()] = scanner
}

// Get retrieves a scanner by name
func (r *Registry) Get(name string) (Scanner, bool) {
	scanner, ok := r.scanners[name]
	return scanner, ok
}

// All returns all registered scanners
func (r *Registry) All() []Scanner {
	scanners := make([]Scanner, 0, len(r.scanners))
	for _, scanner := range r.scanners {
		scanners = append(scanners, scanner)
	}
	return scanners
}

// GetByNames returns scanners by their names
func (r *Registry) GetByNames(names []string) []Scanner {
	scanners := make([]Scanner, 0, len(names))
	for _, name := range names {
		if scanner, ok := r.scanners[name]; ok {
			scanners = append(scanners, scanner)
		}
	}
	return scanners
}
