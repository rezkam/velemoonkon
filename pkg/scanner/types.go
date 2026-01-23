package scanner

import (
	"github.com/velemoonkon/lightning/pkg/dns"
	"github.com/velemoonkon/lightning/pkg/tunnel"
)

// ScanResult contains all results for a single IP scan
type ScanResult struct {
	IP           string              `json:"ip"`
	DNSResult    *dns.TestResult     `json:"dns_result,omitzero"`
	TunnelResult *tunnel.Result      `json:"tunnel_result,omitzero"`
	OpenPorts    []int               `json:"open_ports,omitzero"`
	ScanTime     int64               `json:"scan_time_ms"`
	ScanErrors   []string            `json:"scan_errors,omitzero"` // Individual scanner/detector errors
	Error        string              `json:"error,omitzero"`        // Fatal error that stopped scan
}

// Config contains scanner configuration
type Config struct {
	Workers         int    // Number of concurrent IP workers (0 or negative = auto: max(4, 4*GOMAXPROCS) for I/O-bound work)
	DNSConcurrency  int    // Max concurrent DNS tests per IP (bounded by errgroup)
	Timeout         int    // Timeout in seconds per IP
	RateLimit       int    // Max IPs per second (0 or negative = no limit, uses rate.Inf)
	EnableUDP       bool
	EnableTCP       bool
	EnableDoT       bool
	EnableDoH       bool
	EnableTunnel    bool
	TunnelDNSTT     bool
	TunnelIodine    bool
	TunnelDNScat2   bool
	TunnelDNS2TCP   bool
	EnablePortScan  bool
	TunnelDomain    string
	TestDomains     []string
	Verbose         bool
	Quiet           bool
}

// DefaultConfig returns default scanner configuration
func DefaultConfig() Config {
	return Config{
		Workers:        100,
		Timeout:        5,
		RateLimit:      1000,
		EnableUDP:      true,
		EnableTCP:      true,
		EnableDoT:      true,
		EnableDoH:      true,
		EnableTunnel:   true,
		TunnelDNSTT:    true,
		TunnelIodine:   true,
		TunnelDNScat2:  true,
		TunnelDNS2TCP:  true,
		EnablePortScan: true,
		TunnelDomain:   "",
		Verbose:        false,
		Quiet:          false,
	}
}
