package scanner

import (
	"github.com/velemoonkon/lightning/pkg/dns"
	"github.com/velemoonkon/lightning/pkg/icmp"
	"github.com/velemoonkon/lightning/pkg/tunnel"
)

// ScanResult contains all results for a single IP scan
type ScanResult struct {
	IP           string              `json:"ip"`
	ICMPResult   *icmp.Result        `json:"icmp_result,omitzero"`
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
	// ICMP settings
	EnableICMP      bool   // Enable ICMP ping scanning
	ICMPCount       int    // Number of pings per IP (default 1)
	ICMPPrivileged  bool   // Use privileged raw sockets (requires root)
	// DNS settings
	EnableUDP       bool
	EnableTCP       bool
	EnableDoT       bool
	EnableDoH       bool
	// Tunnel detection
	EnableTunnel    bool
	TunnelDNSTT     bool
	TunnelIodine    bool
	TunnelDNScat2   bool
	TunnelDNS2TCP   bool
	// Other
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
		// ICMP defaults
		EnableICMP:     false, // Disabled by default (requires root for raw sockets)
		ICMPCount:      1,     // Single ping for speed
		ICMPPrivileged: true,  // Raw sockets for best performance
		// DNS defaults
		EnableUDP:      true,
		EnableTCP:      true,
		EnableDoT:      true,
		EnableDoH:      true,
		// Tunnel defaults
		EnableTunnel:   true,
		TunnelDNSTT:    true,
		TunnelIodine:   true,
		TunnelDNScat2:  true,
		TunnelDNS2TCP:  true,
		// Other
		EnablePortScan: true,
		TunnelDomain:   "",
		Verbose:        false,
		Quiet:          false,
	}
}
