package scanner

import (
	"github.com/velemoonkon/lightning/pkg/dns"
	"github.com/velemoonkon/lightning/pkg/tunnel"
)

// ScanResult contains all results for a single IP scan
type ScanResult struct {
	IP           string              `json:"ip"`
	DNSResult    *dns.TestResult     `json:"dns_result,omitempty"`
	TunnelResult *tunnel.Result      `json:"tunnel_result,omitempty"`
	OpenPorts    []int               `json:"open_ports,omitempty"`
	ScanTime     int64               `json:"scan_time_ms"`
	Error        string              `json:"error,omitempty"`
}

// Config contains scanner configuration
type Config struct {
	Workers         int
	DNSConcurrency  int // max concurrent DNS tests per IP
	Timeout         int // seconds per IP
	RateLimit       int // max IPs per second
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
