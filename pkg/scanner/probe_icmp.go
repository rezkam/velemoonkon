package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/velemoonkon/lightning/pkg/icmp"
)

// ICMPProbe implements the Probe interface for ICMP ping scanning
type ICMPProbe struct {
	scanner *icmp.Scanner
	started bool
}

// NewICMPProbe creates a new ICMP probe with the given configuration
func NewICMPProbe(cfg Config) (*ICMPProbe, error) {
	icmpCfg := icmp.Config{
		Timeout:     time.Duration(cfg.Timeout) * time.Second,
		Count:       cfg.ICMPCount,
		Interval:    0, // No interval for single ping (speed)
		PayloadSize: 56,
		Privileged:  cfg.ICMPPrivileged,
	}

	// Use defaults if not specified
	if icmpCfg.Count <= 0 {
		icmpCfg.Count = 1
	}

	scanner := icmp.NewScanner(icmpCfg)
	return &ICMPProbe{
		scanner: scanner,
	}, nil
}

// Name returns the probe identifier
func (p *ICMPProbe) Name() string {
	return "icmp"
}

// Start initializes the ICMP listener sockets
// Must be called before Scan
func (p *ICMPProbe) Start() error {
	if p.started {
		return nil
	}
	if err := p.scanner.Start(); err != nil {
		return fmt.Errorf("failed to start ICMP scanner: %w", err)
	}
	p.started = true
	return nil
}

// Stop releases ICMP resources
func (p *ICMPProbe) Stop() {
	if p.started {
		p.scanner.Stop()
		p.started = false
	}
}

// Scan performs ICMP ping on the given IP and populates the result
func (p *ICMPProbe) Scan(ctx context.Context, ip string, result *ScanResult) error {
	if !p.started {
		return fmt.Errorf("ICMP probe not started")
	}

	icmpResult, err := p.scanner.Ping(ctx, ip)
	if err != nil {
		slog.Debug("ICMP ping error", "ip", ip, "error", err)
		result.ScanErrors = append(result.ScanErrors, fmt.Sprintf("ICMP: %v", err))
		return nil // Don't fail the entire scan
	}

	result.ICMPResult = icmpResult
	return nil
}
