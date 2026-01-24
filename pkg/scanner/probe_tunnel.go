package scanner

import (
	"context"
	"log/slog"

	"github.com/velemoonkon/lightning/pkg/tunnel"
	"golang.org/x/sync/errgroup"
)

// TunnelProbe implements the Probe interface for DNS tunnel detection
type TunnelProbe struct {
	registry    *tunnel.Registry
	detectors   []tunnel.Detector
	domain      string
	concurrency int
}

// NewTunnelProbe creates a new tunnel detection probe with the given configuration
func NewTunnelProbe(cfg Config) *TunnelProbe {
	registry := tunnel.NewDefaultRegistry()

	// Select detectors based on config
	var detectors []tunnel.Detector
	if cfg.TunnelDNSTT {
		if detector, ok := registry.Get("dnstt"); ok {
			detectors = append(detectors, detector)
		}
	}
	if cfg.TunnelIodine {
		if detector, ok := registry.Get("iodine"); ok {
			detectors = append(detectors, detector)
		}
	}
	if cfg.TunnelDNScat2 {
		if detector, ok := registry.Get("dnscat2"); ok {
			detectors = append(detectors, detector)
		}
	}
	if cfg.TunnelDNS2TCP {
		if detector, ok := registry.Get("dns2tcp"); ok {
			detectors = append(detectors, detector)
		}
	}

	domain := cfg.TunnelDomain
	if domain == "" {
		domain = "test.example.com"
	}

	concurrency := cfg.DNSConcurrency
	if concurrency <= 0 {
		concurrency = len(detectors)
	}

	return &TunnelProbe{
		registry:    registry,
		detectors:   detectors,
		domain:      domain,
		concurrency: concurrency,
	}
}

// Name returns the probe identifier
func (p *TunnelProbe) Name() string {
	return "tunnel"
}

// HasDetectors returns true if any tunnel detectors are enabled
func (p *TunnelProbe) HasDetectors() bool {
	return len(p.detectors) > 0
}

// Scan performs tunnel detection on the given IP and populates the result
func (p *TunnelProbe) Scan(ctx context.Context, ip string, result *ScanResult) error {
	tunnelResult := &tunnel.Result{
		IP:            ip,
		AllIndicators: []string{},
	}

	if len(p.detectors) == 0 {
		result.TunnelResult = tunnelResult
		return nil
	}

	// Use errgroup with SetLimit for bounded concurrency
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(min(p.concurrency, len(p.detectors)))

	// Channel for collecting results (buffered to prevent blocking)
	resultChan := make(chan *tunnel.DetectionResult, len(p.detectors))

	// Launch detectors with bounded concurrency
	for _, detector := range p.detectors {
		g.Go(func() error {
			detectionResult, err := detector.Detect(ctx, ip, p.domain)
			if err != nil {
				slog.Debug("detector error",
					"ip", ip,
					"detector", detector.Name(),
					"error", err)
				// Don't fail the entire detection if one detector fails
				return nil
			}

			if detectionResult != nil && detectionResult.IsTunnel {
				resultChan <- detectionResult
			}
			return nil
		})
	}

	// Wait for all detectors to complete
	if err := g.Wait(); err != nil {
		close(resultChan)
		result.TunnelResult = tunnelResult
		return err
	}
	close(resultChan)

	// Collect and merge results
	var bestResult *tunnel.DetectionResult
	bestConfidence := 0 // 0=none, 1=low, 2=medium, 3=high

	for dr := range resultChan {
		// Determine confidence score
		confidence := 0
		switch dr.Confidence {
		case "low":
			confidence = 1
		case "medium":
			confidence = 2
		case "high":
			confidence = 3
		}

		// Keep the highest confidence result
		if confidence > bestConfidence {
			bestConfidence = confidence
			bestResult = dr
		}

		// Merge indicators
		tunnelResult.AllIndicators = append(tunnelResult.AllIndicators, dr.Indicators...)
	}

	// Set final result
	if bestResult != nil {
		tunnelResult.IsTunnel = true
		tunnelResult.TunnelType = bestResult.DetectorName
		tunnelResult.Confidence = bestResult.Confidence
	}

	result.TunnelResult = tunnelResult
	return nil
}
