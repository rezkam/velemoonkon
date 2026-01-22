package tunnel

import (
	"context"
	"fmt"
)

// IodineDetector implements Detector for Iodine tunnels
type IodineDetector struct{}

// NewIodineDetector creates a new Iodine detector
func NewIodineDetector() *IodineDetector {
	return &IodineDetector{}
}

// Name returns the detector name
func (d *IodineDetector) Name() string {
	return "iodine"
}

// Detect performs Iodine detection
func (d *IodineDetector) Detect(ctx context.Context, ip string, domain string) (*DetectionResult, error) {
	result := &DetectionResult{
		DetectorName: d.Name(),
		Indicators:   []string{},
	}

	// Use default domain if not provided
	if domain == "" {
		domain = "test.example.com"
	}

	indicators, err := DetectIodine(ctx, ip, domain)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	result.RawData = indicators

	// Check if tunnel is detected
	isTunnel, confidence := IsIodine(indicators)
	result.IsTunnel = isTunnel
	result.Confidence = confidence

	// Build indicators list
	if indicators.RespondsToNULL {
		result.Indicators = append(result.Indicators, "Responds to NULL records")
	}
	if indicators.HasVersionHandshake {
		result.Indicators = append(result.Indicators, "Iodine version handshake detected")
	}
	if indicators.Base128Detected {
		result.Indicators = append(result.Indicators, "Base128 encoding detected")
	}
	if indicators.HighEntropy {
		result.Indicators = append(result.Indicators, fmt.Sprintf("High entropy (%.2f)", indicators.Entropy))
	}
	if indicators.HasAuthoritativeAnswer {
		result.Indicators = append(result.Indicators, "Authoritative Answer bit set")
	}

	return result, nil
}
