package tunnel

import (
	"context"
	"fmt"
)

// DNScat2Detector implements Detector for DNScat2 tunnels
type DNScat2Detector struct{}

// NewDNScat2Detector creates a new DNScat2 detector
func NewDNScat2Detector() *DNScat2Detector {
	return &DNScat2Detector{}
}

// Name returns the detector name
func (d *DNScat2Detector) Name() string {
	return "dnscat2"
}

// Detect performs DNScat2 detection
func (d *DNScat2Detector) Detect(ctx context.Context, ip string, domain string) (*DetectionResult, error) {
	result := &DetectionResult{
		DetectorName: d.Name(),
		Indicators:   []string{},
	}

	// Use default domain if not provided
	if domain == "" {
		domain = "test.example.com"
	}

	indicators, err := DetectDNScat2(ctx, ip, domain)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	result.RawData = indicators

	// Check if tunnel is detected
	isTunnel, confidence := IsDNScat2(indicators)
	result.IsTunnel = isTunnel
	result.Confidence = confidence

	// Build indicators list
	if indicators.MultiTypeResponses {
		result.Indicators = append(result.Indicators, "Responds to multiple record types")
	}
	if indicators.HexEncodedData {
		result.Indicators = append(result.Indicators, "Hex-encoded data detected")
	}
	if indicators.HighEntropy {
		result.Indicators = append(result.Indicators, fmt.Sprintf("High entropy (%.2f)", indicators.Entropy))
	}
	if indicators.HasAuthoritativeAnswer {
		result.Indicators = append(result.Indicators, "Authoritative Answer bit set")
	}
	if indicators.ConsistentResponses {
		result.Indicators = append(result.Indicators, "Consistent responses across record types")
	}

	return result, nil
}
