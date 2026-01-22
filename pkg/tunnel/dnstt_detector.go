package tunnel

import (
	"context"
	"fmt"
)

// DNSTTDetector implements Detector for DNSTT tunnels
type DNSTTDetector struct{}

// NewDNSTTDetector creates a new DNSTT detector
func NewDNSTTDetector() *DNSTTDetector {
	return &DNSTTDetector{}
}

// Name returns the detector name
func (d *DNSTTDetector) Name() string {
	return "dnstt"
}

// Detect performs DNSTT detection
func (d *DNSTTDetector) Detect(ctx context.Context, ip string, domain string) (*DetectionResult, error) {
	result := &DetectionResult{
		DetectorName: d.Name(),
		Indicators:   []string{},
	}

	// Use default domain if not provided
	if domain == "" {
		domain = "test.example.com"
	}

	indicators, err := DetectDNSTT(ctx, ip, domain)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	result.RawData = indicators

	// Check if tunnel is detected
	isTunnel, confidence := IsDNSTT(indicators)
	result.IsTunnel = isTunnel
	result.Confidence = confidence

	// Build indicators list
	if indicators.HasAuthoritativeAnswer {
		result.Indicators = append(result.Indicators, "Authoritative Answer bit set")
	}
	if indicators.RespondsToBase32 {
		result.Indicators = append(result.Indicators, "Responds to base32 subdomains")
	}
	if indicators.TXTRecordFound {
		result.Indicators = append(result.Indicators, "TXT records present")
	}
	if indicators.HasBinaryData {
		result.Indicators = append(result.Indicators, "Binary data in responses")
	}
	if indicators.TTLEquals60 {
		result.Indicators = append(result.Indicators, "TTL=60 pattern")
	}
	if indicators.UsesEDNS {
		result.Indicators = append(result.Indicators, "EDNS support")
	}
	if indicators.Entropy > 5.0 {
		result.Indicators = append(result.Indicators, fmt.Sprintf("High entropy (%.2f)", indicators.Entropy))
	}

	return result, nil
}
