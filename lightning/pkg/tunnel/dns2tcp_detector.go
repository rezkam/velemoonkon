package tunnel

import (
	"context"
)

// DNS2TCPDetector implements Detector for DNS2TCP tunnels
type DNS2TCPDetector struct{}

// NewDNS2TCPDetector creates a new DNS2TCP detector
func NewDNS2TCPDetector() *DNS2TCPDetector {
	return &DNS2TCPDetector{}
}

// Name returns the detector name
func (d *DNS2TCPDetector) Name() string {
	return "dns2tcp"
}

// Detect performs DNS2TCP detection
func (d *DNS2TCPDetector) Detect(ctx context.Context, ip string, domain string) (*DetectionResult, error) {
	result := &DetectionResult{
		DetectorName: d.Name(),
		Indicators:   []string{},
	}

	// Use default domain if not provided
	if domain == "" {
		domain = "test.example.com"
	}

	indicators, err := DetectDNS2TCP(ctx, ip, domain)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	result.RawData = indicators

	// Check if tunnel is detected
	isTunnel, confidence := IsDNS2TCP(indicators)
	result.IsTunnel = isTunnel
	result.Confidence = confidence

	// Build indicators list
	if indicators.TXTRecordFound {
		result.Indicators = append(result.Indicators, "TXT records present")
	}
	if indicators.KEYRecordFound {
		result.Indicators = append(result.Indicators, "KEY records present")
	}
	if indicators.RespondsToTXT {
		result.Indicators = append(result.Indicators, "Responds to TXT queries")
	}
	if indicators.RespondsToKEY {
		result.Indicators = append(result.Indicators, "Responds to KEY queries")
	}

	return result, nil
}
