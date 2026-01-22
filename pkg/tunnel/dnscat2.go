package tunnel

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DetectDNScat2 detects DNScat2 tunnel characteristics
// DNScat2 rotates between TXT, CNAME, and MX records
// Uses hex-encoded data with high entropy
func DetectDNScat2(ctx context.Context, server string, domain string) (*DNScat2Indicators, error) {
	indicators := &DNScat2Indicators{}

	client := &dns.Client{
		Net:     "udp",
		Timeout: 3 * time.Second,
	}

	serverAddr := server
	if !strings.Contains(server, ":") {
		serverAddr = server + ":53"
	}

	testDomain := fmt.Sprintf("%s.%s", GenerateRandomSubdomain(16), domain)
	recordTypes := []uint16{dns.TypeTXT, dns.TypeCNAME, dns.TypeMX}
	responseCount := 0
	totalEntropy := 0.0
	hasHexData := false
	hasAA := false

	// Test multiple record types
	for _, qtype := range recordTypes {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(testDomain), qtype)
		msg.RecursionDesired = false

		resp, _, err := client.ExchangeContext(ctx, msg, serverAddr)
		if err != nil || resp == nil {
			continue
		}

		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			responseCount++

			// Check AA bit
			if resp.Authoritative {
				hasAA = true
			}

			// Analyze response data
			for _, ans := range resp.Answer {
				var data []byte

				switch qtype {
				case dns.TypeTXT:
					if txt, ok := ans.(*dns.TXT); ok {
						data = []byte(strings.Join(txt.Txt, ""))
					}
				case dns.TypeCNAME:
					if cname, ok := ans.(*dns.CNAME); ok {
						data = []byte(cname.Target)
					}
				case dns.TypeMX:
					if mx, ok := ans.(*dns.MX); ok {
						data = []byte(mx.Mx)
					}
				}

				if len(data) > 0 {
					// Calculate entropy
					entropy := CalculateEntropy(data)
					totalEntropy += entropy

					// Check for hex encoding
					encoding := DetectEncoding(string(data))
					if encoding == "hex" {
						hasHexData = true
					}
				}
			}
		}
	}

	// Set indicators
	if responseCount >= 2 {
		indicators.MultiTypeResponses = true
	}

	if hasHexData {
		indicators.HexEncodedData = true
	}

	avgEntropy := 0.0
	if responseCount > 0 {
		avgEntropy = totalEntropy / float64(responseCount)
	}
	indicators.Entropy = avgEntropy

	if avgEntropy > 4.0 {
		indicators.HighEntropy = true
	}

	if hasAA {
		indicators.HasAuthoritativeAnswer = true
	}

	// Check for consistent responses (same data across types)
	if responseCount >= 2 {
		indicators.ConsistentResponses = true
	}

	return indicators, nil
}

// IsDNScat2 determines if indicators suggest DNScat2 tunnel
func IsDNScat2(indicators *DNScat2Indicators) (bool, string) {
	if indicators == nil {
		return false, "low"
	}

	score := 0

	if indicators.MultiTypeResponses {
		score += 2 // Strong indicator
	}

	if indicators.HexEncodedData {
		score++
	}

	if indicators.HighEntropy {
		score++
	}

	if indicators.HasAuthoritativeAnswer {
		score++
	}

	if indicators.ConsistentResponses {
		score++
	}

	// Confidence levels
	if score >= 4 {
		return true, "high"
	} else if score >= 3 {
		return true, "medium"
	} else if score >= 2 {
		return true, "low"
	}

	return false, "low"
}
