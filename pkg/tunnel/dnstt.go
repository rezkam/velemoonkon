package tunnel

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DetectDNSTT detects DNSTT tunnel characteristics
// DNSTT uses TXT records with base32-encoded subdomains
// Key indicator: Authoritative Answer (AA) bit set
func DetectDNSTT(ctx context.Context, server string, domain string) (*DNSTTIndicators, error) {
	indicators := &DNSTTIndicators{}

	client := &dns.Client{
		Net:     "udp",
		Timeout: 3 * time.Second,
	}

	serverAddr := server
	if !strings.Contains(server, ":") {
		serverAddr = server + ":53"
	}

	// Test 1: Query with base32-encoded subdomain
	base32Subdomain := GenerateRandomSubdomain(32) // DNSTT uses base32
	testDomain := fmt.Sprintf("%s.%s", base32Subdomain, domain)

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(testDomain), dns.TypeTXT)
	msg.RecursionDesired = false // DNSTT servers are authoritative

	// Add EDNS(0)
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	msg.Extra = append(msg.Extra, opt)
	indicators.UsesEDNS = true

	resp, _, err := client.ExchangeContext(ctx, msg, serverAddr)
	if err != nil {
		return indicators, fmt.Errorf("DNSTT query failed: %w", err)
	}

	if resp == nil {
		return indicators, fmt.Errorf("empty response")
	}

	// Check for Authoritative Answer bit (KEY INDICATOR)
	if resp.Authoritative {
		indicators.HasAuthoritativeAnswer = true
	}

	// Check for NOERROR response to random subdomain
	if resp.Rcode == dns.RcodeSuccess {
		indicators.RespondsToBase32 = true
	}

	// Check for TXT records
	if len(resp.Answer) > 0 {
		indicators.TXTRecordFound = true

		// Analyze TXT record content
		for _, ans := range resp.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				for _, str := range txt.Txt {
					data := []byte(str)

					// Check entropy
					entropy := CalculateEntropy(data)
					indicators.Entropy = entropy

					// Check for binary data
					if HasBinaryData(data) {
						indicators.HasBinaryData = true
					}

					// Check TTL (DNSTT often uses TTL=60)
					if ans.Header().Ttl == 60 {
						indicators.TTLEquals60 = true
					}
				}
			}
		}
	}

	return indicators, nil
}

// IsDNSTT determines if indicators suggest DNSTT tunnel
func IsDNSTT(indicators *DNSTTIndicators) (bool, string) {
	if indicators == nil {
		return false, "low"
	}

	score := 0

	// AA bit is the most critical indicator
	if indicators.HasAuthoritativeAnswer {
		score += 2 // Weight this heavily
	}

	if indicators.RespondsToBase32 {
		score++
	}

	if indicators.TXTRecordFound {
		score++
	}

	if indicators.HasBinaryData || indicators.Entropy > 5.0 {
		score++
	}

	if indicators.TTLEquals60 {
		score++
	}

	// Confidence levels
	if score >= 5 {
		return true, "high"
	} else if score >= 3 {
		return true, "medium"
	} else if score >= 2 {
		return true, "low"
	}

	return false, "low"
}
