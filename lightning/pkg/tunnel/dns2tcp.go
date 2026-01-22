package tunnel

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DetectDNS2TCP detects DNS2TCP tunnel characteristics
// DNS2TCP primarily uses TXT and KEY records
func DetectDNS2TCP(ctx context.Context, server string, domain string) (*DNS2TCPIndicators, error) {
	indicators := &DNS2TCPIndicators{}

	client := &dns.Client{
		Net:     "udp",
		Timeout: 3 * time.Second,
	}

	serverAddr := server
	if !strings.Contains(server, ":") {
		serverAddr = server + ":53"
	}

	testDomain := fmt.Sprintf("%s.%s", GenerateRandomSubdomain(16), domain)

	// Test 1: TXT record query
	msgTXT := new(dns.Msg)
	msgTXT.SetQuestion(dns.Fqdn(testDomain), dns.TypeTXT)
	msgTXT.RecursionDesired = false

	respTXT, _, err := client.ExchangeContext(ctx, msgTXT, serverAddr)
	if err == nil && respTXT != nil {
		if respTXT.Rcode == dns.RcodeSuccess && len(respTXT.Answer) > 0 {
			indicators.RespondsToTXT = true
			indicators.TXTRecordFound = true
		}
	}

	// Test 2: KEY record query (type 25)
	msgKEY := new(dns.Msg)
	msgKEY.SetQuestion(dns.Fqdn(testDomain), dns.TypeKEY)
	msgKEY.RecursionDesired = false

	respKEY, _, err := client.ExchangeContext(ctx, msgKEY, serverAddr)
	if err == nil && respKEY != nil {
		if respKEY.Rcode == dns.RcodeSuccess && len(respKEY.Answer) > 0 {
			indicators.RespondsToKEY = true
			indicators.KEYRecordFound = true
		}
	}

	return indicators, nil
}

// IsDNS2TCP determines if indicators suggest DNS2TCP tunnel
func IsDNS2TCP(indicators *DNS2TCPIndicators) (bool, string) {
	if indicators == nil {
		return false, "low"
	}

	score := 0

	if indicators.TXTRecordFound {
		score++
	}

	if indicators.KEYRecordFound {
		score += 2 // KEY records are stronger indicator
	}

	if indicators.RespondsToTXT {
		score++
	}

	if indicators.RespondsToKEY {
		score++
	}

	// Confidence levels
	if score >= 3 {
		return true, "high"
	} else if score >= 2 {
		return true, "medium"
	} else if score >= 1 {
		return true, "low"
	}

	return false, "low"
}
