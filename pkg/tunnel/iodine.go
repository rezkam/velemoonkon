package tunnel

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DetectIodine detects Iodine tunnel characteristics
// Iodine uses NULL records (type 10) and has version handshake pattern
func DetectIodine(ctx context.Context, server string, domain string) (*IodineIndicators, error) {
	indicators := &IodineIndicators{}

	client := &dns.Client{
		Net:     "udp",
		Timeout: 3 * time.Second,
	}

	serverAddr := server
	if !strings.Contains(server, ":") {
		serverAddr = server + ":53"
	}

	// Test 1: Query for NULL record (type 10) - Iodine's preferred type
	testDomain := fmt.Sprintf("%s.%s", GenerateRandomSubdomain(16), domain)

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(testDomain), dns.TypeNULL)
	msg.RecursionDesired = false

	resp, _, err := client.ExchangeContext(ctx, msg, serverAddr)
	if err == nil && resp != nil {
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			indicators.RespondsToNULL = true

			// Check for NULL record data
			for _, ans := range resp.Answer {
				if null, ok := ans.(*dns.NULL); ok {
					data := []byte(null.Data)

					// Calculate entropy
					entropy := CalculateEntropy(data)
					indicators.Entropy = entropy

					if entropy > 5.0 {
						indicators.HighEntropy = true
					}

					// Check for base128 encoding
					if IsBase128(data) {
						indicators.Base128Detected = true
					}

					// Check for version handshake pattern
					// Iodine sends 0x00000502 or "VACK"
					if len(data) >= 4 {
						hexData := hex.EncodeToString(data[:4])
						if hexData == "00000502" || strings.Contains(string(data), "VACK") {
							indicators.HasVersionHandshake = true
						}
					}
				}
			}

			// Check AA bit
			if resp.Authoritative {
				indicators.HasAuthoritativeAnswer = true
			}
		}
	}

	// Test 2: Try TXT record as fallback (Iodine can use multiple types)
	msg2 := new(dns.Msg)
	msg2.SetQuestion(dns.Fqdn(testDomain), dns.TypeTXT)
	msg2.RecursionDesired = false

	resp2, _, err2 := client.ExchangeContext(ctx, msg2, serverAddr)
	if err2 == nil && resp2 != nil && len(resp2.Answer) > 0 {
		for _, ans := range resp2.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				for _, str := range txt.Txt {
					data := []byte(str)
					entropy := CalculateEntropy(data)
					if entropy > indicators.Entropy {
						indicators.Entropy = entropy
					}
					if entropy > 5.0 {
						indicators.HighEntropy = true
					}
				}
			}
		}
	}

	return indicators, nil
}

// IsIodine determines if indicators suggest Iodine tunnel
func IsIodine(indicators *IodineIndicators) (bool, string) {
	if indicators == nil {
		return false, ""
	}

	score := 0

	// NULL record response is strong indicator
	if indicators.RespondsToNULL {
		score += 2
	}

	if indicators.HasVersionHandshake {
		score += 2 // Very strong indicator
	}

	if indicators.Base128Detected {
		score++
	}

	if indicators.HighEntropy {
		score++
	}

	if indicators.HasAuthoritativeAnswer {
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

	return false, ""
}
