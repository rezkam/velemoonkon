package dns

import (
	"context"

	"github.com/miekg/dns"
)

// UDPScanner implements Scanner for UDP DNS
type UDPScanner struct {
	opts        QueryOptions
	testDomains []string
}

// NewUDPScanner creates a new UDP DNS scanner
func NewUDPScanner(opts QueryOptions, testDomains []string) *UDPScanner {
	if len(testDomains) == 0 {
		testDomains = []string{"chatgpt.com", "google.com", "microsoft.com"}
	}
	return &UDPScanner{opts: opts, testDomains: testDomains}
}

// Name returns the scanner name
func (s *UDPScanner) Name() string {
	return "udp"
}

// Scan performs UDP DNS scan
func (s *UDPScanner) Scan(ctx context.Context, ip string) (*ScanResult, error) {
	result := &ScanResult{
		ScannerName:     s.Name(),
		DomainsResolved: []string{},
	}

	for _, domain := range s.testDomains {
		resp, rtt, err := QueryUDP(ctx, ip, domain, dns.TypeA, s.opts)
		if err != nil {
			continue
		}

		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			result.Success = true
			result.ResponseTime = rtt
			result.DomainsResolved = append(result.DomainsResolved, domain)
			result.Recursive = resp.RecursionAvailable

			if resp.IsEdns0() != nil {
				result.SupportsEDNS = true
			}
		}
	}

	if !result.Success {
		result.Error = "no successful queries"
	}

	return result, nil
}
