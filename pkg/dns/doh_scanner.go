package dns

import (
	"context"

	"github.com/miekg/dns"
)

// DoHScanner implements Scanner for DNS over HTTPS
type DoHScanner struct {
	opts        QueryOptions
	testDomains []string
}

// NewDoHScanner creates a new DoH scanner
func NewDoHScanner(opts QueryOptions, testDomains []string) *DoHScanner {
	if len(testDomains) == 0 {
		testDomains = []string{"chatgpt.com", "google.com", "microsoft.com"}
	}
	return &DoHScanner{opts: opts, testDomains: testDomains}
}

// Name returns the scanner name
func (s *DoHScanner) Name() string {
	return "doh"
}

// Scan performs DoH scan
func (s *DoHScanner) Scan(ctx context.Context, ip string) (*ScanResult, error) {
	result := &ScanResult{
		ScannerName:     s.Name(),
		DomainsResolved: []string{},
	}

	// Use first test domain
	testDomain := s.testDomains[0]

	// Try common DoH endpoints
	for _, endpoint := range CommonDoHEndpoints {
		resp, rtt, err := QueryDoH(ctx, ip, testDomain, dns.TypeA, endpoint, s.opts)
		if err != nil {
			continue
		}

		if resp.Rcode == dns.RcodeSuccess {
			result.Success = true
			result.ResponseTime = rtt
			result.Endpoint = endpoint.Path
			if len(resp.Answer) > 0 {
				result.DomainsResolved = append(result.DomainsResolved, testDomain)
			}
			result.Recursive = resp.RecursionAvailable
			break
		}
	}

	if !result.Success {
		result.Error = "no working DoH endpoint found"
	}

	return result, nil
}
