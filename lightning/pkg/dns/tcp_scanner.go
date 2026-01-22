package dns

import (
	"context"

	"github.com/miekg/dns"
)

// TCPScanner implements Scanner for TCP DNS
type TCPScanner struct {
	opts        QueryOptions
	testDomains []string
}

// NewTCPScanner creates a new TCP DNS scanner
func NewTCPScanner(opts QueryOptions, testDomains []string) *TCPScanner {
	if len(testDomains) == 0 {
		testDomains = []string{"chatgpt.com", "google.com", "microsoft.com"}
	}
	return &TCPScanner{opts: opts, testDomains: testDomains}
}

// Name returns the scanner name
func (s *TCPScanner) Name() string {
	return "tcp"
}

// Scan performs TCP DNS scan
func (s *TCPScanner) Scan(ctx context.Context, ip string) (*ScanResult, error) {
	result := &ScanResult{
		ScannerName:     s.Name(),
		DomainsResolved: []string{},
	}

	for _, domain := range s.testDomains {
		resp, rtt, err := QueryTCP(ctx, ip, domain, dns.TypeA, s.opts)
		if err != nil {
			continue
		}

		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			result.Success = true
			result.ResponseTime = rtt
			result.DomainsResolved = append(result.DomainsResolved, domain)
			result.Recursive = resp.RecursionAvailable
		}
	}

	if !result.Success {
		result.Error = "no successful queries"
	}

	return result, nil
}
