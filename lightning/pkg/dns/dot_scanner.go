package dns

import (
	"context"

	"github.com/miekg/dns"
)

// DoTScanner implements Scanner for DNS over TLS
type DoTScanner struct {
	opts        QueryOptions
	testDomains []string
}

// NewDoTScanner creates a new DoT scanner
func NewDoTScanner(opts QueryOptions, testDomains []string) *DoTScanner {
	if len(testDomains) == 0 {
		testDomains = []string{"chatgpt.com", "google.com", "microsoft.com"}
	}
	return &DoTScanner{opts: opts, testDomains: testDomains}
}

// Name returns the scanner name
func (s *DoTScanner) Name() string {
	return "dot"
}

// Scan performs DoT scan
func (s *DoTScanner) Scan(ctx context.Context, ip string) (*ScanResult, error) {
	result := &ScanResult{
		ScannerName:     s.Name(),
		DomainsResolved: []string{},
	}

	// Use first test domain
	testDomain := s.testDomains[0]

	resp, rtt, err := QueryDoT(ctx, ip, testDomain, dns.TypeA, s.opts)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	if resp.Rcode == dns.RcodeSuccess {
		result.Success = true
		result.ResponseTime = rtt
		result.DomainsResolved = append(result.DomainsResolved, testDomain)
		result.Recursive = resp.RecursionAvailable
	} else {
		result.Error = "query failed"
	}

	return result, nil
}
