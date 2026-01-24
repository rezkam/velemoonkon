package scanner

import (
	"context"
	"log/slog"

	"github.com/velemoonkon/lightning/pkg/dns"
	"golang.org/x/sync/errgroup"
)

// DNSProbe implements the Probe interface for DNS scanning
type DNSProbe struct {
	registry    *dns.Registry
	scanners    []dns.Scanner
	concurrency int
}

// NewDNSProbe creates a new DNS probe with the given configuration
func NewDNSProbe(cfg Config) *DNSProbe {
	// Create registry with test domains
	registry := dns.NewDefaultRegistry(cfg.TestDomains)

	// Select scanners based on config
	var scanners []dns.Scanner
	if cfg.EnableUDP {
		if scanner, ok := registry.Get("udp"); ok {
			scanners = append(scanners, scanner)
		}
	}
	if cfg.EnableTCP {
		if scanner, ok := registry.Get("tcp"); ok {
			scanners = append(scanners, scanner)
		}
	}
	if cfg.EnableDoT {
		if scanner, ok := registry.Get("dot"); ok {
			scanners = append(scanners, scanner)
		}
	}
	if cfg.EnableDoH {
		if scanner, ok := registry.Get("doh"); ok {
			scanners = append(scanners, scanner)
		}
	}

	concurrency := cfg.DNSConcurrency
	if concurrency <= 0 {
		concurrency = len(scanners)
	}

	return &DNSProbe{
		registry:    registry,
		scanners:    scanners,
		concurrency: concurrency,
	}
}

// Name returns the probe identifier
func (p *DNSProbe) Name() string {
	return "dns"
}

// HasScanners returns true if any DNS scanners are enabled
func (p *DNSProbe) HasScanners() bool {
	return len(p.scanners) > 0
}

// Scan performs DNS tests on the given IP and populates the result
func (p *DNSProbe) Scan(ctx context.Context, ip string, result *ScanResult) error {
	dnsResult := &dns.TestResult{
		IP:                  ip,
		TestDomainsResolved: []string{},
		TestDomainsFailed:   []string{},
	}

	if len(p.scanners) == 0 {
		result.DNSResult = dnsResult
		return nil
	}

	// Use errgroup with SetLimit for bounded concurrency
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(min(p.concurrency, len(p.scanners)))

	// Channel for collecting results (buffered to prevent blocking)
	type scannerResult struct {
		name       string
		scanResult *dns.ScanResult
	}
	resultChan := make(chan scannerResult, len(p.scanners))

	// Launch scanners with bounded concurrency
	for _, scanner := range p.scanners {
		g.Go(func() error {
			scanResult, err := scanner.Scan(ctx, ip)
			if err != nil {
				slog.Debug("scanner error",
					"ip", ip,
					"scanner", scanner.Name(),
					"error", err)
				// Don't fail the entire scan if one scanner fails
				return nil
			}

			if scanResult != nil && scanResult.Success {
				resultChan <- scannerResult{
					name:       scanner.Name(),
					scanResult: scanResult,
				}
			}
			return nil
		})
	}

	// Wait for all scanners to complete
	if err := g.Wait(); err != nil {
		close(resultChan)
		result.DNSResult = dnsResult
		return err
	}
	close(resultChan)

	// Merge results
	for sr := range resultChan {
		switch sr.name {
		case "udp":
			dnsResult.UDPPortOpen = true
			dnsResult.RespondsToQueries = true
			dnsResult.SupportsRecursion = sr.scanResult.Recursive
			dnsResult.SupportsEDNS = sr.scanResult.SupportsEDNS
			dnsResult.TestDomainsResolved = append(dnsResult.TestDomainsResolved, sr.scanResult.DomainsResolved...)
			if dnsResult.DNSServerType == "" {
				if sr.scanResult.Recursive {
					dnsResult.DNSServerType = "recursive"
				} else {
					dnsResult.DNSServerType = "authoritative"
				}
			}
		case "tcp":
			dnsResult.TCPPortOpen = true
			dnsResult.SupportsTCP = true
		case "dot":
			dnsResult.SupportsDoT = true
			dnsResult.DoTResponseTime = sr.scanResult.ResponseTime
			dnsResult.DoTResponseTimeMs = dns.Milliseconds(sr.scanResult.ResponseTime.Milliseconds())
			if sr.scanResult.Error != "" {
				dnsResult.DoTError = sr.scanResult.Error
			}
		case "doh":
			dnsResult.SupportsDoH = true
			dnsResult.DoHEndpoint = sr.scanResult.Endpoint
			dnsResult.DoHResponseTime = sr.scanResult.ResponseTime
			dnsResult.DoHResponseTimeMs = dns.Milliseconds(sr.scanResult.ResponseTime.Milliseconds())
			if sr.scanResult.Error != "" {
				dnsResult.DoHError = sr.scanResult.Error
			}
		}
	}

	result.DNSResult = dnsResult
	return nil
}
