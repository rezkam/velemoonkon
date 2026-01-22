package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/velemoonkon/lightning/pkg/dns"
	"github.com/velemoonkon/lightning/pkg/tunnel"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

// Scanner orchestrates concurrent IP scanning
type Scanner struct {
	config          Config
	limiter         *rate.Limiter
	dnsRegistry     *dns.Registry
	tunnelRegistry  *tunnel.Registry
	dnsScanners     []dns.Scanner
	tunnelDetectors []tunnel.Detector
}

// NewScanner creates a new scanner with configuration
func NewScanner(config Config) *Scanner {
	// Create rate limiter
	limiter := rate.NewLimiter(rate.Limit(config.RateLimit), config.RateLimit)

	// Create registries
	dnsRegistry := dns.NewDefaultRegistry(config.TestDomains)
	tunnelRegistry := tunnel.NewDefaultRegistry()

	// Select scanners based on config
	var dnsScanners []dns.Scanner
	if config.EnableUDP {
		if scanner, ok := dnsRegistry.Get("udp"); ok {
			dnsScanners = append(dnsScanners, scanner)
		}
	}
	if config.EnableTCP {
		if scanner, ok := dnsRegistry.Get("tcp"); ok {
			dnsScanners = append(dnsScanners, scanner)
		}
	}
	if config.EnableDoT {
		if scanner, ok := dnsRegistry.Get("dot"); ok {
			dnsScanners = append(dnsScanners, scanner)
		}
	}
	if config.EnableDoH {
		if scanner, ok := dnsRegistry.Get("doh"); ok {
			dnsScanners = append(dnsScanners, scanner)
		}
	}

	// Select detectors based on config
	var tunnelDetectors []tunnel.Detector
	if config.EnableTunnel {
		if config.TunnelDNSTT {
			if detector, ok := tunnelRegistry.Get("dnstt"); ok {
				tunnelDetectors = append(tunnelDetectors, detector)
			}
		}
		if config.TunnelIodine {
			if detector, ok := tunnelRegistry.Get("iodine"); ok {
				tunnelDetectors = append(tunnelDetectors, detector)
			}
		}
		if config.TunnelDNScat2 {
			if detector, ok := tunnelRegistry.Get("dnscat2"); ok {
				tunnelDetectors = append(tunnelDetectors, detector)
			}
		}
		if config.TunnelDNS2TCP {
			if detector, ok := tunnelRegistry.Get("dns2tcp"); ok {
				tunnelDetectors = append(tunnelDetectors, detector)
			}
		}
	}

	return &Scanner{
		config:          config,
		limiter:         limiter,
		dnsRegistry:     dnsRegistry,
		tunnelRegistry:  tunnelRegistry,
		dnsScanners:     dnsScanners,
		tunnelDetectors: tunnelDetectors,
	}
}

// Scan scans a list of IPs and returns results
func (s *Scanner) Scan(ctx context.Context, ips []net.IP) ([]*ScanResult, error) {
	ipChan := make(chan net.IP, 1000)
	resultChan := make(chan *ScanResult, 1000)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < s.config.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(ctx, ipChan, resultChan)
		}()
	}

	// Start result collector
	var results []*ScanResult
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for result := range resultChan {
			results = append(results, result)
			if !s.config.Quiet {
				s.logProgress(result)
			}
		}
	}()

	// Feed IPs to workers
	go func() {
		for _, ip := range ips {
			// Apply rate limiting
			if err := s.limiter.Wait(ctx); err != nil {
				break
			}
			ipChan <- ip
		}
		close(ipChan)
	}()

	// Wait for workers to complete
	wg.Wait()
	close(resultChan)

	// Wait for collector to finish
	collectorWg.Wait()

	return results, nil
}

// worker processes individual IPs
func (s *Scanner) worker(ctx context.Context, ipChan <-chan net.IP, resultChan chan<- *ScanResult) {
	for ip := range ipChan {
		// Create timeout context for this IP
		ipCtx, cancel := context.WithTimeout(ctx, time.Duration(s.config.Timeout)*time.Second)
		result := s.scanIP(ipCtx, ip.String())
		cancel()

		resultChan <- result
	}
}

// scanIP performs all enabled scans on a single IP
func (s *Scanner) scanIP(ctx context.Context, ip string) *ScanResult {
	start := time.Now()
	result := &ScanResult{
		IP: ip,
	}

	// DNS Testing
	if len(s.dnsScanners) > 0 {
		dnsResult, err := s.testDNS(ctx, ip)
		if err != nil && s.config.Verbose {
			fmt.Printf("[%s] DNS test error: %v\n", ip, err)
		}
		result.DNSResult = dnsResult
	}

	// Tunnel Detection
	if len(s.tunnelDetectors) > 0 {
		tunnelResult, err := s.detectTunnel(ctx, ip)
		if err != nil && s.config.Verbose {
			fmt.Printf("[%s] Tunnel detection error: %v\n", ip, err)
		}
		result.TunnelResult = tunnelResult
	}

	// Port Scanning
	if s.config.EnablePortScan {
		openPorts := ScanDNSPorts(ctx, ip)
		result.OpenPorts = openPorts
	}

	result.ScanTime = time.Since(start).Milliseconds()
	return result
}

// testDNS performs DNS tests using registered scanners with bounded concurrency using errgroup
func (s *Scanner) testDNS(ctx context.Context, ip string) (*dns.TestResult, error) {
	result := &dns.TestResult{
		IP:                  ip,
		TestDomainsResolved: []string{},
		TestDomainsFailed:   []string{},
	}

	if len(s.dnsScanners) == 0 {
		return result, nil
	}

	// Use errgroup with SetLimit for bounded concurrency
	g, ctx := errgroup.WithContext(ctx)
	concurrency := s.config.DNSConcurrency
	if concurrency <= 0 || concurrency > len(s.dnsScanners) {
		concurrency = len(s.dnsScanners)
	}
	g.SetLimit(concurrency)

	// Channel for collecting results (buffered to prevent blocking)
	type scannerResult struct {
		name       string
		scanResult *dns.ScanResult
	}
	resultChan := make(chan scannerResult, len(s.dnsScanners))

	// Launch scanners with bounded concurrency
	for _, scanner := range s.dnsScanners {
		scanner := scanner // Capture loop variable
		g.Go(func() error {
			scanResult, err := scanner.Scan(ctx, ip)
			if err != nil {
				if s.config.Verbose {
					fmt.Printf("[%s] %s scanner error: %v\n", ip, scanner.Name(), err)
				}
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
		return result, err
	}
	close(resultChan)

	// Merge results
	for sr := range resultChan {
		switch sr.name {
		case "udp":
			result.UDPPortOpen = true
			result.RespondsToQueries = true
			result.SupportsRecursion = sr.scanResult.Recursive
			result.SupportsEDNS = sr.scanResult.SupportsEDNS
			result.TestDomainsResolved = append(result.TestDomainsResolved, sr.scanResult.DomainsResolved...)
			if result.DNSServerType == "" {
				if sr.scanResult.Recursive {
					result.DNSServerType = "recursive"
				} else {
					result.DNSServerType = "authoritative"
				}
			}
		case "tcp":
			result.TCPPortOpen = true
			result.SupportsTCP = true
		case "dot":
			result.SupportsDoT = true
			result.DoTResponseTime = sr.scanResult.ResponseTime
			if sr.scanResult.Error != "" {
				result.DoTError = sr.scanResult.Error
			}
		case "doh":
			result.SupportsDoH = true
			result.DoHEndpoint = sr.scanResult.Endpoint
			result.DoHResponseTime = sr.scanResult.ResponseTime
			if sr.scanResult.Error != "" {
				result.DoHError = sr.scanResult.Error
			}
		}
	}

	return result, nil
}

// detectTunnel performs tunnel detection using registered detectors with bounded concurrency using errgroup
func (s *Scanner) detectTunnel(ctx context.Context, ip string) (*tunnel.Result, error) {
	result := &tunnel.Result{
		IP:            ip,
		AllIndicators: []string{},
	}

	if len(s.tunnelDetectors) == 0 {
		return result, nil
	}

	domain := s.config.TunnelDomain
	if domain == "" {
		domain = "test.example.com"
	}

	// Use errgroup with SetLimit for bounded concurrency
	g, ctx := errgroup.WithContext(ctx)
	concurrency := s.config.DNSConcurrency
	if concurrency <= 0 || concurrency > len(s.tunnelDetectors) {
		concurrency = len(s.tunnelDetectors)
	}
	g.SetLimit(concurrency)

	// Channel for collecting results (buffered to prevent blocking)
	resultChan := make(chan *tunnel.DetectionResult, len(s.tunnelDetectors))

	// Launch detectors with bounded concurrency
	for _, detector := range s.tunnelDetectors {
		detector := detector // Capture loop variable
		g.Go(func() error {
			detectionResult, err := detector.Detect(ctx, ip, domain)
			if err != nil {
				if s.config.Verbose {
					fmt.Printf("[%s] %s detector error: %v\n", ip, detector.Name(), err)
				}
				// Don't fail the entire detection if one detector fails
				return nil
			}

			if detectionResult != nil && detectionResult.IsTunnel {
				resultChan <- detectionResult
			}
			return nil
		})
	}

	// Wait for all detectors to complete
	if err := g.Wait(); err != nil {
		close(resultChan)
		return result, err
	}
	close(resultChan)

	// Collect and merge results
	var bestResult *tunnel.DetectionResult
	bestConfidence := 0 // 0=none, 1=low, 2=medium, 3=high

	for dr := range resultChan {
		// Determine confidence score
		confidence := 0
		switch dr.Confidence {
		case "low":
			confidence = 1
		case "medium":
			confidence = 2
		case "high":
			confidence = 3
		}

		// Keep the highest confidence result
		if confidence > bestConfidence {
			bestConfidence = confidence
			bestResult = dr
		}

		// Merge indicators
		result.AllIndicators = append(result.AllIndicators, dr.Indicators...)
	}

	// Set final result
	if bestResult != nil {
		result.IsTunnel = true
		result.TunnelType = bestResult.DetectorName
		result.Confidence = bestResult.Confidence
	}

	return result, nil
}

// logProgress logs scan progress
func (s *Scanner) logProgress(result *ScanResult) {
	if result.DNSResult != nil && result.DNSResult.RespondsToQueries {
		fmt.Printf("[✓] %s - DNS: %s", result.IP, result.DNSResult.DNSServerType)
		if result.DNSResult.SupportsDoT {
			fmt.Print(" | DoT")
		}
		if result.DNSResult.SupportsDoH {
			fmt.Printf(" | DoH(%s)", result.DNSResult.DoHEndpoint)
		}
		if result.TunnelResult != nil && result.TunnelResult.IsTunnel {
			fmt.Printf(" | TUNNEL: %s (%s)", result.TunnelResult.TunnelType, result.TunnelResult.Confidence)
		}
		fmt.Println()
	}
}
