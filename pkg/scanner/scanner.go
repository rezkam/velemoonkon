package scanner

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"net"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/velemoonkon/lightning/pkg/config"
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
	// Validate and sanitize config
	// Workers=0 means "auto": use max(4, 4*GOMAXPROCS) for I/O-bound scanning
	// This provides reasonable concurrency: 4 minimum on single-core, scales with CPUs
	if config.Workers <= 0 {
		cpus := runtime.GOMAXPROCS(0)
		config.Workers = max(4, cpus*4)
	}

	// Create rate limiter - treat RateLimit <= 0 as no limit
	var limiter *rate.Limiter
	if config.RateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(config.RateLimit), config.RateLimit)
	} else {
		limiter = rate.NewLimiter(rate.Inf, 0) // No rate limit
	}

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
// For streaming large CIDR ranges, use ScanIter() with an iterator to avoid allocating the full IP list
// Goroutine fan-out is bounded:
// - Workers goroutines process IPs from ipChan
// - Per IP: DNS tests use errgroup.SetLimit(DNSConcurrency), tunnel detectors use errgroup.SetLimit,
//   port scanning uses errgroup.SetLimit(5)
// - Total concurrent goroutines ≈ Workers + (Workers × max(DNSConcurrency, detectorCount, 5))
// - With auto-workers (CPUs × 10) this keeps concurrency proportional to available CPU cores
func (s *Scanner) Scan(ctx context.Context, ips []net.IP) ([]*ScanResult, error) {
	// Convert slice to iterator and use ScanIter for actual scanning
	return s.ScanIter(ctx, slices.Values(ips), len(ips))
}

// ScanIter scans IPs from an iterator and returns results
// This enables streaming scanning of large CIDR ranges without allocating the full IP list
// Example: scanner.ScanIter(ctx, input.IPRange("10.0.0.0/8"), 16777216)
//
// The sizeHint parameter is used for preallocating the result slice. Use 0 if unknown.
// Goroutine fan-out is identical to Scan() - see Scan() documentation for details
//
// Channel buffer sizes are configurable via LIGHTNING_SCANNER_IP_BUFFER and
// LIGHTNING_SCANNER_RESULT_BUFFER environment variables (default: 1000 each)
func (s *Scanner) ScanIter(ctx context.Context, ipSeq iter.Seq[net.IP], sizeHint int) ([]*ScanResult, error) {
	cfg := config.Scanner
	ipChan := make(chan net.IP, cfg.IPChannelBuffer)
	resultChan := make(chan *ScanResult, cfg.ResultChannelBuffer)
	var wg sync.WaitGroup

	// Start workers
	for range s.config.Workers {
		wg.Go(func() {
			s.worker(ctx, ipChan, resultChan)
		})
	}

	// Start result collector with preallocated slice
	var results []*ScanResult
	if sizeHint > 0 {
		results = make([]*ScanResult, 0, sizeHint)
	} else {
		results = make([]*ScanResult, 0)
	}

	var collectorWg sync.WaitGroup
	collectorWg.Go(func() {
		for result := range resultChan {
			results = append(results, result)
			if !s.config.Quiet {
				s.logProgress(result)
			}
		}
	})

	// Feed IPs to workers from iterator with cooperative cancellation
	go func() {
		defer close(ipChan)
		for ip := range ipSeq {
			// Check for cancellation before rate limiting
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Apply rate limiting
			if err := s.limiter.Wait(ctx); err != nil {
				return
			}

			// Send IP with cancellation check
			select {
			case <-ctx.Done():
				return
			case ipChan <- ip:
			}
		}
	}()

	// Wait for workers to complete
	wg.Wait()
	close(resultChan)

	// Wait for collector to finish
	collectorWg.Wait()

	return results, ctx.Err()
}

// ScanStream scans IPs from an iterator and calls resultHandler for each result
// This avoids accumulating results in memory, ideal for large scans (e.g., /8 ranges)
// The resultHandler is called synchronously, so it should be fast or buffer internally
// Returns total count of results processed
func (s *Scanner) ScanStream(ctx context.Context, ipSeq iter.Seq[net.IP], resultHandler func(*ScanResult) error) (int, error) {
	cfg := config.Scanner
	ipChan := make(chan net.IP, cfg.IPChannelBuffer)
	resultChan := make(chan *ScanResult, cfg.ResultChannelBuffer)
	var wg sync.WaitGroup

	// Start workers
	for range s.config.Workers {
		wg.Go(func() {
			s.worker(ctx, ipChan, resultChan)
		})
	}

	// Start result collector that calls handler instead of accumulating
	var collectorWg sync.WaitGroup
	var handlerErr error
	resultCount := 0
	collectorWg.Go(func() {
		for result := range resultChan {
			resultCount++
			if !s.config.Quiet {
				s.logProgress(result)
			}

			// Call user-provided handler
			if err := resultHandler(result); err != nil {
				handlerErr = err
				// Continue processing remaining results even if handler fails
			}
		}
	})

	// Feed IPs to workers from iterator with cooperative cancellation
	go func() {
		defer close(ipChan)
		for ip := range ipSeq {
			// Check for cancellation
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Apply rate limiting
			if err := s.limiter.Wait(ctx); err != nil {
				return
			}

			// Send IP to worker pool (non-blocking on cancel)
			select {
			case <-ctx.Done():
				return
			case ipChan <- ip:
			}
		}
	}()

	// Wait for workers to finish
	wg.Wait()
	close(resultChan)

	// Wait for collector to finish
	collectorWg.Wait()

	if handlerErr != nil {
		return resultCount, handlerErr
	}
	return resultCount, ctx.Err()
}

// worker processes individual IPs
// Uses select to immediately stop on cancellation, discarding any buffered IPs
func (s *Scanner) worker(ctx context.Context, ipChan <-chan net.IP, resultChan chan<- *ScanResult) {
	for {
		select {
		case <-ctx.Done():
			// Immediately exit on cancellation, don't process buffered IPs
			return
		case ip, ok := <-ipChan:
			if !ok {
				// Channel closed, no more work
				return
			}

			// Create timeout context for this IP
			ipCtx, cancel := context.WithTimeout(ctx, time.Duration(s.config.Timeout)*time.Second)
			result := s.scanIP(ipCtx, ip.String())
			cancel()

			// Try to send result with cancellation check
			select {
			case <-ctx.Done():
				return
			case resultChan <- result:
			}
		}
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
		if err != nil {
			slog.Debug("DNS test error", "ip", ip, "error", err)
			result.ScanErrors = append(result.ScanErrors, fmt.Sprintf("DNS: %v", err))
		}
		result.DNSResult = dnsResult
	}

	// Tunnel Detection
	if len(s.tunnelDetectors) > 0 {
		tunnelResult, err := s.detectTunnel(ctx, ip)
		if err != nil {
			slog.Debug("tunnel detection error", "ip", ip, "error", err)
			result.ScanErrors = append(result.ScanErrors, fmt.Sprintf("Tunnel: %v", err))
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
	if concurrency <= 0 {
		concurrency = len(s.dnsScanners)
	}
	g.SetLimit(min(concurrency, len(s.dnsScanners)))

	// Channel for collecting results (buffered to prevent blocking)
	type scannerResult struct {
		name       string
		scanResult *dns.ScanResult
	}
	resultChan := make(chan scannerResult, len(s.dnsScanners))

	// Launch scanners with bounded concurrency
	for _, scanner := range s.dnsScanners {
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
			result.DoTResponseTimeMs = dns.Milliseconds(sr.scanResult.ResponseTime.Milliseconds())
			if sr.scanResult.Error != "" {
				result.DoTError = sr.scanResult.Error
			}
		case "doh":
			result.SupportsDoH = true
			result.DoHEndpoint = sr.scanResult.Endpoint
			result.DoHResponseTime = sr.scanResult.ResponseTime
			result.DoHResponseTimeMs = dns.Milliseconds(sr.scanResult.ResponseTime.Milliseconds())
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
	if concurrency <= 0 {
		concurrency = len(s.tunnelDetectors)
	}
	g.SetLimit(min(concurrency, len(s.tunnelDetectors)))

	// Channel for collecting results (buffered to prevent blocking)
	resultChan := make(chan *tunnel.DetectionResult, len(s.tunnelDetectors))

	// Launch detectors with bounded concurrency
	for _, detector := range s.tunnelDetectors {
		g.Go(func() error {
			detectionResult, err := detector.Detect(ctx, ip, domain)
			if err != nil {
				slog.Debug("detector error",
					"ip", ip,
					"detector", detector.Name(),
					"error", err)
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

// logProgress logs scan progress with structured logging
func (s *Scanner) logProgress(result *ScanResult) {
	if result.DNSResult != nil && result.DNSResult.RespondsToQueries {
		attrs := []slog.Attr{
			slog.String("ip", result.IP),
			slog.String("dns_type", result.DNSResult.DNSServerType),
			slog.Bool("dot", result.DNSResult.SupportsDoT),
		}

		if result.DNSResult.SupportsDoH {
			attrs = append(attrs, slog.String("doh_endpoint", result.DNSResult.DoHEndpoint))
		}

		if result.TunnelResult != nil && result.TunnelResult.IsTunnel {
			attrs = append(attrs,
				slog.String("tunnel_type", result.TunnelResult.TunnelType),
				slog.String("tunnel_confidence", result.TunnelResult.Confidence),
			)
		}

		slog.LogAttrs(context.Background(), slog.LevelInfo, "scan result", attrs...)
	}
}
