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
	"golang.org/x/time/rate"
)

// Scanner orchestrates concurrent IP scanning using pluggable probes
type Scanner struct {
	config    Config
	limiter   *rate.Limiter
	probes    *ProbeRegistry
	icmpProbe *ICMPProbe // Kept separately for lifecycle management
}

// NewScanner creates a new scanner with configuration
func NewScanner(cfg Config) *Scanner {
	// Validate and sanitize config
	// Workers=0 means "auto": use max(4, 4*GOMAXPROCS) for I/O-bound scanning
	if cfg.Workers <= 0 {
		cpus := runtime.GOMAXPROCS(0)
		cfg.Workers = max(4, cpus*4)
	}

	// Create rate limiter - treat RateLimit <= 0 as no limit
	var limiter *rate.Limiter
	if cfg.RateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(cfg.RateLimit), cfg.RateLimit)
	} else {
		limiter = rate.NewLimiter(rate.Inf, 0) // No rate limit
	}

	// Create probe registry and register enabled probes
	probes := NewProbeRegistry()
	var icmpProbe *ICMPProbe

	// Register ICMP probe if enabled
	if cfg.EnableICMP {
		probe, err := NewICMPProbe(cfg)
		if err != nil {
			slog.Warn("failed to create ICMP probe", "error", err)
		} else {
			icmpProbe = probe
			probes.Register(probe)
		}
	}

	// Register DNS probe if any DNS scanners are enabled
	if cfg.EnableUDP || cfg.EnableTCP || cfg.EnableDoT || cfg.EnableDoH {
		dnsProbe := NewDNSProbe(cfg)
		if dnsProbe.HasScanners() {
			probes.Register(dnsProbe)
		}
	}

	// Register tunnel probe if enabled
	if cfg.EnableTunnel {
		tunnelProbe := NewTunnelProbe(cfg)
		if tunnelProbe.HasDetectors() {
			probes.Register(tunnelProbe)
		}
	}

	// Register port scan probe if enabled
	if cfg.EnablePortScan {
		probes.Register(NewPortsProbe())
	}

	return &Scanner{
		config:    cfg,
		limiter:   limiter,
		probes:    probes,
		icmpProbe: icmpProbe,
	}
}

// Start initializes probes that require setup (e.g., ICMP sockets)
// Call this before scanning if ICMP is enabled
func (s *Scanner) Start() error {
	if s.icmpProbe != nil {
		if err := s.icmpProbe.Start(); err != nil {
			return fmt.Errorf("failed to start ICMP probe: %w", err)
		}
	}
	return nil
}

// Stop releases resources held by probes
func (s *Scanner) Stop() {
	if s.icmpProbe != nil {
		s.icmpProbe.Stop()
	}
}

// Scan scans a list of IPs and returns results
// For streaming large CIDR ranges, use ScanIter() with an iterator to avoid allocating the full IP list
// Goroutine fan-out is bounded:
// - Workers goroutines process IPs from ipChan
// - Per IP: probes run sequentially (ICMP, DNS, Tunnel, Ports)
// - DNS and Tunnel probes use errgroup.SetLimit internally for concurrent sub-operations
// - Total concurrent goroutines ≈ Workers + (Workers × probe concurrency)
func (s *Scanner) Scan(ctx context.Context, ips []net.IP) ([]*ScanResult, error) {
	// Convert slice to iterator and use ScanIter for actual scanning
	return s.ScanIter(ctx, slices.Values(ips), len(ips))
}

// ScanIter scans IPs from an iterator and returns results
// This enables streaming scanning of large CIDR ranges without allocating the full IP list
// Example: scanner.ScanIter(ctx, input.IPRange("10.0.0.0/8"), 16777216)
//
// The sizeHint parameter is used for preallocating the result slice. Use 0 if unknown.
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

// scanIP performs all enabled probes on a single IP
func (s *Scanner) scanIP(ctx context.Context, ip string) *ScanResult {
	start := time.Now()
	result := &ScanResult{
		IP: ip,
	}

	// Run all registered probes sequentially
	for _, probe := range s.probes.All() {
		if err := probe.Scan(ctx, ip, result); err != nil {
			slog.Debug("probe error", "ip", ip, "probe", probe.Name(), "error", err)
			result.ScanErrors = append(result.ScanErrors, fmt.Sprintf("%s: %v", probe.Name(), err))
		}
	}

	result.ScanTime = time.Since(start).Milliseconds()
	return result
}

// logProgress logs scan progress with structured logging using slog.Group for nested attributes
func (s *Scanner) logProgress(result *ScanResult) {
	attrs := []any{slog.String("ip", result.IP)}

	// Log ICMP results as a group
	if result.ICMPResult != nil {
		icmpAttrs := []any{slog.Bool("reachable", result.ICMPResult.Reachable)}
		if result.ICMPResult.Reachable {
			icmpAttrs = append(icmpAttrs, slog.Float64("rtt_ms", result.ICMPResult.RTTMs))
		}
		attrs = append(attrs, slog.Group("icmp", icmpAttrs...))
	}

	// Log DNS results as a group
	if result.DNSResult != nil && result.DNSResult.RespondsToQueries {
		dnsAttrs := []any{
			slog.String("type", result.DNSResult.DNSServerType),
			slog.Bool("dot", result.DNSResult.SupportsDoT),
		}
		if result.DNSResult.SupportsDoH {
			dnsAttrs = append(dnsAttrs, slog.String("doh_endpoint", result.DNSResult.DoHEndpoint))
		}
		attrs = append(attrs, slog.Group("dns", dnsAttrs...))
	}

	// Log tunnel results as a group
	if result.TunnelResult != nil && result.TunnelResult.IsTunnel {
		attrs = append(attrs, slog.Group("tunnel",
			slog.String("type", result.TunnelResult.TunnelType),
			slog.String("confidence", result.TunnelResult.Confidence),
		))
	}

	// Only log if there's something interesting to report
	if len(attrs) > 1 { // More than just IP
		slog.Info("scan result", attrs...)
	}
}
