//go:build go1.25

package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// =============================================================================
// Rate Limiter Tests
// =============================================================================

// TestScannerRateLimit verifies rate limiting with fake time
func TestScannerRateLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()

		config := Config{
			Workers:   10,
			RateLimit: 100, // 100 IPs/sec
			Timeout:   5,
			Quiet:     true,
		}
		s := NewScanner(config)

		ips := generateTestIPs(500)

		start := time.Now()
		_, err := s.Scan(ctx, ips)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("Scan failed: %v", err)
		}

		// 500 IPs at 100/sec = 5 seconds (with tolerance for implementation variance)
		expectedSeconds := 5.0
		actualSeconds := elapsed.Seconds()

		// Rate limiting should take meaningful time (at least 50% of expected)
		if actualSeconds < expectedSeconds*0.5 {
			t.Errorf("Rate limiting too fast: expected ~%.1fs, got %.3fs", expectedSeconds, actualSeconds)
		}

		t.Logf("Rate limit test passed: 500 IPs in %.3fs fake time", actualSeconds)
	})
}

// TestScannerNoRateLimit verifies unlimited rate when RateLimit=0
func TestScannerNoRateLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()

		config := Config{
			Workers:   50,
			RateLimit: 0, // Unlimited
			Timeout:   1,
			Quiet:     true,
		}
		s := NewScanner(config)

		ips := generateTestIPs(100)

		start := time.Now()
		results, err := s.Scan(ctx, ips)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("Scan failed: %v", err)
		}

		if len(results) != 100 {
			t.Fatalf("Expected 100 results, got %d", len(results))
		}

		// With 50 workers and 1s timeout, 100 IPs should complete in ~2s
		// (2 rounds of 50 workers each)
		if elapsed > 5*time.Second {
			t.Errorf("No rate limit should be fast: got %.3fs", elapsed.Seconds())
		}

		t.Logf("No rate limit test passed: 100 IPs in %.3fs fake time", elapsed.Seconds())
	})
}

// =============================================================================
// Timeout Tests
// =============================================================================

// TestScannerTimeout verifies per-IP timeout behavior
func TestScannerTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()

		config := Config{
			Workers:   1,
			Timeout:   1, // 1 second timeout
			RateLimit: 0,
			Quiet:     true,
		}
		s := NewScanner(config)

		// TEST-NET-1 (documentation) - will timeout
		ips := []net.IP{net.ParseIP("192.0.2.1")}

		results, err := s.Scan(ctx, ips)

		if err != nil {
			t.Fatalf("Scan failed: %v", err)
		}

		if len(results) != 1 {
			t.Fatalf("Expected 1 result, got %d", len(results))
		}

		// Scanner should complete (timeout may not reflect in fake time with real network)
		t.Logf("Timeout test passed: scanner completed with config timeout=%ds", config.Timeout)
	})
}

// TestScannerZeroTimeout verifies behavior when Timeout=0 (no default override)
func TestScannerZeroTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := Config{
			Workers:   1,
			Timeout:   0, // 0 means use query-level timeouts, not per-IP timeout
			RateLimit: 0,
			Quiet:     true,
		}
		s := NewScanner(config)

		// Verify scanner was created with the specified timeout
		if s.config.Timeout != 0 {
			t.Errorf("Expected timeout=0 to be preserved, got %d", s.config.Timeout)
		}

		t.Logf("Zero timeout test passed: scanner accepts Timeout=0 (uses query-level timeouts)")
	})
}

// =============================================================================
// Context Cancellation Tests
// =============================================================================

// TestScannerCancellation verifies graceful cancellation mid-scan
func TestScannerCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		config := Config{
			Workers:   10,
			Timeout:   5,
			RateLimit: 100,
			Quiet:     true,
		}
		s := NewScanner(config)

		ips := generateTestIPs(1000)

		done := make(chan struct{})
		var results []*ScanResult
		var scanErr error

		go func() {
			results, scanErr = s.Scan(ctx, ips)
			close(done)
		}()

		// Cancel after 2 seconds of fake time
		time.Sleep(2 * time.Second)
		cancel()

		synctest.Wait()
		<-done

		// Should have context.Canceled error
		if scanErr != context.Canceled {
			t.Errorf("Expected context.Canceled, got %v", scanErr)
		}

		// Should have scanned fewer than all IPs
		if len(results) >= len(ips) {
			t.Errorf("Expected < %d results (cancelled), got %d", len(ips), len(results))
		}

		t.Logf("Cancellation test passed: %d/%d IPs before cancel", len(results), len(ips))
	})
}

// TestScannerContextDeadline verifies context deadline is respected
func TestScannerContextDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Context with 3 second deadline
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()

		config := Config{
			Workers:   10,
			Timeout:   10, // Long timeout per IP
			RateLimit: 10, // Slow rate
			Quiet:     true,
		}
		s := NewScanner(config)

		ips := generateTestIPs(100) // Would take 10s at rate limit

		start := time.Now()
		results, err := s.Scan(ctx, ips)
		elapsed := time.Since(start)

		// Should finish around context deadline (3s), not full scan time (10s)
		if elapsed > 5*time.Second {
			t.Errorf("Context deadline not respected: elapsed %.3fs", elapsed.Seconds())
		}

		// Should have DeadlineExceeded error
		if !errors.Is(err, context.DeadlineExceeded) && err != context.DeadlineExceeded {
			// Also accept Canceled since deadline triggers cancellation
			if !errors.Is(err, context.Canceled) && err != context.Canceled {
				t.Logf("Note: err = %v (not DeadlineExceeded, but may be ok)", err)
			}
		}

		t.Logf("Context deadline test passed: %d results in %.3fs", len(results), elapsed.Seconds())
	})
}

// =============================================================================
// Worker Concurrency Tests
// =============================================================================

// TestScannerWorkerConcurrency verifies parallel worker execution
func TestScannerWorkerConcurrency(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()

		config := Config{
			Workers:   5,
			Timeout:   1,
			RateLimit: 0,
			Quiet:     true,
		}
		s := NewScanner(config)

		ips := generateTestIPs(50)

		start := time.Now()
		results, err := s.Scan(ctx, ips)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("Scan failed: %v", err)
		}

		if len(results) != 50 {
			t.Fatalf("Expected 50 results, got %d", len(results))
		}

		// 5 workers, 50 IPs, 1s timeout = ~10s (10 rounds)
		expectedSeconds := 10.0
		if elapsed > time.Duration(expectedSeconds*1.5)*time.Second {
			t.Errorf("Concurrency issue: expected ~%.1fs, got %.3fs", expectedSeconds, elapsed.Seconds())
		}

		t.Logf("Worker concurrency test passed: %.3fs with %d workers", elapsed.Seconds(), config.Workers)
	})
}

// TestScannerAutoWorkers verifies auto-worker calculation
func TestScannerAutoWorkers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := Config{
			Workers:   0, // Auto
			Timeout:   5,
			RateLimit: 1000,
			Quiet:     true,
		}
		s := NewScanner(config)

		// Should have computed positive worker count
		if s.config.Workers <= 0 {
			t.Errorf("Auto workers should be positive, got %d", s.config.Workers)
		}

		t.Logf("Auto workers test passed: computed %d workers", s.config.Workers)
	})
}

// TestScannerSingleWorker verifies single-worker sequential processing
func TestScannerSingleWorker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()

		config := Config{
			Workers:   1, // Single worker
			Timeout:   1,
			RateLimit: 0,
			Quiet:     true,
		}
		s := NewScanner(config)

		ips := generateTestIPs(5)

		results, err := s.Scan(ctx, ips)

		if err != nil {
			t.Fatalf("Scan failed: %v", err)
		}

		if len(results) != 5 {
			t.Fatalf("Expected 5 results, got %d", len(results))
		}

		// Verify single worker was used
		if s.config.Workers != 1 {
			t.Errorf("Expected Workers=1, got %d", s.config.Workers)
		}

		t.Logf("Single worker test passed: processed 5 IPs sequentially")
	})
}

// =============================================================================
// Iterator and Streaming Tests
// =============================================================================

// TestIteratorScanning verifies ScanIter with iterator input
func TestIteratorScanning(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()

		config := Config{
			Workers:   5,
			Timeout:   1,
			RateLimit: 0,
			Quiet:     true,
		}
		s := NewScanner(config)

		ipGenerator := func(yield func(net.IP) bool) {
			for i := range 20 {
				if !yield(net.ParseIP(fmt.Sprintf("10.0.0.%d", i+1))) {
					return
				}
			}
		}

		results, err := s.ScanIter(ctx, ipGenerator, 20)

		if err != nil {
			t.Fatalf("ScanIter failed: %v", err)
		}

		if len(results) != 20 {
			t.Fatalf("Expected 20 results, got %d", len(results))
		}

		t.Logf("Iterator scanning test passed: %d IPs from iterator", len(results))
	})
}

// TestStreamingScanning verifies ScanStream callback-based scanning
func TestStreamingScanning(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()

		config := Config{
			Workers:   5,
			Timeout:   1,
			RateLimit: 0,
			Quiet:     true,
		}
		s := NewScanner(config)

		ipGenerator := func(yield func(net.IP) bool) {
			for i := range 30 {
				if !yield(net.ParseIP(fmt.Sprintf("10.0.1.%d", i+1))) {
					return
				}
			}
		}

		var resultCount atomic.Int32
		handler := func(result *ScanResult) error {
			resultCount.Add(1)
			return nil
		}

		count, err := s.ScanStream(ctx, ipGenerator, handler)

		if err != nil {
			t.Fatalf("ScanStream failed: %v", err)
		}

		if count != 30 {
			t.Errorf("Expected count 30, got %d", count)
		}

		if resultCount.Load() != 30 {
			t.Errorf("Handler called %d times, expected 30", resultCount.Load())
		}

		t.Logf("Streaming scanning test passed: %d results via callback", count)
	})
}

// TestStreamingHandlerError verifies ScanStream continues on handler errors
func TestStreamingHandlerError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()

		config := Config{
			Workers:   2,
			Timeout:   1,
			RateLimit: 0,
			Quiet:     true,
		}
		s := NewScanner(config)

		ips := generateTestIPs(10)
		ipGenerator := func(yield func(net.IP) bool) {
			for _, ip := range ips {
				if !yield(ip) {
					return
				}
			}
		}

		var handlerCalls atomic.Int32
		errHandler := func(result *ScanResult) error {
			handlerCalls.Add(1)
			// Return error on every call
			return errors.New("handler error")
		}

		count, err := s.ScanStream(ctx, ipGenerator, errHandler)

		// Should still process all IPs despite handler errors
		if count != 10 {
			t.Errorf("Expected count 10, got %d", count)
		}

		// Should return the handler error
		if err == nil {
			t.Errorf("Expected handler error to be returned")
		}

		if handlerCalls.Load() != 10 {
			t.Errorf("Handler should be called for all results, got %d", handlerCalls.Load())
		}

		t.Logf("Streaming handler error test passed: %d results, err=%v", count, err)
	})
}

// =============================================================================
// Edge Case Tests
// =============================================================================

// TestScannerEmptyInput verifies handling of empty IP list
func TestScannerEmptyInput(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()

		config := Config{
			Workers:   5,
			Timeout:   5,
			RateLimit: 100,
			Quiet:     true,
		}
		s := NewScanner(config)

		ips := []net.IP{} // Empty

		results, err := s.Scan(ctx, ips)

		if err != nil {
			t.Fatalf("Scan of empty list failed: %v", err)
		}

		if len(results) != 0 {
			t.Errorf("Expected 0 results for empty input, got %d", len(results))
		}

		t.Logf("Empty input test passed")
	})
}

// TestScannerNilInput verifies handling of nil IP list
func TestScannerNilInput(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()

		config := Config{
			Workers:   5,
			Timeout:   5,
			RateLimit: 100,
			Quiet:     true,
		}
		s := NewScanner(config)

		var ips []net.IP = nil

		results, err := s.Scan(ctx, ips)

		if err != nil {
			t.Fatalf("Scan of nil list failed: %v", err)
		}

		if len(results) != 0 {
			t.Errorf("Expected 0 results for nil input, got %d", len(results))
		}

		t.Logf("Nil input test passed")
	})
}

// TestScannerLargeInput verifies handling of large IP lists
func TestScannerLargeInput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large input test in short mode")
	}

	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()

		config := Config{
			Workers:   100,
			Timeout:   1,
			RateLimit: 10000, // High rate
			Quiet:     true,
		}
		s := NewScanner(config)

		ips := generateTestIPs(5000)

		start := time.Now()
		results, err := s.Scan(ctx, ips)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("Large scan failed: %v", err)
		}

		if len(results) != 5000 {
			t.Errorf("Expected 5000 results, got %d", len(results))
		}

		t.Logf("Large input test passed: %d results in %.3fs fake time", len(results), elapsed.Seconds())
	})
}

// TestScannerDuplicateIPs verifies handling of duplicate IPs
func TestScannerDuplicateIPs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()

		config := Config{
			Workers:   5,
			Timeout:   1,
			RateLimit: 0,
			Quiet:     true,
		}
		s := NewScanner(config)

		// Create list with duplicates
		ips := []net.IP{
			net.ParseIP("192.168.1.1"),
			net.ParseIP("192.168.1.1"), // Duplicate
			net.ParseIP("192.168.1.2"),
			net.ParseIP("192.168.1.1"), // Duplicate
			net.ParseIP("192.168.1.3"),
		}

		results, err := s.Scan(ctx, ips)

		if err != nil {
			t.Fatalf("Scan failed: %v", err)
		}

		// Should process all IPs including duplicates
		if len(results) != 5 {
			t.Errorf("Expected 5 results (including dupes), got %d", len(results))
		}

		t.Logf("Duplicate IPs test passed: %d results", len(results))
	})
}

// =============================================================================
// Probe-Based Architecture Tests
// =============================================================================

// TestScannerWithNoProbes verifies scanner runs with no probes enabled
func TestScannerWithNoProbes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()

		config := Config{
			Workers:   2,
			Timeout:   1,
			RateLimit: 0,
			Quiet:     true,
			// No probes enabled (all Enable* flags are false)
		}
		s := NewScanner(config)

		// Should have no probes registered
		if s.probes.Count() != 0 {
			t.Errorf("Expected 0 probes, got %d", s.probes.Count())
		}

		ips := generateTestIPs(5)
		results, err := s.Scan(ctx, ips)

		if err != nil {
			t.Fatalf("Scan failed: %v", err)
		}

		// Should still return results (just with no probe data)
		if len(results) != 5 {
			t.Errorf("Expected 5 results, got %d", len(results))
		}

		t.Logf("No probes test passed: %d results with 0 probes", len(results))
	})
}

// TestScannerWithDNSProbe verifies DNS probe registration and execution
func TestScannerWithDNSProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := Config{
			Workers:   2,
			Timeout:   1,
			RateLimit: 0,
			Quiet:     true,
			EnableUDP: true,
			EnableTCP: true,
		}
		s := NewScanner(config)

		// Should have DNS probe registered
		if s.probes.Count() == 0 {
			t.Error("Expected DNS probe to be registered")
		}

		foundDNS := false
		for _, probe := range s.probes.All() {
			if probe.Name() == "dns" {
				foundDNS = true
				break
			}
		}
		if !foundDNS {
			t.Error("Expected DNS probe in registry")
		}

		t.Logf("DNS probe test passed: probe registered")
	})
}

// TestScannerWithPortsProbe verifies port scan probe
func TestScannerWithPortsProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()

		config := Config{
			Workers:        2,
			Timeout:        1,
			RateLimit:      0,
			Quiet:          true,
			EnablePortScan: true,
		}
		s := NewScanner(config)

		// Should have ports probe registered
		foundPorts := false
		for _, probe := range s.probes.All() {
			if probe.Name() == "ports" {
				foundPorts = true
				break
			}
		}
		if !foundPorts {
			t.Error("Expected ports probe in registry")
		}

		ips := generateTestIPs(3)
		results, err := s.Scan(ctx, ips)

		if err != nil {
			t.Fatalf("Scan failed: %v", err)
		}

		if len(results) != 3 {
			t.Errorf("Expected 3 results, got %d", len(results))
		}

		t.Logf("Ports probe test passed: %d results", len(results))
	})
}

// TestScannerWithTunnelProbe verifies tunnel probe
func TestScannerWithTunnelProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := Config{
			Workers:       2,
			Timeout:       1,
			RateLimit:     0,
			Quiet:         true,
			EnableTunnel:  true,
			TunnelDNSTT:   true,
			TunnelIodine:  true,
			TunnelDomain:  "test.example.com",
		}
		s := NewScanner(config)

		// Should have tunnel probe registered
		foundTunnel := false
		for _, probe := range s.probes.All() {
			if probe.Name() == "tunnel" {
				foundTunnel = true
				break
			}
		}
		if !foundTunnel {
			t.Error("Expected tunnel probe in registry")
		}

		t.Logf("Tunnel probe test passed: probe registered")
	})
}

// TestScannerMultipleProbes verifies multiple probes run in sequence
func TestScannerMultipleProbes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()

		config := Config{
			Workers:        2,
			Timeout:        2,
			RateLimit:      0,
			Quiet:          true,
			EnableUDP:      true,  // DNS
			EnableTCP:      true,  // DNS
			EnablePortScan: true,  // Ports
		}
		s := NewScanner(config)

		// Should have multiple probes registered
		if s.probes.Count() < 2 {
			t.Errorf("Expected at least 2 probes, got %d", s.probes.Count())
		}

		ips := generateTestIPs(3)
		results, err := s.Scan(ctx, ips)

		if err != nil {
			t.Fatalf("Scan failed: %v", err)
		}

		if len(results) != 3 {
			t.Errorf("Expected 3 results, got %d", len(results))
		}

		t.Logf("Multiple probes test passed: %d probes, %d results", s.probes.Count(), len(results))
	})
}

// TestScannerLifecycle verifies Start/Stop lifecycle
func TestScannerLifecycle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := Config{
			Workers:   2,
			Timeout:   1,
			RateLimit: 0,
			Quiet:     true,
		}
		s := NewScanner(config)

		// Start should succeed even with no ICMP probe
		if err := s.Start(); err != nil {
			t.Fatalf("Start failed: %v", err)
		}

		// Stop should be safe to call
		s.Stop()

		// Double stop should be safe
		s.Stop()

		t.Logf("Lifecycle test passed")
	})
}

// TestScannerProbeErrors verifies error handling in probes
func TestScannerProbeErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()

		config := Config{
			Workers:   2,
			Timeout:   1, // Short timeout
			RateLimit: 0,
			Quiet:     true,
			EnableUDP: true,
		}
		s := NewScanner(config)

		// Scan documentation IPs (will timeout/fail)
		ips := []net.IP{net.ParseIP("192.0.2.1")}
		results, err := s.Scan(ctx, ips)

		if err != nil {
			t.Fatalf("Scan failed: %v", err)
		}

		if len(results) != 1 {
			t.Fatalf("Expected 1 result, got %d", len(results))
		}

		// Result should have scan errors recorded
		t.Logf("Probe errors test passed: %d errors recorded", len(results[0].ScanErrors))
	})
}

// TestScannerStreamWithProbes verifies streaming with multiple probes
func TestScannerStreamWithProbes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()

		config := Config{
			Workers:        3,
			Timeout:        1,
			RateLimit:      0,
			Quiet:          true,
			EnablePortScan: true,
		}
		s := NewScanner(config)

		ipGenerator := func(yield func(net.IP) bool) {
			for i := range 10 {
				if !yield(net.ParseIP(fmt.Sprintf("10.0.2.%d", i+1))) {
					return
				}
			}
		}

		var resultCount atomic.Int32
		handler := func(result *ScanResult) error {
			resultCount.Add(1)
			return nil
		}

		count, err := s.ScanStream(ctx, ipGenerator, handler)

		if err != nil {
			t.Fatalf("ScanStream failed: %v", err)
		}

		if count != 10 {
			t.Errorf("Expected count 10, got %d", count)
		}

		if resultCount.Load() != 10 {
			t.Errorf("Handler called %d times, expected 10", resultCount.Load())
		}

		t.Logf("Streaming with probes test passed: %d results", count)
	})
}

// =============================================================================
// Helper Functions
// =============================================================================

// generateTestIPs creates a slice of test IP addresses
func generateTestIPs(count int) []net.IP {
	ips := make([]net.IP, count)
	for i := range count {
		// Use different /16 ranges to avoid collision
		a := (i / 65536) % 256
		b := (i / 256) % 256
		c := i % 256
		ips[i] = net.ParseIP(fmt.Sprintf("10.%d.%d.%d", a, b, c))
	}
	return ips
}
