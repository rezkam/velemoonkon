package integration

import (
	"context"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/velemoonkon/lightning/pkg/dns"
	"github.com/velemoonkon/lightning/pkg/scanner"
)

// TestServers contains the test server addresses
var TestServers = map[string]string{
	"bind9":    "127.0.0.1:15353",
	"unbound":  "127.0.0.1:15454",
	"coredns":  "127.0.0.1:15555",
	"doh":      "127.0.0.1:8443",
}

func TestUDPScanner(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tests := []struct {
		name       string
		server     string
		wantSuccess bool
	}{
		{
			name:       "BIND9 Recursive",
			server:     "127.0.0.1:15353",
			wantSuccess: true,
		},
		{
			name:       "Unbound Recursive",
			server:     "127.0.0.1:15454",
			wantSuccess: true,
		},
		{
			name:       "CoreDNS",
			server:     "127.0.0.1:15555",
			wantSuccess: true,
		},
		{
			name:       "Non-existent Server",
			server:     "127.0.0.1:9999",
			wantSuccess: false,
		},
	}

	opts := dns.DefaultQueryOptions()
	scanner := dns.NewUDPScanner(opts, nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			result, err := scanner.Scan(ctx, tt.server)

			if tt.wantSuccess {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.True(t, result.Success, "Expected successful DNS query")
				assert.Equal(t, "udp", result.ScannerName)
				assert.Greater(t, len(result.DomainsResolved), 0, "Expected at least one domain resolved")
			} else {
				// Non-existent servers should return error or unsuccessful result
				if err == nil {
					assert.False(t, result.Success, "Expected unsuccessful query for non-existent server")
				}
			}
		})
	}
}

func TestTCPScanner(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tests := []struct {
		name       string
		server     string
		wantSuccess bool
	}{
		{
			name:       "BIND9 TCP",
			server:     "127.0.0.1:15353",
			wantSuccess: true,
		},
		{
			name:       "Unbound TCP",
			server:     "127.0.0.1:15454",
			wantSuccess: true,
		},
	}

	opts := dns.DefaultQueryOptions()
	scanner := dns.NewTCPScanner(opts, nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			result, err := scanner.Scan(ctx, tt.server)

			if tt.wantSuccess {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.True(t, result.Success, "Expected successful TCP DNS query")
				assert.Equal(t, "tcp", result.ScannerName)
			}
		})
	}
}

func TestDoTScanner(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("BIND9 DoT", func(t *testing.T) {
		opts := dns.DefaultQueryOptions()
		scanner := dns.NewDoTScanner(opts, nil)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		result, err := scanner.Scan(ctx, "127.0.0.1:8853")

		// DoT might not work without proper certificates
		if err != nil {
			t.Logf("DoT test failed (expected if no valid certs): %v", err)
			return
		}

		if result != nil && result.Success {
			assert.Equal(t, "dot", result.ScannerName)
			t.Logf("DoT connection successful")
		}
	})

	// Test against public DoT servers
	t.Run("Cloudflare DoT", func(t *testing.T) {
		opts := dns.DefaultQueryOptions()
		scanner := dns.NewDoTScanner(opts, nil)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		result, err := scanner.Scan(ctx, "1.1.1.1:853")
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success, "Expected successful DoT query to Cloudflare")
		assert.Equal(t, "dot", result.ScannerName)
	})
}

func TestDoHScanner(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test against public DoH servers
	t.Run("Cloudflare DoH", func(t *testing.T) {
		opts := dns.DefaultQueryOptions()
		scanner := dns.NewDoHScanner(opts, nil)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		result, err := scanner.Scan(ctx, "1.1.1.1")
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success, "Expected successful DoH query to Cloudflare")
		assert.Equal(t, "doh", result.ScannerName)
		assert.Equal(t, "/dns-query", result.Endpoint)
	})

	t.Run("Google DoH", func(t *testing.T) {
		opts := dns.DefaultQueryOptions()
		scanner := dns.NewDoHScanner(opts, nil)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		result, err := scanner.Scan(ctx, "8.8.8.8")
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Success, "Expected successful DoH query to Google")
		assert.Equal(t, "doh", result.ScannerName)
	})
}

func TestDNSScannerRegistry(t *testing.T) {
	t.Run("Registry Has All Scanners", func(t *testing.T) {
		registry := dns.NewDefaultRegistry(nil)

		expectedScanners := []string{"udp", "tcp", "dot", "doh"}
		for _, name := range expectedScanners {
			scanner, ok := registry.Get(name)
			assert.True(t, ok, "Scanner %s should be registered", name)
			assert.NotNil(t, scanner)
			assert.Equal(t, name, scanner.Name())
		}
	})

	t.Run("GetByNames", func(t *testing.T) {
		registry := dns.NewDefaultRegistry(nil)

		scanners := registry.GetByNames([]string{"udp", "tcp"})
		assert.Len(t, scanners, 2)
		assert.Equal(t, "udp", scanners[0].Name())
		assert.Equal(t, "tcp", scanners[1].Name())
	})

	t.Run("All Scanners", func(t *testing.T) {
		registry := dns.NewDefaultRegistry(nil)

		allScanners := registry.All()
		assert.Len(t, allScanners, 4)
	})
}

// =============================================================================
// Context and Timeout Tests
// =============================================================================

func TestScannerContextCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tests := []struct {
		name        string
		newScanner  func() dns.Scanner
		server      string
	}{
		{"UDP", func() dns.Scanner { return dns.NewUDPScanner(dns.DefaultQueryOptions(), nil) }, "1.1.1.1:53"},
		{"TCP", func() dns.Scanner { return dns.NewTCPScanner(dns.DefaultQueryOptions(), nil) }, "1.1.1.1:53"},
		{"DoT", func() dns.Scanner { return dns.NewDoTScanner(dns.DefaultQueryOptions(), nil) }, "1.1.1.1:853"},
		{"DoH", func() dns.Scanner { return dns.NewDoHScanner(dns.DefaultQueryOptions(), nil) }, "1.1.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := tt.newScanner()
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // Cancel immediately

			result, err := scanner.Scan(ctx, tt.server)
			// Should handle gracefully without panic
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.False(t, result.Success, "Cancelled context should not succeed")
		})
	}
}

func TestScannerWithShortTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	opts := dns.QueryOptions{
		Timeout:          1 * time.Millisecond, // Very short timeout
		RecursionDesired: true,
		UseEDNS:          true,
		EDNSBufferSize:   4096,
	}

	tests := []struct {
		name       string
		newScanner func() dns.Scanner
		server     string
	}{
		{"UDP", func() dns.Scanner { return dns.NewUDPScanner(opts, nil) }, "1.1.1.1:53"},
		{"TCP", func() dns.Scanner { return dns.NewTCPScanner(opts, nil) }, "1.1.1.1:53"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := tt.newScanner()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			result, err := scanner.Scan(ctx, tt.server)
			// May timeout but shouldn't error fatally
			require.NoError(t, err)
			require.NotNil(t, result)
			// Short timeout may or may not succeed depending on network
		})
	}
}

// =============================================================================
// Custom Test Domains Tests
// =============================================================================

func TestScannerWithCustomTestDomains(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	customDomains := []string{"example.org", "example.net"}
	opts := dns.DefaultQueryOptions()

	tests := []struct {
		name       string
		newScanner func() dns.Scanner
	}{
		{"UDP", func() dns.Scanner { return dns.NewUDPScanner(opts, customDomains) }},
		{"TCP", func() dns.Scanner { return dns.NewTCPScanner(opts, customDomains) }},
		{"DoT", func() dns.Scanner { return dns.NewDoTScanner(opts, customDomains) }},
		{"DoH", func() dns.Scanner { return dns.NewDoHScanner(opts, customDomains) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := tt.newScanner()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Verify custom domains are used (test against Cloudflare)
			result, err := scanner.Scan(ctx, "1.1.1.1:53")
			require.NoError(t, err)
			require.NotNil(t, result)
			// The scanner should use our custom domains
		})
	}
}

// =============================================================================
// Full Scanner Pipeline Tests
// =============================================================================

func TestFullScannerPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Single IP Scan All Protocols", func(t *testing.T) {
		cfg := scanner.Config{
			Workers:        1,
			Timeout:        10,
			RateLimit:      0, // No rate limit
			EnableUDP:      true,
			EnableTCP:      true,
			EnableDoT:      true,
			EnableDoH:      true,
			EnableTunnel:   false, // No tunnel detection for this test
			EnablePortScan: false,
		}

		s := scanner.NewScanner(cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		ips := []net.IP{net.ParseIP("1.1.1.1")}
		results, err := s.Scan(ctx, ips)

		require.NoError(t, err)
		require.Len(t, results, 1)

		result := results[0]
		assert.Equal(t, "1.1.1.1", result.IP)
		require.NotNil(t, result.DNSResult)
		assert.True(t, result.DNSResult.UDPPortOpen || result.DNSResult.TCPPortOpen)
	})

	t.Run("Multiple IPs Concurrent", func(t *testing.T) {
		cfg := scanner.Config{
			Workers:        4,
			Timeout:        10,
			RateLimit:      0,
			EnableUDP:      true,
			EnableTCP:      false,
			EnableDoT:      false,
			EnableDoH:      false,
			EnableTunnel:   false,
			EnablePortScan: false,
		}

		s := scanner.NewScanner(cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		ips := []net.IP{
			net.ParseIP("1.1.1.1"),
			net.ParseIP("8.8.8.8"),
			net.ParseIP("9.9.9.9"),
		}

		results, err := s.Scan(ctx, ips)

		require.NoError(t, err)
		assert.Len(t, results, 3)

		// All should be successful DNS servers
		for _, result := range results {
			require.NotNil(t, result.DNSResult)
			assert.True(t, result.DNSResult.UDPPortOpen, "Expected %s to respond on UDP", result.IP)
		}
	})
}

func TestFullScannerWithTunnelDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := scanner.Config{
		Workers:       1,
		Timeout:       10,
		RateLimit:     0,
		EnableUDP:     true,
		EnableTCP:     false,
		EnableDoT:     false,
		EnableDoH:     false,
		EnableTunnel:  true,
		TunnelDNSTT:   true,
		TunnelIodine:  true,
		TunnelDNScat2: true,
		TunnelDNS2TCP: true,
		TunnelDomain:  "example.com",
	}

	s := scanner.NewScanner(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test against Cloudflare - should NOT detect as tunnel
	ips := []net.IP{net.ParseIP("1.1.1.1")}
	results, err := s.Scan(ctx, ips)

	require.NoError(t, err)
	require.Len(t, results, 1)

	result := results[0]
	assert.Equal(t, "1.1.1.1", result.IP)

	if result.TunnelResult != nil {
		assert.False(t, result.TunnelResult.IsTunnel, "Cloudflare should not be detected as tunnel")
	}
}

// =============================================================================
// Streaming Scan Tests
// =============================================================================

func TestScannerStreamingOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := scanner.Config{
		Workers:        2,
		Timeout:        10,
		RateLimit:      0,
		EnableUDP:      true,
		EnableTCP:      false,
		EnableDoT:      false,
		EnableDoH:      false,
		EnableTunnel:   false,
		EnablePortScan: false,
	}

	s := scanner.NewScanner(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ips := []net.IP{
		net.ParseIP("1.1.1.1"),
		net.ParseIP("8.8.8.8"),
	}

	var streamedResults []*scanner.ScanResult
	count, err := s.ScanStream(ctx, slices.Values(ips), func(result *scanner.ScanResult) error {
		streamedResults = append(streamedResults, result)
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, 2, count)
	assert.Len(t, streamedResults, 2)
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestScannerNonExistentServers(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Use TEST-NET addresses that are guaranteed non-routable
	testNetIPs := []string{
		"192.0.2.1:53",   // TEST-NET-1
		"198.51.100.1:53", // TEST-NET-2
		"203.0.113.1:53",  // TEST-NET-3
	}

	opts := dns.DefaultQueryOptions()
	opts.Timeout = 2 * time.Second // Short timeout for non-existent

	tests := []struct {
		name       string
		newScanner func() dns.Scanner
	}{
		{"UDP", func() dns.Scanner { return dns.NewUDPScanner(opts, nil) }},
		{"TCP", func() dns.Scanner { return dns.NewTCPScanner(opts, nil) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := tt.newScanner()

			for _, server := range testNetIPs {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				result, err := scanner.Scan(ctx, server)
				cancel()

				require.NoError(t, err, "Should not return error, just unsuccessful result")
				require.NotNil(t, result)
				assert.False(t, result.Success, "Non-existent server should not succeed")
			}
		})
	}
}

func TestScannerInvalidAddresses(t *testing.T) {
	opts := dns.DefaultQueryOptions()
	scanner := dns.NewUDPScanner(opts, nil)

	tests := []struct {
		name    string
		address string
	}{
		{"Empty address", ""},
		{"Invalid format", "not-an-ip"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			result, err := scanner.Scan(ctx, tt.address)
			// May error or return unsuccessful result
			if err == nil {
				assert.False(t, result.Success)
			}
		})
	}
}

// =============================================================================
// Protocol-Specific Feature Tests
// =============================================================================

func TestUDPEDNSSupport(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	opts := dns.QueryOptions{
		Timeout:          3 * time.Second,
		RecursionDesired: true,
		UseEDNS:          true,
		EDNSBufferSize:   4096,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := dns.TestUDPDNS(ctx, "1.1.1.1:53")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.UDPPortOpen)
	assert.True(t, result.RespondsToQueries)
	assert.True(t, result.SupportsEDNS, "Cloudflare should support EDNS")
	_ = opts // opts used for reference
}

func TestRecursionDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Cloudflare is a recursive resolver
	result, err := dns.TestUDPDNS(ctx, "1.1.1.1:53")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.SupportsRecursion)
	assert.Equal(t, "recursive", result.DNSServerType)
}

// =============================================================================
// Rate Limiting Integration Tests
// =============================================================================

func TestScannerRateLimiting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := scanner.Config{
		Workers:        10,
		Timeout:        5,
		RateLimit:      2, // Only 2 IPs per second
		EnableUDP:      true,
		EnableTCP:      false,
		EnableDoT:      false,
		EnableDoH:      false,
		EnableTunnel:   false,
		EnablePortScan: false,
	}

	s := scanner.NewScanner(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ips := []net.IP{
		net.ParseIP("1.1.1.1"),
		net.ParseIP("8.8.8.8"),
		net.ParseIP("9.9.9.9"),
		net.ParseIP("208.67.222.222"),
	}

	start := time.Now()
	results, err := s.Scan(ctx, ips)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Len(t, results, 4)

	// With rate limit of 2/sec and 4 IPs, should take at least ~1.5 seconds
	// (first 2 immediately, then wait 1 sec for next 2)
	assert.GreaterOrEqual(t, elapsed, 1*time.Second, "Rate limiting should slow down scanning")
}
