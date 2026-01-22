package integration

import (
	"context"
	"testing"
	"time"

	"github.com/velemoonkon/lightning/pkg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	scanner := dns.NewUDPScanner(opts)

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
	scanner := dns.NewTCPScanner(opts)

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
		scanner := dns.NewDoTScanner(opts)

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
		scanner := dns.NewDoTScanner(opts)

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
		scanner := dns.NewDoHScanner(opts)

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
		scanner := dns.NewDoHScanner(opts)

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
		registry := dns.NewDefaultRegistry()

		expectedScanners := []string{"udp", "tcp", "dot", "doh"}
		for _, name := range expectedScanners {
			scanner, ok := registry.Get(name)
			assert.True(t, ok, "Scanner %s should be registered", name)
			assert.NotNil(t, scanner)
			assert.Equal(t, name, scanner.Name())
		}
	})

	t.Run("GetByNames", func(t *testing.T) {
		registry := dns.NewDefaultRegistry()

		scanners := registry.GetByNames([]string{"udp", "tcp"})
		assert.Len(t, scanners, 2)
		assert.Equal(t, "udp", scanners[0].Name())
		assert.Equal(t, "tcp", scanners[1].Name())
	})

	t.Run("All Scanners", func(t *testing.T) {
		registry := dns.NewDefaultRegistry()

		allScanners := registry.All()
		assert.Len(t, allScanners, 4)
	})
}
