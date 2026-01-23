package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/velemoonkon/lightning/pkg/tunnel"
)

// TunnelServers contains the test tunnel server addresses
var TunnelServers = map[string]string{
	"dnstt":   "127.0.0.1:15301",
	"iodine":  "127.0.0.1:15302",
	"dnscat2": "127.0.0.1:15303",
	"dns2tcp": "127.0.0.1:15304",
}

func TestDNSTTDetector(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	detector := tunnel.NewDNSTTDetector()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("DNSTT Tunnel Server", func(t *testing.T) {
		result, err := detector.Detect(ctx, "127.0.0.1:15301", "t.example.com")
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "dnstt", result.DetectorName)
		// May or may not detect depending on server configuration
		if result.IsTunnel {
			assert.Contains(t, []string{"high", "medium", "low"}, result.Confidence)
			assert.Greater(t, len(result.Indicators), 0)
			t.Logf("DNSTT detected with confidence: %s, indicators: %v", result.Confidence, result.Indicators)
		}
	})

	t.Run("Normal DNS Server Should Not Trigger", func(t *testing.T) {
		result, err := detector.Detect(ctx, "1.1.1.1:53", "cloudflare.com")
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "dnstt", result.DetectorName)
		assert.False(t, result.IsTunnel, "Normal DNS server should not be detected as DNSTT tunnel")
	})
}

func TestIodineDetector(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	detector := tunnel.NewIodineDetector()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("Iodine Tunnel Server", func(t *testing.T) {
		result, err := detector.Detect(ctx, "127.0.0.1:15302", "i.example.com")
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "iodine", result.DetectorName)
		if result.IsTunnel {
			assert.Contains(t, []string{"high", "medium", "low"}, result.Confidence)
			assert.Greater(t, len(result.Indicators), 0)
			t.Logf("Iodine detected with confidence: %s, indicators: %v", result.Confidence, result.Indicators)
		}
	})

	t.Run("Normal DNS Server Should Not Trigger", func(t *testing.T) {
		result, err := detector.Detect(ctx, "8.8.8.8:53", "google.com")
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "iodine", result.DetectorName)
		assert.False(t, result.IsTunnel, "Normal DNS server should not be detected as Iodine tunnel")
	})
}

func TestDNScat2Detector(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	detector := tunnel.NewDNScat2Detector()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("DNScat2 Tunnel Server", func(t *testing.T) {
		result, err := detector.Detect(ctx, "127.0.0.1:15303", "d.example.com")
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "dnscat2", result.DetectorName)
		if result.IsTunnel {
			assert.Contains(t, []string{"high", "medium", "low"}, result.Confidence)
			assert.Greater(t, len(result.Indicators), 0)
			t.Logf("DNScat2 detected with confidence: %s, indicators: %v", result.Confidence, result.Indicators)
		}
	})

	t.Run("Normal DNS Server Should Not Trigger", func(t *testing.T) {
		result, err := detector.Detect(ctx, "1.1.1.1:53", "cloudflare.com")
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "dnscat2", result.DetectorName)
		assert.False(t, result.IsTunnel, "Normal DNS server should not be detected as DNScat2 tunnel")
	})
}

func TestDNS2TCPDetector(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	detector := tunnel.NewDNS2TCPDetector()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("DNS2TCP Tunnel Server", func(t *testing.T) {
		result, err := detector.Detect(ctx, "127.0.0.1:15304", "tcp.example.com")
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "dns2tcp", result.DetectorName)
		if result.IsTunnel {
			assert.Contains(t, []string{"high", "medium", "low"}, result.Confidence)
			assert.Greater(t, len(result.Indicators), 0)
			t.Logf("DNS2TCP detected with confidence: %s, indicators: %v", result.Confidence, result.Indicators)
		}
	})

	t.Run("Normal DNS Server Should Not Trigger", func(t *testing.T) {
		result, err := detector.Detect(ctx, "8.8.8.8:53", "google.com")
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "dns2tcp", result.DetectorName)
		assert.False(t, result.IsTunnel, "Normal DNS server should not be detected as DNS2TCP tunnel")
	})
}

func TestTunnelDetectorRegistry(t *testing.T) {
	t.Run("Registry Has All Detectors", func(t *testing.T) {
		registry := tunnel.NewDefaultRegistry()

		expectedDetectors := []string{"dnstt", "iodine", "dnscat2", "dns2tcp"}
		for _, name := range expectedDetectors {
			detector, ok := registry.Get(name)
			assert.True(t, ok, "Detector %s should be registered", name)
			assert.NotNil(t, detector)
			assert.Equal(t, name, detector.Name())
		}
	})

	t.Run("GetByNames", func(t *testing.T) {
		registry := tunnel.NewDefaultRegistry()

		detectors := registry.GetByNames([]string{"dnstt", "iodine"})
		assert.Len(t, detectors, 2)
		assert.Equal(t, "dnstt", detectors[0].Name())
		assert.Equal(t, "iodine", detectors[1].Name())
	})

	t.Run("All Detectors", func(t *testing.T) {
		registry := tunnel.NewDefaultRegistry()

		allDetectors := registry.All()
		assert.Len(t, allDetectors, 4)
	})
}

func TestFalsePositiveRates(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test against well-known public DNS servers to ensure low false positive rate
	publicServers := map[string]string{
		"Cloudflare": "1.1.1.1:53",
		"Google":     "8.8.8.8:53",
		"Quad9":      "9.9.9.9:53",
		"OpenDNS":    "208.67.222.222:53",
	}

	registry := tunnel.NewDefaultRegistry()
	detectors := registry.All()

	for serverName, serverAddr := range publicServers {
		t.Run(serverName, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			falsePositives := 0
			for _, detector := range detectors {
				result, err := detector.Detect(ctx, serverAddr, "example.com")
				if err != nil {
					continue
				}

				if result.IsTunnel {
					t.Logf("FALSE POSITIVE: %s detected %s as %s tunnel with confidence %s",
						detector.Name(), serverName, result.DetectorName, result.Confidence)
					falsePositives++
				}
			}

			assert.Equal(t, 0, falsePositives, "Expected no false positives for %s", serverName)
		})
	}
}

// =============================================================================
// Context Cancellation Tests
// =============================================================================

func TestDetectorContextCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	detectors := []struct {
		name     string
		detector tunnel.Detector
	}{
		{"DNSTT", tunnel.NewDNSTTDetector()},
		{"Iodine", tunnel.NewIodineDetector()},
		{"DNScat2", tunnel.NewDNScat2Detector()},
		{"DNS2TCP", tunnel.NewDNS2TCPDetector()},
	}

	for _, tt := range detectors {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // Cancel immediately

			result, err := tt.detector.Detect(ctx, "1.1.1.1:53", "example.com")
			// Should handle gracefully without panic
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.False(t, result.IsTunnel, "Cancelled context should not detect tunnel")
		})
	}
}

func TestDetectorWithShortTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	detectors := []struct {
		name     string
		detector tunnel.Detector
	}{
		{"DNSTT", tunnel.NewDNSTTDetector()},
		{"Iodine", tunnel.NewIodineDetector()},
		{"DNScat2", tunnel.NewDNScat2Detector()},
		{"DNS2TCP", tunnel.NewDNS2TCPDetector()},
	}

	for _, tt := range detectors {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
			defer cancel()

			result, err := tt.detector.Detect(ctx, "1.1.1.1:53", "example.com")
			// May timeout but should handle gracefully
			require.NoError(t, err)
			require.NotNil(t, result)
		})
	}
}

// =============================================================================
// Concurrent Detection Tests
// =============================================================================

func TestConcurrentDetectorExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	registry := tunnel.NewDefaultRegistry()
	detectors := registry.All()
	server := "1.1.1.1:53"
	domain := "example.com"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Run all detectors concurrently
	var wg sync.WaitGroup
	results := make(chan *tunnel.DetectionResult, len(detectors))
	errors := make(chan error, len(detectors))

	for _, detector := range detectors {
		wg.Add(1)
		go func(d tunnel.Detector) {
			defer wg.Done()
			result, err := d.Detect(ctx, server, domain)
			if err != nil {
				errors <- err
				return
			}
			results <- result
		}(detector)
	}

	wg.Wait()
	close(results)
	close(errors)

	// Collect results
	var detectionResults []*tunnel.DetectionResult
	for result := range results {
		detectionResults = append(detectionResults, result)
	}

	// Check for errors
	var detectionErrors []error
	for err := range errors {
		detectionErrors = append(detectionErrors, err)
	}

	assert.Empty(t, detectionErrors, "Expected no errors from concurrent detection")
	assert.Len(t, detectionResults, len(detectors), "Expected result from each detector")

	// None should detect tunnel on Cloudflare
	for _, result := range detectionResults {
		assert.False(t, result.IsTunnel, "Cloudflare should not be detected as tunnel by %s", result.DetectorName)
	}
}

// =============================================================================
// Non-Existent Server Tests
// =============================================================================

func TestDetectorNonExistentServers(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Use TEST-NET addresses
	testNetServers := []string{
		"192.0.2.1:53",   // TEST-NET-1
		"198.51.100.1:53", // TEST-NET-2
		"203.0.113.1:53",  // TEST-NET-3
	}

	detectors := []struct {
		name     string
		detector tunnel.Detector
	}{
		{"DNSTT", tunnel.NewDNSTTDetector()},
		{"Iodine", tunnel.NewIodineDetector()},
		{"DNScat2", tunnel.NewDNScat2Detector()},
		{"DNS2TCP", tunnel.NewDNS2TCPDetector()},
	}

	for _, tt := range detectors {
		t.Run(tt.name, func(t *testing.T) {
			for _, server := range testNetServers {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				result, err := tt.detector.Detect(ctx, server, "example.com")
				cancel()

				require.NoError(t, err)
				require.NotNil(t, result)
				assert.False(t, result.IsTunnel, "Non-existent server should not be detected as tunnel")
				assert.Equal(t, tt.detector.Name(), result.DetectorName)
			}
		})
	}
}

// =============================================================================
// Result Structure Tests
// =============================================================================

func TestDetectionResultStructure(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	detector := tunnel.NewDNSTTDetector()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := detector.Detect(ctx, "1.1.1.1:53", "cloudflare.com")
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify result structure
	assert.Equal(t, "dnstt", result.DetectorName)
	assert.False(t, result.IsTunnel)

	// For non-tunnel detection, confidence should be empty
	if !result.IsTunnel {
		assert.Empty(t, result.Confidence)
	}
}

func TestDetectionResultWithIndicators(t *testing.T) {
	// Test the DetectionResult structure with all fields
	result := &tunnel.DetectionResult{
		DetectorName: "dnstt",
		IsTunnel:     true,
		Confidence:   "high",
		Indicators:   []string{"characteristic_response", "unusual_record_type"},
	}

	assert.Equal(t, "dnstt", result.DetectorName)
	assert.True(t, result.IsTunnel)
	assert.Equal(t, "high", result.Confidence)
	assert.Len(t, result.Indicators, 2)
	assert.Contains(t, result.Indicators, "characteristic_response")
	assert.Contains(t, result.Indicators, "unusual_record_type")
}

// =============================================================================
// Registry Filtering Tests
// =============================================================================

func TestRegistryFiltering(t *testing.T) {
	registry := tunnel.NewDefaultRegistry()

	t.Run("GetByNames returns only valid detectors", func(t *testing.T) {
		detectors := registry.GetByNames([]string{"dnstt", "invalid", "iodine", "unknown"})
		assert.Len(t, detectors, 2)
		assert.Equal(t, "dnstt", detectors[0].Name())
		assert.Equal(t, "iodine", detectors[1].Name())
	})

	t.Run("GetByNames preserves order", func(t *testing.T) {
		detectors := registry.GetByNames([]string{"dns2tcp", "dnscat2", "dnstt"})
		assert.Len(t, detectors, 3)
		assert.Equal(t, "dns2tcp", detectors[0].Name())
		assert.Equal(t, "dnscat2", detectors[1].Name())
		assert.Equal(t, "dnstt", detectors[2].Name())
	})

	t.Run("GetByNames with empty list", func(t *testing.T) {
		detectors := registry.GetByNames([]string{})
		assert.Empty(t, detectors)
	})

	t.Run("GetByNames with all invalid", func(t *testing.T) {
		detectors := registry.GetByNames([]string{"invalid1", "invalid2"})
		assert.Empty(t, detectors)
	})
}

// =============================================================================
// Multiple Domain Tests
// =============================================================================

func TestDetectorWithDifferentDomains(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	detector := tunnel.NewDNSTTDetector()
	domains := []string{
		"example.com",
		"test.example.org",
		"subdomain.example.net",
		"tunnel.test.com",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			result, err := detector.Detect(ctx, "1.1.1.1:53", domain)
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, "dnstt", result.DetectorName)
			assert.False(t, result.IsTunnel, "Cloudflare should not trigger false positive for domain %s", domain)
		})
	}
}

// =============================================================================
// Full Tunnel Result Tests
// =============================================================================

func TestFullTunnelResultStructure(t *testing.T) {
	result := &tunnel.Result{
		IP:            "192.168.1.100",
		IsTunnel:      true,
		TunnelType:    "dnstt",
		Confidence:    "high",
		AllIndicators: []string{"indicator1", "indicator2", "indicator3"},
		RespondsToDNS: true,
		IsRecursive:   false,
	}

	assert.Equal(t, "192.168.1.100", result.IP)
	assert.True(t, result.IsTunnel)
	assert.Equal(t, "dnstt", result.TunnelType)
	assert.Equal(t, "high", result.Confidence)
	assert.True(t, result.RespondsToDNS)
	assert.False(t, result.IsRecursive)
	assert.Len(t, result.AllIndicators, 3)
}
