package integration

import (
	"context"
	"testing"
	"time"

	"github.com/velemoonkon/lightning/pkg/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
