package tunnel

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// DNSTT Detector Unit Tests
// =============================================================================

func TestDNSTTDetector_Name(t *testing.T) {
	detector := NewDNSTTDetector()
	assert.Equal(t, "dnstt", detector.Name())
}

func TestDNSTTDetector_DetectNonExistent(t *testing.T) {
	detector := NewDNSTTDetector()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Non-existent IP should return result with IsTunnel=false
	result, err := detector.Detect(ctx, "192.0.2.1:53", "tunnel.example.com")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "dnstt", result.DetectorName)
	assert.False(t, result.IsTunnel)
}

func TestDNSTTDetector_DetectCancelled(t *testing.T) {
	detector := NewDNSTTDetector()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := detector.Detect(ctx, "1.1.1.1:53", "tunnel.example.com")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsTunnel)
}

// =============================================================================
// Iodine Detector Unit Tests
// =============================================================================

func TestIodineDetector_Name(t *testing.T) {
	detector := NewIodineDetector()
	assert.Equal(t, "iodine", detector.Name())
}

func TestIodineDetector_DetectNonExistent(t *testing.T) {
	detector := NewIodineDetector()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := detector.Detect(ctx, "192.0.2.1:53", "tunnel.example.com")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "iodine", result.DetectorName)
	assert.False(t, result.IsTunnel)
}

// =============================================================================
// DNScat2 Detector Unit Tests
// =============================================================================

func TestDNScat2Detector_Name(t *testing.T) {
	detector := NewDNScat2Detector()
	assert.Equal(t, "dnscat2", detector.Name())
}

func TestDNScat2Detector_DetectNonExistent(t *testing.T) {
	detector := NewDNScat2Detector()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := detector.Detect(ctx, "192.0.2.1:53", "tunnel.example.com")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "dnscat2", result.DetectorName)
	assert.False(t, result.IsTunnel)
}

// =============================================================================
// DNS2TCP Detector Unit Tests
// =============================================================================

func TestDNS2TCPDetector_Name(t *testing.T) {
	detector := NewDNS2TCPDetector()
	assert.Equal(t, "dns2tcp", detector.Name())
}

func TestDNS2TCPDetector_DetectNonExistent(t *testing.T) {
	detector := NewDNS2TCPDetector()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := detector.Detect(ctx, "192.0.2.1:53", "tunnel.example.com")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "dns2tcp", result.DetectorName)
	assert.False(t, result.IsTunnel)
}

// =============================================================================
// Registry Unit Tests
// =============================================================================

func TestDefaultRegistry_AllDetectorsRegistered(t *testing.T) {
	registry := NewDefaultRegistry()

	detectors := []string{"dnstt", "iodine", "dnscat2", "dns2tcp"}
	for _, name := range detectors {
		detector, ok := registry.Get(name)
		assert.True(t, ok, "Detector %s should be registered", name)
		assert.NotNil(t, detector)
		assert.Equal(t, name, detector.Name())
	}
}

func TestDefaultRegistry_UnknownDetector(t *testing.T) {
	registry := NewDefaultRegistry()

	detector, ok := registry.Get("unknown")
	assert.False(t, ok)
	assert.Nil(t, detector)
}

func TestDefaultRegistry_GetByNames(t *testing.T) {
	registry := NewDefaultRegistry()

	detectors := registry.GetByNames([]string{"dnstt", "iodine"})
	assert.Len(t, detectors, 2)
	assert.Equal(t, "dnstt", detectors[0].Name())
	assert.Equal(t, "iodine", detectors[1].Name())
}

func TestDefaultRegistry_GetByNamesWithInvalid(t *testing.T) {
	registry := NewDefaultRegistry()

	detectors := registry.GetByNames([]string{"dnstt", "invalid", "iodine"})
	assert.Len(t, detectors, 2)
}

func TestDefaultRegistry_All(t *testing.T) {
	registry := NewDefaultRegistry()

	allDetectors := registry.All()
	assert.Len(t, allDetectors, 4)

	names := make(map[string]bool)
	for _, d := range allDetectors {
		names[d.Name()] = true
	}

	assert.True(t, names["dnstt"])
	assert.True(t, names["iodine"])
	assert.True(t, names["dnscat2"])
	assert.True(t, names["dns2tcp"])
}

// =============================================================================
// DetectionResult Unit Tests
// =============================================================================

func TestDetectionResult_DefaultValues(t *testing.T) {
	result := &DetectionResult{}

	assert.Empty(t, result.DetectorName)
	assert.False(t, result.IsTunnel)
	assert.Empty(t, result.Confidence)
	assert.Nil(t, result.Indicators)
}

func TestDetectionResult_TunnelDetected(t *testing.T) {
	result := &DetectionResult{
		DetectorName: "dnstt",
		IsTunnel:     true,
		Confidence:   "high",
		Indicators:   []string{"characteristic_response", "unusual_record_type"},
	}

	assert.Equal(t, "dnstt", result.DetectorName)
	assert.True(t, result.IsTunnel)
	assert.Equal(t, "high", result.Confidence)
	assert.Len(t, result.Indicators, 2)
}

func TestDetectionResult_NoTunnelDetected(t *testing.T) {
	result := &DetectionResult{
		DetectorName: "iodine",
		IsTunnel:     false,
		Confidence:   "",
		Indicators:   nil,
	}

	assert.Equal(t, "iodine", result.DetectorName)
	assert.False(t, result.IsTunnel)
	assert.Empty(t, result.Confidence)
	assert.Nil(t, result.Indicators)
}

// =============================================================================
// Result Unit Tests (Full Tunnel Result)
// =============================================================================

func TestResult_DefaultValues(t *testing.T) {
	result := &Result{}

	assert.Empty(t, result.IP)
	assert.False(t, result.IsTunnel)
	assert.Empty(t, result.TunnelType)
}

func TestResult_FullyPopulated(t *testing.T) {
	result := &Result{
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
	assert.Len(t, result.AllIndicators, 3)
	assert.True(t, result.RespondsToDNS)
	assert.False(t, result.IsRecursive)
}

// =============================================================================
// Confidence Level Tests
// =============================================================================

func TestConfidenceLevels(t *testing.T) {
	// Valid confidence levels
	validLevels := []string{"high", "medium", "low"}

	for _, level := range validLevels {
		result := &DetectionResult{
			IsTunnel:   true,
			Confidence: level,
		}
		assert.Contains(t, []string{"high", "medium", "low"}, result.Confidence)
	}
}

// =============================================================================
// Indicator Tests
// =============================================================================

func TestIndicators_Append(t *testing.T) {
	result := &DetectionResult{
		Indicators: []string{},
	}

	result.Indicators = append(result.Indicators, "indicator1")
	result.Indicators = append(result.Indicators, "indicator2")

	assert.Len(t, result.Indicators, 2)
	assert.Equal(t, "indicator1", result.Indicators[0])
	assert.Equal(t, "indicator2", result.Indicators[1])
}

func TestResult_AllIndicators(t *testing.T) {
	result := &Result{
		IP:            "192.168.1.100",
		IsTunnel:      true,
		AllIndicators: []string{"main_indicator", "secondary_indicator", "tertiary_indicator"},
	}

	assert.Len(t, result.AllIndicators, 3)
	assert.Contains(t, result.AllIndicators, "main_indicator")
	assert.Contains(t, result.AllIndicators, "secondary_indicator")
	assert.Contains(t, result.AllIndicators, "tertiary_indicator")
}
