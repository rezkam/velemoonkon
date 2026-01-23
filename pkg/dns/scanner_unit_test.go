package dns

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// UDP Scanner Unit Tests
// =============================================================================

func TestUDPScanner_Name(t *testing.T) {
	scanner := NewUDPScanner(DefaultQueryOptions(), nil)
	assert.Equal(t, "udp", scanner.Name())
}

func TestUDPScanner_DefaultTestDomains(t *testing.T) {
	scanner := NewUDPScanner(DefaultQueryOptions(), nil)
	assert.Equal(t, []string{"chatgpt.com", "google.com", "microsoft.com"}, scanner.testDomains)
}

func TestUDPScanner_CustomTestDomains(t *testing.T) {
	customDomains := []string{"example.com", "test.org"}
	scanner := NewUDPScanner(DefaultQueryOptions(), customDomains)
	assert.Equal(t, customDomains, scanner.testDomains)
}

func TestUDPScanner_ScanNonExistent(t *testing.T) {
	scanner := NewUDPScanner(DefaultQueryOptions(), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Non-existent IP should return result with Success=false
	result, err := scanner.Scan(ctx, "192.0.2.1:53") // TEST-NET-1
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "udp", result.ScannerName)
	assert.False(t, result.Success)
}

func TestUDPScanner_ScanCancelled(t *testing.T) {
	scanner := NewUDPScanner(DefaultQueryOptions(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := scanner.Scan(ctx, "1.1.1.1:53")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Success)
}

// =============================================================================
// TCP Scanner Unit Tests
// =============================================================================

func TestTCPScanner_Name(t *testing.T) {
	scanner := NewTCPScanner(DefaultQueryOptions(), nil)
	assert.Equal(t, "tcp", scanner.Name())
}

func TestTCPScanner_DefaultTestDomains(t *testing.T) {
	scanner := NewTCPScanner(DefaultQueryOptions(), nil)
	assert.Equal(t, []string{"chatgpt.com", "google.com", "microsoft.com"}, scanner.testDomains)
}

func TestTCPScanner_ScanNonExistent(t *testing.T) {
	scanner := NewTCPScanner(DefaultQueryOptions(), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, "192.0.2.1:53")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "tcp", result.ScannerName)
	assert.False(t, result.Success)
}

// =============================================================================
// DoT Scanner Unit Tests
// =============================================================================

func TestDoTScanner_Name(t *testing.T) {
	scanner := NewDoTScanner(DefaultQueryOptions(), nil)
	assert.Equal(t, "dot", scanner.Name())
}

func TestDoTScanner_DefaultTestDomains(t *testing.T) {
	scanner := NewDoTScanner(DefaultQueryOptions(), nil)
	assert.Equal(t, []string{"chatgpt.com", "google.com", "microsoft.com"}, scanner.testDomains)
}

func TestDoTScanner_ScanNonExistent(t *testing.T) {
	scanner := NewDoTScanner(DefaultQueryOptions(), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, "192.0.2.1:853")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "dot", result.ScannerName)
	assert.False(t, result.Success)
}

// =============================================================================
// DoH Scanner Unit Tests
// =============================================================================

func TestDoHScanner_Name(t *testing.T) {
	scanner := NewDoHScanner(DefaultQueryOptions(), nil)
	assert.Equal(t, "doh", scanner.Name())
}

func TestDoHScanner_DefaultTestDomains(t *testing.T) {
	scanner := NewDoHScanner(DefaultQueryOptions(), nil)
	assert.Equal(t, []string{"chatgpt.com", "google.com", "microsoft.com"}, scanner.testDomains)
}

func TestDoHScanner_ScanNonExistent(t *testing.T) {
	scanner := NewDoHScanner(DefaultQueryOptions(), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, "192.0.2.1")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "doh", result.ScannerName)
	assert.False(t, result.Success)
}

// =============================================================================
// Query Options Unit Tests
// =============================================================================

func TestDefaultQueryOptions(t *testing.T) {
	opts := DefaultQueryOptions()

	assert.Equal(t, 3*time.Second, opts.Timeout)
	assert.True(t, opts.RecursionDesired)
	assert.True(t, opts.UseEDNS)
	assert.Equal(t, uint16(4096), opts.EDNSBufferSize)
}

func TestQueryOptions_CustomValues(t *testing.T) {
	opts := QueryOptions{
		Timeout:          5 * time.Second,
		RecursionDesired: false,
		UseEDNS:          false,
		EDNSBufferSize:   512,
	}

	assert.Equal(t, 5*time.Second, opts.Timeout)
	assert.False(t, opts.RecursionDesired)
	assert.False(t, opts.UseEDNS)
	assert.Equal(t, uint16(512), opts.EDNSBufferSize)
}

// =============================================================================
// Registry Unit Tests
// =============================================================================

func TestDefaultRegistry_AllScannersRegistered(t *testing.T) {
	registry := NewDefaultRegistry(nil)

	scanners := []string{"udp", "tcp", "dot", "doh"}
	for _, name := range scanners {
		scanner, ok := registry.Get(name)
		assert.True(t, ok, "Scanner %s should be registered", name)
		assert.NotNil(t, scanner)
		assert.Equal(t, name, scanner.Name())
	}
}

func TestDefaultRegistry_UnknownScanner(t *testing.T) {
	registry := NewDefaultRegistry(nil)

	scanner, ok := registry.Get("unknown")
	assert.False(t, ok)
	assert.Nil(t, scanner)
}

func TestDefaultRegistry_GetByNames(t *testing.T) {
	registry := NewDefaultRegistry(nil)

	scanners := registry.GetByNames([]string{"udp", "tcp"})
	assert.Len(t, scanners, 2)
	assert.Equal(t, "udp", scanners[0].Name())
	assert.Equal(t, "tcp", scanners[1].Name())
}

func TestDefaultRegistry_GetByNamesWithInvalid(t *testing.T) {
	registry := NewDefaultRegistry(nil)

	scanners := registry.GetByNames([]string{"udp", "invalid", "tcp"})
	assert.Len(t, scanners, 2)
	assert.Equal(t, "udp", scanners[0].Name())
	assert.Equal(t, "tcp", scanners[1].Name())
}

func TestDefaultRegistry_All(t *testing.T) {
	registry := NewDefaultRegistry(nil)

	allScanners := registry.All()
	assert.Len(t, allScanners, 4)

	names := make(map[string]bool)
	for _, s := range allScanners {
		names[s.Name()] = true
	}

	assert.True(t, names["udp"])
	assert.True(t, names["tcp"])
	assert.True(t, names["dot"])
	assert.True(t, names["doh"])
}

// =============================================================================
// ScanResult Unit Tests
// =============================================================================

func TestScanResult_DefaultValues(t *testing.T) {
	result := &ScanResult{}

	assert.Empty(t, result.ScannerName)
	assert.False(t, result.Success)
	assert.Empty(t, result.Error)
	assert.Nil(t, result.DomainsResolved)
}

func TestScanResult_WithValues(t *testing.T) {
	result := &ScanResult{
		ScannerName:     "udp",
		Success:         true,
		ResponseTime:    50 * time.Millisecond,
		DomainsResolved: []string{"google.com"},
		Recursive:       true,
		SupportsEDNS:    true,
	}

	assert.Equal(t, "udp", result.ScannerName)
	assert.True(t, result.Success)
	assert.Equal(t, 50*time.Millisecond, result.ResponseTime)
	assert.Equal(t, []string{"google.com"}, result.DomainsResolved)
	assert.True(t, result.Recursive)
	assert.True(t, result.SupportsEDNS)
}

// =============================================================================
// TestResult (for full DNS testing) Unit Tests
// =============================================================================

func TestTestResult_DefaultValues(t *testing.T) {
	result := &TestResult{}

	assert.Empty(t, result.IP)
	assert.False(t, result.UDPPortOpen)
	assert.False(t, result.TCPPortOpen)
	assert.False(t, result.RespondsToQueries)
}

func TestTestResult_FullyPopulated(t *testing.T) {
	result := &TestResult{
		IP:                  "1.1.1.1",
		UDPPortOpen:         true,
		TCPPortOpen:         true,
		RespondsToQueries:   true,
		SupportsRecursion:   true,
		SupportsTCP:         true,
		SupportsEDNS:        true,
		SupportsDoT:         true,
		DoTResponseTime:     25 * time.Millisecond,
		DoTResponseTimeMs:   25,
		SupportsDoH:         true,
		DoHEndpoint:         "/dns-query",
		DoHResponseTime:     30 * time.Millisecond,
		DoHResponseTimeMs:   30,
		TestDomainsResolved: []string{"google.com", "cloudflare.com"},
		DNSServerType:       "recursive",
	}

	assert.Equal(t, "1.1.1.1", result.IP)
	assert.True(t, result.UDPPortOpen)
	assert.True(t, result.SupportsRecursion)
	assert.Equal(t, "recursive", result.DNSServerType)
	assert.Len(t, result.TestDomainsResolved, 2)
}

// =============================================================================
// Milliseconds Type Unit Tests
// =============================================================================

func TestMilliseconds_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		ms       Milliseconds
		expected string
	}{
		{"zero", 0, "0"},
		{"positive", 123, "123"},
		{"large", 9999, "9999"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.ms.MarshalJSON()
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(data))
		})
	}
}

// =============================================================================
// DoH Endpoint Unit Tests
// =============================================================================

func TestCommonDoHEndpoints(t *testing.T) {
	// Verify all endpoints are POST only (GET not implemented)
	for _, endpoint := range CommonDoHEndpoints {
		assert.Equal(t, "POST", endpoint.Method, "All endpoints should be POST")
		assert.NotEmpty(t, endpoint.Path)
	}
}

func TestDoHEndpoint_StandardPaths(t *testing.T) {
	paths := make(map[string]bool)
	for _, endpoint := range CommonDoHEndpoints {
		paths[endpoint.Path] = true
	}

	// Standard RFC 8484 path should be present
	assert.True(t, paths["/dns-query"], "RFC 8484 /dns-query should be present")
}
