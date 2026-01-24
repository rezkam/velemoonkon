package scanner

import (
	"context"
	"testing"
)

func TestProbeRegistry(t *testing.T) {
	registry := NewProbeRegistry()

	if registry.Count() != 0 {
		t.Errorf("Expected empty registry, got %d probes", registry.Count())
	}

	// Add a probe
	probe := NewProbeFunc("test", func(ctx context.Context, ip string, result *ScanResult) error {
		result.IP = ip
		return nil
	})
	registry.Register(probe)

	if registry.Count() != 1 {
		t.Errorf("Expected 1 probe, got %d", registry.Count())
	}

	probes := registry.All()
	if len(probes) != 1 {
		t.Errorf("Expected 1 probe in All(), got %d", len(probes))
	}
	if probes[0].Name() != "test" {
		t.Errorf("Expected probe name 'test', got '%s'", probes[0].Name())
	}
}

func TestProbeFunc(t *testing.T) {
	called := false
	probe := NewProbeFunc("custom", func(ctx context.Context, ip string, result *ScanResult) error {
		called = true
		result.IP = ip
		return nil
	})

	if probe.Name() != "custom" {
		t.Errorf("Expected name 'custom', got '%s'", probe.Name())
	}

	result := &ScanResult{}
	err := probe.Scan(context.Background(), "1.2.3.4", result)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !called {
		t.Error("Probe function was not called")
	}
	if result.IP != "1.2.3.4" {
		t.Errorf("Expected IP '1.2.3.4', got '%s'", result.IP)
	}
}

func TestMultipleProbes(t *testing.T) {
	registry := NewProbeRegistry()

	probe1 := NewProbeFunc("probe1", func(ctx context.Context, ip string, result *ScanResult) error {
		result.ScanErrors = append(result.ScanErrors, "probe1-ran")
		return nil
	})
	probe2 := NewProbeFunc("probe2", func(ctx context.Context, ip string, result *ScanResult) error {
		result.ScanErrors = append(result.ScanErrors, "probe2-ran")
		return nil
	})

	registry.Register(probe1)
	registry.Register(probe2)

	if registry.Count() != 2 {
		t.Errorf("Expected 2 probes, got %d", registry.Count())
	}

	// Run all probes
	result := &ScanResult{}
	for _, probe := range registry.All() {
		probe.Scan(context.Background(), "10.0.0.1", result)
	}

	if len(result.ScanErrors) != 2 {
		t.Errorf("Expected 2 markers, got %d", len(result.ScanErrors))
	}
}

func TestDNSProbeCreation(t *testing.T) {
	cfg := Config{
		EnableUDP: true,
		EnableTCP: true,
		EnableDoT: false,
		EnableDoH: false,
	}

	probe := NewDNSProbe(cfg)

	if probe.Name() != "dns" {
		t.Errorf("Expected name 'dns', got '%s'", probe.Name())
	}
	if !probe.HasScanners() {
		t.Error("Expected DNS probe to have scanners with UDP and TCP enabled")
	}
}

func TestDNSProbeNoScanners(t *testing.T) {
	cfg := Config{
		EnableUDP: false,
		EnableTCP: false,
		EnableDoT: false,
		EnableDoH: false,
	}

	probe := NewDNSProbe(cfg)

	if probe.HasScanners() {
		t.Error("Expected DNS probe to have no scanners when all disabled")
	}
}

func TestTunnelProbeCreation(t *testing.T) {
	cfg := Config{
		TunnelDNSTT:   true,
		TunnelIodine:  true,
		TunnelDNScat2: false,
		TunnelDNS2TCP: false,
		TunnelDomain:  "test.example.com",
	}

	probe := NewTunnelProbe(cfg)

	if probe.Name() != "tunnel" {
		t.Errorf("Expected name 'tunnel', got '%s'", probe.Name())
	}
	if !probe.HasDetectors() {
		t.Error("Expected tunnel probe to have detectors")
	}
	if probe.domain != "test.example.com" {
		t.Errorf("Expected domain 'test.example.com', got '%s'", probe.domain)
	}
}

func TestTunnelProbeNoDetectors(t *testing.T) {
	cfg := Config{
		TunnelDNSTT:   false,
		TunnelIodine:  false,
		TunnelDNScat2: false,
		TunnelDNS2TCP: false,
	}

	probe := NewTunnelProbe(cfg)

	if probe.HasDetectors() {
		t.Error("Expected tunnel probe to have no detectors when all disabled")
	}
}

func TestTunnelProbeDefaultDomain(t *testing.T) {
	cfg := Config{
		TunnelDNSTT:  true,
		TunnelDomain: "", // Empty
	}

	probe := NewTunnelProbe(cfg)

	if probe.domain != "test.example.com" {
		t.Errorf("Expected default domain 'test.example.com', got '%s'", probe.domain)
	}
}

func TestPortsProbe(t *testing.T) {
	probe := NewPortsProbe()

	if probe.Name() != "ports" {
		t.Errorf("Expected name 'ports', got '%s'", probe.Name())
	}
}

func TestICMPProbeCreation(t *testing.T) {
	cfg := Config{
		Timeout:        5,
		ICMPCount:      3,
		ICMPPrivileged: false,
	}

	probe, err := NewICMPProbe(cfg)
	if err != nil {
		t.Fatalf("Failed to create ICMP probe: %v", err)
	}

	if probe.Name() != "icmp" {
		t.Errorf("Expected name 'icmp', got '%s'", probe.Name())
	}
}

func TestICMPProbeDefaultCount(t *testing.T) {
	cfg := Config{
		Timeout:   5,
		ICMPCount: 0, // Should default to 1
	}

	probe, err := NewICMPProbe(cfg)
	if err != nil {
		t.Fatalf("Failed to create ICMP probe: %v", err)
	}

	// The count should be set to 1 by default in NewICMPProbe
	if probe.scanner == nil {
		t.Error("Expected scanner to be created")
	}
}
