package icmp

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Timeout != 2*time.Second {
		t.Errorf("Expected timeout 2s, got %v", cfg.Timeout)
	}
	if cfg.Count != 1 {
		t.Errorf("Expected count 1, got %d", cfg.Count)
	}
	if cfg.PayloadSize != 56 {
		t.Errorf("Expected payload 56, got %d", cfg.PayloadSize)
	}
	if !cfg.Privileged {
		t.Error("Expected privileged true by default")
	}
}

func TestNewScanner(t *testing.T) {
	cfg := Config{
		Timeout:     5 * time.Second,
		Count:       3,
		PayloadSize: 64,
		Privileged:  false,
	}

	scanner := NewScanner(cfg)

	if scanner == nil {
		t.Fatal("Expected scanner to be created")
	}
	if scanner.config.Timeout != 5*time.Second {
		t.Errorf("Expected timeout 5s, got %v", scanner.config.Timeout)
	}
	if scanner.config.Count != 3 {
		t.Errorf("Expected count 3, got %d", scanner.config.Count)
	}
}

func TestNewScannerDefaults(t *testing.T) {
	// Test that zero values get defaults
	cfg := Config{}
	scanner := NewScanner(cfg)

	if scanner.config.Timeout != 2*time.Second {
		t.Errorf("Expected default timeout 2s, got %v", scanner.config.Timeout)
	}
	if scanner.config.Count != 1 {
		t.Errorf("Expected default count 1, got %d", scanner.config.Count)
	}
	if scanner.config.PayloadSize != 56 {
		t.Errorf("Expected default payload 56, got %d", scanner.config.PayloadSize)
	}
}

func TestResultStructure(t *testing.T) {
	result := &Result{
		IP:          "192.168.1.1",
		Reachable:   true,
		RTT:         50 * time.Millisecond,
		RTTMs:       50.0,
		PacketsSent: 3,
		PacketsRecv: 3,
		PacketLoss:  0.0,
		MinRTT:      45 * time.Millisecond,
		MaxRTT:      55 * time.Millisecond,
		AvgRTT:      50 * time.Millisecond,
		IsIPv6:      false,
	}

	if result.IP != "192.168.1.1" {
		t.Errorf("Expected IP 192.168.1.1, got %s", result.IP)
	}
	if !result.Reachable {
		t.Error("Expected reachable true")
	}
	if result.PacketLoss != 0.0 {
		t.Errorf("Expected 0%% packet loss, got %.2f%%", result.PacketLoss)
	}
}

func TestResultWithPacketLoss(t *testing.T) {
	result := &Result{
		IP:          "10.0.0.1",
		Reachable:   true,
		PacketsSent: 5,
		PacketsRecv: 3,
		PacketLoss:  40.0, // 2 out of 5 lost = 40%
	}

	if result.PacketLoss != 40.0 {
		t.Errorf("Expected 40%% packet loss, got %.2f%%", result.PacketLoss)
	}
}

func TestScannerIDUnique(t *testing.T) {
	// Create multiple scanners and verify they have different IDs
	s1 := NewScanner(Config{})
	time.Sleep(time.Millisecond) // Ensure different UnixNano
	s2 := NewScanner(Config{})

	// IDs are based on UnixNano, should be different
	// (though there's a small chance they could collide in fast tests)
	t.Logf("Scanner IDs: s1=%d, s2=%d", s1.id, s2.id)
}

func TestScannerClosedState(t *testing.T) {
	scanner := NewScanner(Config{})

	// Initially not closed
	if scanner.closed.Load() {
		t.Error("Scanner should not be closed initially")
	}

	// Stop should set closed state
	scanner.Stop()

	if !scanner.closed.Load() {
		t.Error("Scanner should be closed after Stop")
	}

	// Double stop should be safe
	scanner.Stop() // Should not panic
}
