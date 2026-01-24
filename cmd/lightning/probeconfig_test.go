package main

import (
	"testing"
)

func TestResolveProbeConfig_Defaults(t *testing.T) {
	// Default run: lightning <target>
	// Should enable DNS and ports, disable ICMP and tunnel
	flags := ProbeFlags{
		DNSProto:       "all",
		TunnelType:     "all", // Default value, but should NOT enable tunnel
		ICMPPrivileged: true,
	}

	cfg := ResolveProbeConfig(flags)

	// DNS should be enabled by default
	if !cfg.EnableUDP || !cfg.EnableTCP || !cfg.EnableDoT || !cfg.EnableDoH {
		t.Error("DNS should be enabled by default")
	}

	// Ports should be enabled by default
	if !cfg.EnablePortScan {
		t.Error("Port scanning should be enabled by default")
	}

	// ICMP should be disabled by default
	if cfg.EnableICMP {
		t.Error("ICMP should be disabled by default (requires --icmp flag)")
	}

	// Tunnel should be disabled by default even with TunnelType="all"
	if cfg.EnableTunnel {
		t.Error("Tunnel detection should be disabled by default (requires --tunnel flag)")
	}
	if cfg.TunnelDNSTT || cfg.TunnelIodine || cfg.TunnelDNScat2 || cfg.TunnelDNS2TCP {
		t.Error("Tunnel detectors should all be false when --tunnel is not set")
	}
}

func TestResolveProbeConfig_TunnelFlag(t *testing.T) {
	// lightning <target> --tunnel
	flags := ProbeFlags{
		EnableTunnel: true,
		TunnelType:   "all",
		DNSProto:     "all",
	}

	cfg := ResolveProbeConfig(flags)

	// Tunnel should be enabled
	if !cfg.EnableTunnel {
		t.Error("Tunnel should be enabled with --tunnel flag")
	}
	if !cfg.TunnelDNSTT || !cfg.TunnelIodine || !cfg.TunnelDNScat2 || !cfg.TunnelDNS2TCP {
		t.Error("All tunnel detectors should be enabled with --tunnel --tunnel-type=all")
	}

	// When explicit flags are used, defaults are disabled
	if cfg.EnableUDP || cfg.EnableTCP {
		t.Error("DNS should be disabled when --tunnel is explicitly set without --dns")
	}
	if cfg.EnablePortScan {
		t.Error("Port scan should be disabled when --tunnel is explicitly set without --ports")
	}
}

func TestResolveProbeConfig_TunnelTypeSpecific(t *testing.T) {
	// lightning <target> --tunnel --tunnel-type=dnstt,iodine
	flags := ProbeFlags{
		EnableTunnel: true,
		TunnelType:   "dnstt,iodine",
	}

	cfg := ResolveProbeConfig(flags)

	if !cfg.EnableTunnel {
		t.Error("Tunnel should be enabled")
	}
	if !cfg.TunnelDNSTT {
		t.Error("DNSTT should be enabled")
	}
	if !cfg.TunnelIodine {
		t.Error("Iodine should be enabled")
	}
	if cfg.TunnelDNScat2 {
		t.Error("DNScat2 should be disabled")
	}
	if cfg.TunnelDNS2TCP {
		t.Error("DNS2TCP should be disabled")
	}
}

func TestResolveProbeConfig_ICMPFlag(t *testing.T) {
	// lightning <target> --icmp
	flags := ProbeFlags{
		EnableICMP:     true,
		ICMPPrivileged: true,
		DNSProto:       "all",
		TunnelType:     "all",
	}

	cfg := ResolveProbeConfig(flags)

	// ICMP should be enabled
	if !cfg.EnableICMP {
		t.Error("ICMP should be enabled with --icmp flag")
	}
	if !cfg.ICMPPrivileged {
		t.Error("ICMP should use privileged mode by default")
	}

	// Other probes disabled when explicit flag used
	if cfg.EnableUDP || cfg.EnableTCP {
		t.Error("DNS should be disabled when --icmp is explicitly set without --dns")
	}
	if cfg.EnableTunnel {
		t.Error("Tunnel should still be disabled without --tunnel flag")
	}
}

func TestResolveProbeConfig_ICMPUDPMode(t *testing.T) {
	// lightning <target> --icmp --icmp-udp
	flags := ProbeFlags{
		EnableICMP:     true,
		ICMPPrivileged: true, // Default
		ICMPUseUDP:     true, // Override to UDP mode
	}

	cfg := ResolveProbeConfig(flags)

	if !cfg.EnableICMP {
		t.Error("ICMP should be enabled")
	}
	if cfg.ICMPPrivileged {
		t.Error("ICMP should use unprivileged UDP mode when --icmp-udp is set")
	}
}

func TestResolveProbeConfig_NoDNS(t *testing.T) {
	// lightning <target> --no-dns
	flags := ProbeFlags{
		NoDNS:      true,
		DNSProto:   "all",
		TunnelType: "all",
	}

	cfg := ResolveProbeConfig(flags)

	// DNS should be disabled
	if cfg.EnableUDP || cfg.EnableTCP || cfg.EnableDoT || cfg.EnableDoH {
		t.Error("DNS should be disabled with --no-dns flag")
	}

	// Ports should still be enabled
	if !cfg.EnablePortScan {
		t.Error("Port scanning should still be enabled")
	}

	// Tunnel should still be disabled
	if cfg.EnableTunnel {
		t.Error("Tunnel should still be disabled without --tunnel flag")
	}
}

func TestResolveProbeConfig_NoPorts(t *testing.T) {
	// lightning <target> --no-ports
	flags := ProbeFlags{
		NoPorts:    true,
		DNSProto:   "all",
		TunnelType: "all",
	}

	cfg := ResolveProbeConfig(flags)

	// Ports should be disabled
	if cfg.EnablePortScan {
		t.Error("Port scanning should be disabled with --no-ports flag")
	}

	// DNS should still be enabled
	if !cfg.EnableUDP || !cfg.EnableTCP {
		t.Error("DNS should still be enabled")
	}
}

func TestResolveProbeConfig_DNSOnly(t *testing.T) {
	// lightning <target> --dns
	flags := ProbeFlags{
		EnableDNS:  true,
		DNSProto:   "all",
		TunnelType: "all",
	}

	cfg := ResolveProbeConfig(flags)

	// DNS should be enabled
	if !cfg.EnableUDP || !cfg.EnableTCP || !cfg.EnableDoT || !cfg.EnableDoH {
		t.Error("DNS should be enabled with --dns flag")
	}

	// Other probes disabled when explicit flag used
	if cfg.EnablePortScan {
		t.Error("Port scan should be disabled when --dns is explicitly set without --ports")
	}
	if cfg.EnableICMP {
		t.Error("ICMP should be disabled without --icmp flag")
	}
	if cfg.EnableTunnel {
		t.Error("Tunnel should be disabled without --tunnel flag")
	}
}

func TestResolveProbeConfig_DNSProtoSpecific(t *testing.T) {
	// lightning <target> --dns-proto=udp,doh
	flags := ProbeFlags{
		DNSProto:   "udp,doh",
		TunnelType: "all",
	}

	cfg := ResolveProbeConfig(flags)

	if !cfg.EnableUDP {
		t.Error("UDP should be enabled")
	}
	if cfg.EnableTCP {
		t.Error("TCP should be disabled")
	}
	if cfg.EnableDoT {
		t.Error("DoT should be disabled")
	}
	if !cfg.EnableDoH {
		t.Error("DoH should be enabled")
	}
}

func TestResolveProbeConfig_DNSProtoNone(t *testing.T) {
	// lightning <target> --dns-proto=none
	flags := ProbeFlags{
		DNSProto:   "none",
		TunnelType: "all",
	}

	cfg := ResolveProbeConfig(flags)

	if cfg.EnableUDP || cfg.EnableTCP || cfg.EnableDoT || cfg.EnableDoH {
		t.Error("All DNS protocols should be disabled with --dns-proto=none")
	}
}

func TestResolveProbeConfig_MultipleExplicitFlags(t *testing.T) {
	// lightning <target> --dns --icmp --tunnel
	flags := ProbeFlags{
		EnableDNS:    true,
		EnableICMP:   true,
		EnableTunnel: true,
		DNSProto:     "all",
		TunnelType:   "all",
	}

	cfg := ResolveProbeConfig(flags)

	// DNS should be enabled
	if !cfg.EnableUDP {
		t.Error("DNS should be enabled")
	}

	// ICMP should be enabled
	if !cfg.EnableICMP {
		t.Error("ICMP should be enabled")
	}

	// Tunnel should be enabled
	if !cfg.EnableTunnel {
		t.Error("Tunnel should be enabled")
	}

	// Ports should be disabled (not explicitly enabled)
	if cfg.EnablePortScan {
		t.Error("Port scan should be disabled when not explicitly enabled")
	}
}

func TestResolveProbeConfig_AllProbes(t *testing.T) {
	// lightning <target> --dns --icmp --tunnel --ports
	flags := ProbeFlags{
		EnableDNS:    true,
		EnableICMP:   true,
		EnableTunnel: true,
		EnablePorts:  true,
		DNSProto:     "all",
		TunnelType:   "all",
	}

	cfg := ResolveProbeConfig(flags)

	if !cfg.EnableUDP {
		t.Error("DNS should be enabled")
	}
	if !cfg.EnableICMP {
		t.Error("ICMP should be enabled")
	}
	if !cfg.EnableTunnel {
		t.Error("Tunnel should be enabled")
	}
	if !cfg.EnablePortScan {
		t.Error("Port scan should be enabled")
	}
}

func TestResolveProbeConfig_TunnelTypeNone(t *testing.T) {
	// Edge case: --tunnel --tunnel-type=none
	flags := ProbeFlags{
		EnableTunnel: true,
		TunnelType:   "none",
	}

	cfg := ResolveProbeConfig(flags)

	// Even with --tunnel, if tunnel-type=none, nothing should be enabled
	if cfg.EnableTunnel {
		t.Error("Tunnel should be disabled with --tunnel-type=none")
	}
}

func TestParseDNSProto(t *testing.T) {
	tests := []struct {
		name                       string
		proto                      string
		wantUDP, wantTCP, wantDoT, wantDoH bool
	}{
		{"all", "all", true, true, true, true},
		{"empty defaults to all", "", true, true, true, true},
		{"none", "none", false, false, false, false},
		{"udp only", "udp", true, false, false, false},
		{"tcp only", "tcp", false, true, false, false},
		{"dot only", "dot", false, false, true, false},
		{"doh only", "doh", false, false, false, true},
		{"udp,tcp", "udp,tcp", true, true, false, false},
		{"dot,doh", "dot,doh", false, false, true, true},
		{"mixed case", "UDP,DoH", true, false, false, true},
		{"with spaces", " udp , tcp ", true, true, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			udp, tcp, dot, doh := parseDNSProto(tt.proto)
			if udp != tt.wantUDP {
				t.Errorf("UDP: got %v, want %v", udp, tt.wantUDP)
			}
			if tcp != tt.wantTCP {
				t.Errorf("TCP: got %v, want %v", tcp, tt.wantTCP)
			}
			if dot != tt.wantDoT {
				t.Errorf("DoT: got %v, want %v", dot, tt.wantDoT)
			}
			if doh != tt.wantDoH {
				t.Errorf("DoH: got %v, want %v", doh, tt.wantDoH)
			}
		})
	}
}

func TestParseTunnelTypes(t *testing.T) {
	tests := []struct {
		name                                              string
		types                                             string
		wantEnabled, wantDNSTT, wantIodine, wantDNScat2, wantDNS2TCP bool
	}{
		{"all", "all", true, true, true, true, true},
		{"none", "none", false, false, false, false, false},
		{"empty", "", false, false, false, false, false},
		{"dnstt only", "dnstt", true, true, false, false, false},
		{"iodine only", "iodine", true, false, true, false, false},
		{"dnscat2 only", "dnscat2", true, false, false, true, false},
		{"dns2tcp only", "dns2tcp", true, false, false, false, true},
		{"dnstt,iodine", "dnstt,iodine", true, true, true, false, false},
		{"mixed case", "DNSTT,Iodine", true, true, true, false, false},
		{"with spaces", " dnstt , dns2tcp ", true, true, false, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enabled, dnstt, iodine, dnscat2, dns2tcp := parseTunnelTypes(tt.types)
			if enabled != tt.wantEnabled {
				t.Errorf("enabled: got %v, want %v", enabled, tt.wantEnabled)
			}
			if dnstt != tt.wantDNSTT {
				t.Errorf("dnstt: got %v, want %v", dnstt, tt.wantDNSTT)
			}
			if iodine != tt.wantIodine {
				t.Errorf("iodine: got %v, want %v", iodine, tt.wantIodine)
			}
			if dnscat2 != tt.wantDNScat2 {
				t.Errorf("dnscat2: got %v, want %v", dnscat2, tt.wantDNScat2)
			}
			if dns2tcp != tt.wantDNS2TCP {
				t.Errorf("dns2tcp: got %v, want %v", dns2tcp, tt.wantDNS2TCP)
			}
		})
	}
}
