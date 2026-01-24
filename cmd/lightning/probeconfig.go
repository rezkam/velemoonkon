package main

// ProbeFlags represents the CLI flags for probe configuration
type ProbeFlags struct {
	// Explicit enable flags
	EnableDNS    bool
	EnableICMP   bool
	EnableTunnel bool
	EnablePorts  bool

	// Explicit disable flags
	NoDNS   bool
	NoPorts bool

	// DNS options
	DNSProto string // "all", "udp", "tcp", "dot", "doh", or comma-separated

	// Tunnel options
	TunnelType   string // "all", "none", "dnstt", "iodine", "dnscat2", "dns2tcp", or comma-separated
	TunnelDomain string

	// ICMP options
	ICMPCount      int
	ICMPPrivileged bool
	ICMPUseUDP     bool
}

// ProbeConfig represents the resolved probe configuration
type ProbeConfig struct {
	// DNS
	EnableUDP bool
	EnableTCP bool
	EnableDoT bool
	EnableDoH bool

	// ICMP
	EnableICMP     bool
	ICMPCount      int
	ICMPPrivileged bool

	// Tunnel
	EnableTunnel  bool
	TunnelDNSTT   bool
	TunnelIodine  bool
	TunnelDNScat2 bool
	TunnelDNS2TCP bool
	TunnelDomain  string

	// Ports
	EnablePortScan bool
}

// ResolveProbeConfig resolves CLI flags to probe configuration
// Default behavior: DNS and ports enabled, ICMP and tunnel disabled
func ResolveProbeConfig(flags ProbeFlags) ProbeConfig {
	// Resolve probe settings
	// Default: DNS and ports enabled, ICMP and tunnel disabled
	doDNS := (flags.EnableDNS || !flags.NoDNS) && !flags.NoDNS
	doPorts := (flags.EnablePorts || !flags.NoPorts) && !flags.NoPorts
	doICMP := flags.EnableICMP
	doTunnel := flags.EnableTunnel

	// If user explicitly enabled something, don't use defaults
	if flags.EnableDNS || flags.EnableICMP || flags.EnableTunnel || flags.EnablePorts {
		doDNS = flags.EnableDNS
		doPorts = flags.EnablePorts
	}

	// Parse DNS protocols
	udp, tcp, dot, doh := parseDNSProto(flags.DNSProto)

	// Parse tunnel types - only enabled if --tunnel flag is set
	var tunnelEnabled, dnstt, iodine, dnscat2, dns2tcp bool
	if doTunnel {
		tunnelEnabled, dnstt, iodine, dnscat2, dns2tcp = parseTunnelTypes(flags.TunnelType)
	}

	// ICMP socket type
	privileged := flags.ICMPPrivileged && !flags.ICMPUseUDP

	return ProbeConfig{
		// DNS
		EnableUDP: doDNS && udp,
		EnableTCP: doDNS && tcp,
		EnableDoT: doDNS && dot,
		EnableDoH: doDNS && doh,

		// ICMP
		EnableICMP:     doICMP,
		ICMPCount:      flags.ICMPCount,
		ICMPPrivileged: privileged,

		// Tunnel
		EnableTunnel:  tunnelEnabled,
		TunnelDNSTT:   dnstt,
		TunnelIodine:  iodine,
		TunnelDNScat2: dnscat2,
		TunnelDNS2TCP: dns2tcp,
		TunnelDomain:  flags.TunnelDomain,

		// Ports
		EnablePortScan: doPorts,
	}
}
