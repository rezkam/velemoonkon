package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/velemoonkon/lightning/pkg/config"
	"github.com/velemoonkon/lightning/pkg/input"
	"github.com/velemoonkon/lightning/pkg/output"
	"github.com/velemoonkon/lightning/pkg/scanner"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// CLI flags
var (
	// Input
	inputFile string

	// Probes
	enableDNS    bool
	enableICMP   bool
	enableTunnel bool
	enablePorts  bool
	noDNS        bool
	noPorts      bool

	// DNS options
	dnsProto string

	// ICMP options
	icmpCount      int
	icmpPrivileged bool
	icmpUDP        bool

	// Tunnel options
	tunnelType   string
	tunnelDomain string

	// Output
	outputFile   string
	outputFormat string

	// Performance
	workers int
	timeout int
	rate    int

	// Logging
	quiet   bool
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "lightning [flags] <target>...",
	Short: "High-performance network scanner",
	Long: `Lightning - Fast network scanning for DNS, ICMP, and tunnel detection

Scans IP addresses and CIDR ranges for:
  • DNS servers (UDP, TCP, DoT, DoH)
  • ICMP reachability (ping)
  • DNS tunnel endpoints (DNSTT, Iodine, DNScat2, DNS2TCP)
  • Open ports (53, 443, 853)

Output formats:
  • JSONL (default) - streaming, pipe to jq
  • Parquet - columnar, query with DuckDB`,

	Example: `  # Basic DNS scan
  lightning 8.8.8.8

  # Scan CIDR range, save to file
  lightning 10.0.0.0/24 -o results.jsonl

  # ICMP ping only (requires root)
  sudo lightning 8.8.8.8 --icmp --no-dns --no-ports

  # DNS + ICMP combined
  sudo lightning 8.8.8.0/24 --icmp -o scan.jsonl

  # Only test DoH and DoT
  lightning 1.1.1.1 --dns-proto dot,doh

  # Tunnel detection
  lightning 1.1.1.1 --tunnel --tunnel-domain t.example.com

  # High-performance scan
  lightning 5.62.160.0/19 -w 500 -r 2000 -o results.jsonl

  # Parquet output for analytics
  lightning 10.0.0.0/16 --format parquet -o scan.parquet
  # Then query: duckdb -c "SELECT ip FROM 'scan.parquet' WHERE dns_supports_doh"

  # Pipe JSONL to jq
  lightning 1.1.1.1 | jq '.dns_result'

  # Read targets from file
  lightning -f targets.txt -o results.jsonl`,

	Args: func(cmd *cobra.Command, args []string) error {
		if inputFile == "" && len(args) == 0 {
			return fmt.Errorf("requires target(s) or -f/--file")
		}
		return nil
	},
	RunE:          runScan,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.SetVersionTemplate(fmt.Sprintf("lightning %s (commit: %s, built: %s)\n", version, commit, date))

	f := rootCmd.Flags()

	// Input
	f.StringVarP(&inputFile, "file", "f", "", "Read targets from file (one per line)")

	// Probes
	f.BoolVar(&enableDNS, "dns", false, "Enable DNS scanning")
	f.BoolVar(&enableICMP, "icmp", false, "Enable ICMP ping (requires root)")
	f.BoolVar(&enableTunnel, "tunnel", false, "Enable tunnel detection")
	f.BoolVar(&enablePorts, "ports", false, "Enable port scanning")
	f.BoolVar(&noDNS, "no-dns", false, "Disable DNS scanning")
	f.BoolVar(&noPorts, "no-ports", false, "Disable port scanning")

	// DNS options
	f.StringVar(&dnsProto, "dns-proto", "all", "DNS protocols: all, udp, tcp, dot, doh")

	// ICMP options
	f.IntVar(&icmpCount, "icmp-count", 1, "ICMP pings per IP")
	f.BoolVar(&icmpPrivileged, "icmp-privileged", true, "Use raw sockets (requires root)")
	f.BoolVar(&icmpUDP, "icmp-udp", false, "Use UDP sockets (no root needed)")

	// Tunnel options
	f.StringVar(&tunnelType, "tunnel-type", "all", "Tunnel types: all, dnstt, iodine, dnscat2, dns2tcp")
	f.StringVar(&tunnelDomain, "tunnel-domain", "", "Domain for tunnel detection")

	// Output
	f.StringVarP(&outputFile, "output", "o", "-", "Output file (- for stdout)")
	f.StringVar(&outputFormat, "format", "jsonl", "Output format: jsonl, parquet")

	// Performance
	f.IntVarP(&workers, "workers", "w", 100, "Concurrent workers")
	f.IntVarP(&timeout, "timeout", "t", 5, "Timeout per IP (seconds)")
	f.IntVarP(&rate, "rate", "r", 1000, "Max IPs/second (0 = unlimited)")

	// Logging
	f.BoolVarP(&quiet, "quiet", "q", false, "Suppress progress output")
	f.BoolVarP(&verbose, "verbose", "v", false, "Verbose logging")

	// Group flags in help
	rootCmd.SetUsageTemplate(usageTemplate)
}

func runScan(cmd *cobra.Command, args []string) error {
	initLogger()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		slog.Info("stopping scan...")
		cancel()
	}()

	// Parse targets
	ips, err := parseTargets(args)
	if err != nil {
		return err
	}

	if len(ips) == 0 {
		return fmt.Errorf("no valid IP addresses found")
	}

	slog.Info("starting scan", "targets", len(ips))

	// Resolve probe settings
	// Default: DNS and ports enabled, ICMP and tunnel disabled
	doDNS := (enableDNS || !noDNS) && !noDNS
	doPorts := (enablePorts || !noPorts) && !noPorts
	doICMP := enableICMP
	doTunnel := enableTunnel

	// If user explicitly enabled something, don't use defaults
	if enableDNS || enableICMP || enableTunnel || enablePorts {
		doDNS = enableDNS
		doPorts = enablePorts
	}

	// Parse DNS protocols
	udp, tcp, dot, doh := parseDNSProto(dnsProto)

	// Parse tunnel types - only enabled if --tunnel flag is set
	var tunnelEnabled, dnstt, iodine, dnscat2, dns2tcp bool
	if doTunnel {
		tunnelEnabled, dnstt, iodine, dnscat2, dns2tcp = parseTunnelTypes(tunnelType)
	}

	// ICMP socket type
	privileged := icmpPrivileged && !icmpUDP

	// Build scanner config
	cfg := scanner.Config{
		Workers:        workers,
		DNSConcurrency: config.Scanner.DefaultDNSConcurrency,
		Timeout:        timeout,
		RateLimit:      rate,
		// ICMP
		EnableICMP:     doICMP,
		ICMPCount:      icmpCount,
		ICMPPrivileged: privileged,
		// DNS
		EnableUDP: doDNS && udp,
		EnableTCP: doDNS && tcp,
		EnableDoT: doDNS && dot,
		EnableDoH: doDNS && doh,
		// Tunnel
		EnableTunnel:  tunnelEnabled,
		TunnelDNSTT:   dnstt,
		TunnelIodine:  iodine,
		TunnelDNScat2: dnscat2,
		TunnelDNS2TCP: dns2tcp,
		TunnelDomain:  tunnelDomain,
		// Ports
		EnablePortScan: doPorts,
		// Other
		TestDomains: parseTestDomains(config.Scanner.DefaultTestDomains),
		Verbose:     verbose,
		Quiet:       quiet,
	}

	// Create and start scanner
	s := scanner.NewScanner(cfg)
	if err := s.Start(); err != nil {
		return fmt.Errorf("failed to start: %w", err)
	}
	defer s.Stop()

	// Setup output writer
	resultHandler, closeWriter, err := createOutputWriter()
	if err != nil {
		return err
	}

	startTime := time.Now()

	// Run scan
	ipSeq := slices.Values(ips)
	resultCount, scanErr := s.ScanStream(ctx, ipSeq, resultHandler)

	// Close writer
	if closeErr := closeWriter(); closeErr != nil && scanErr == nil {
		scanErr = closeErr
	}

	if scanErr != nil && ctx.Err() == nil {
		return fmt.Errorf("scan failed: %w", scanErr)
	}

	slog.Info("scan completed", "results", resultCount, "duration", time.Since(startTime).Round(time.Millisecond))

	return nil
}

func parseTargets(args []string) ([]net.IP, error) {
	if inputFile != "" {
		slog.Debug("reading targets", "file", inputFile)
		return input.ParseFile(inputFile)
	}
	return input.ParseTargets(args)
}

func createOutputWriter() (func(*scanner.ScanResult) error, func() error, error) {
	format := strings.ToLower(outputFormat)

	switch format {
	case "parquet":
		if outputFile == "-" {
			return nil, nil, fmt.Errorf("parquet cannot write to stdout, use -o file.parquet")
		}
		pw, err := output.NewParquetWriter(outputFile)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create parquet writer: %w", err)
		}
		return pw.Write, pw.Close, nil

	default: // jsonl
		jw, err := output.NewWriter(outputFile)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create writer: %w", err)
		}
		return jw.Write, jw.Close, nil
	}
}

func initLogger() {
	var level slog.Level
	switch {
	case verbose:
		level = slog.LevelDebug
	case quiet:
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}

func parseDNSProto(proto string) (udp, tcp, dot, doh bool) {
	proto = strings.ToLower(strings.TrimSpace(proto))

	if proto == "" || proto == "all" {
		return true, true, true, true
	}
	if proto == "none" {
		return false, false, false, false
	}

	for _, p := range strings.Split(proto, ",") {
		switch strings.TrimSpace(p) {
		case "udp":
			udp = true
		case "tcp":
			tcp = true
		case "dot":
			dot = true
		case "doh":
			doh = true
		}
	}
	return
}

func parseTunnelTypes(types string) (enabled, dnstt, iodine, dnscat2, dns2tcp bool) {
	types = strings.ToLower(strings.TrimSpace(types))

	if types == "" || types == "none" {
		return false, false, false, false, false
	}
	if types == "all" {
		return true, true, true, true, true
	}

	for _, t := range strings.Split(types, ",") {
		switch strings.TrimSpace(t) {
		case "dnstt":
			dnstt, enabled = true, true
		case "iodine":
			iodine, enabled = true, true
		case "dnscat2":
			dnscat2, enabled = true, true
		case "dns2tcp":
			dns2tcp, enabled = true, true
		}
	}
	return
}

func parseTestDomains(domains string) []string {
	if domains == "" {
		return []string{"chatgpt.com", "google.com", "microsoft.com"}
	}

	var result []string
	for _, d := range strings.Split(domains, ",") {
		if d = strings.TrimSpace(d); d != "" {
			result = append(result, d)
		}
	}

	if len(result) == 0 {
		return []string{"chatgpt.com", "google.com", "microsoft.com"}
	}
	return result
}

func main() {
	config.Init()

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

const usageTemplate = `Usage:
  {{.UseLine}}

Examples:
{{.Example}}

Input:
  -f, --file string        Read targets from file

Probes:
      --dns                Enable DNS scanning (default when no probe specified)
      --icmp               Enable ICMP ping (requires root)
      --tunnel             Enable tunnel detection
      --ports              Enable port scanning (default when no probe specified)
      --no-dns             Disable DNS scanning
      --no-ports           Disable port scanning

DNS Options:
      --dns-proto string   Protocols: all, udp, tcp, dot, doh (default "all")

ICMP Options:
      --icmp-count int     Pings per IP (default 1)
      --icmp-privileged    Use raw sockets, requires root (default true)
      --icmp-udp           Use UDP sockets, no root needed

Tunnel Options:
      --tunnel-type string   Types: all, dnstt, iodine, dnscat2, dns2tcp (default "all")
      --tunnel-domain string Domain for detection

Output:
  -o, --output string      Output file, - for stdout (default "-")
      --format string      Format: jsonl, parquet (default "jsonl")

Performance:
  -w, --workers int        Concurrent workers (default 100)
  -t, --timeout int        Timeout per IP in seconds (default 5)
  -r, --rate int           Max IPs/second, 0=unlimited (default 1000)

Logging:
  -q, --quiet              Suppress progress output
  -v, --verbose            Verbose logging

Other:
  -h, --help               Show help
      --version            Show version
`
