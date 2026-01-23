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

	"github.com/velemoonkon/lightning/pkg/config"
	"github.com/velemoonkon/lightning/pkg/input"
	"github.com/velemoonkon/lightning/pkg/output"
	"github.com/velemoonkon/lightning/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"

	// File input
	inputFile string

	// Output options
	outputFormat string
	outputPrefix string
	quiet        bool
	verbose      bool

	// Scanner and detector types
	scannerTypes  string
	detectorTypes string
	tunnelDomain  string

	// Performance
	workers   int
	timeout   int
	rateLimit int
)

var rootCmd = &cobra.Command{
	Use:     "lightning [flags] <target>",
	Short:   "Fast DNS scanner with tunnel detection",
	Version: version,
	Long: `Lightning - Production-ready DNS testing and tunnel detection tool

Scans IPs for DNS functionality (UDP, TCP, DoT, DoH) and detects DNS tunnels
(DNSTT, Iodine, DNScat2, DNS2TCP) with high-performance concurrent scanning.

By default, outputs JSON reports with DNS scanning enabled and tunnel detection disabled.`,
	Example: `  # Scan single IP with DNS tests
  lightning 8.8.8.8

  # Scan CIDR range with high performance
  lightning 5.62.160.0/19 -w 500 --rate-limit 2000

  # Scan file with IPs/CIDRs
  lightning -f targets.txt

  # Output both JSON and Markdown
  lightning 8.8.8.8 --output-format json,md

  # Scan with all DNS tests (default)
  lightning 8.8.8.8 --scanner all

  # Only test UDP and TCP DNS
  lightning 8.8.8.8 --scanner udp,tcp

  # Only test DoH and DoT
  lightning 1.1.1.1 --scanner dot,doh

  # Enable tunnel detection for all types
  lightning 1.1.1.1 --detector all

  # Only detect DNSTT and Iodine tunnels
  lightning 1.1.1.1 --detector dnstt,iodine

  # Scan with specific tunnel domain
  lightning 1.1.1.1 --detector all --tunnel-domain tunnel.example.com`,
	Args: func(cmd *cobra.Command, args []string) error {
		if inputFile == "" && len(args) == 0 {
			return fmt.Errorf("requires either a target argument or --file flag")
		}
		return nil
	},
	RunE: runScan,
}

func init() {
	rootCmd.SetVersionTemplate(fmt.Sprintf("lightning %s (commit: %s, built: %s)\n", version, commit, date))

	rootCmd.SetHelpCommand(&cobra.Command{
		Use:    "help [command]",
		Short:  "Help about any command",
		Hidden: false,
	})
}

func init() {
	// File input
	rootCmd.Flags().StringVarP(&inputFile, "file", "f", "", "file containing IPs/CIDRs (one per line)")

	// Output options
	rootCmd.Flags().StringVar(&outputFormat, "output-format", "json", "output format: json, md, or json,md")
	rootCmd.Flags().StringVarP(&outputPrefix, "output", "o", "", "output file prefix (auto-generated if not specified)")
	rootCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "suppress progress output")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "verbose logging")

	// Scanner and detector types
	rootCmd.Flags().StringVar(&scannerTypes, "scanner", "all", "scanner types: all, udp, tcp, dot, doh (comma-separated)")
	rootCmd.Flags().StringVar(&detectorTypes, "detector", "", "detector types: all, dnstt, iodine, dnscat2, dns2tcp (comma-separated, default: disabled)")
	rootCmd.Flags().StringVar(&tunnelDomain, "tunnel-domain", "", "specific domain for tunnel detection")

	// Performance tuning
	rootCmd.Flags().IntVarP(&workers, "workers", "w", 100, "concurrent IP workers (0=auto: max(4, 4*CPUs) for I/O-bound work)")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "t", 5, "timeout per IP in seconds")
	rootCmd.Flags().IntVar(&rateLimit, "rate-limit", 1000, "max IPs per second (0=unlimited)")
}

// initLogger configures structured logging based on verbosity flags
func initLogger() {
	var level slog.Level
	if verbose {
		level = slog.LevelDebug
	} else if quiet {
		level = slog.LevelError
	} else {
		level = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})
	logger := slog.New(handler)
	slog.SetDefault(logger)
}

func runScan(cmd *cobra.Command, args []string) error {
	// Initialize structured logging
	initLogger()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		slog.Info("interrupt received, stopping scan")
		cancel()
	}()

	// Parse targets
	var ips []net.IP
	var err error

	if inputFile != "" {
		slog.Info("reading targets from file", "file", inputFile)
		ips, err = input.ParseFile(inputFile)
		if err != nil {
			return fmt.Errorf("failed to parse file: %w", err)
		}
	} else {
		ips, err = input.ParseTargets(args)
		if err != nil {
			return fmt.Errorf("failed to parse targets: %w", err)
		}
	}

	if len(ips) == 0 {
		return fmt.Errorf("no valid IP addresses found")
	}

	slog.Info("starting scan", "total_ips", len(ips))

	// Parse scanner and detector types
	enableUDP, enableTCP, enableDoT, enableDoH := parseScannerTypes(scannerTypes)
	enableTunnel, enableDNSTT, enableIodine, enableDNScat2, enableDNS2TCP := parseDetectorTypes(detectorTypes)

	// Parse test domains from ENV default
	domains := parseTestDomains(config.Scanner.DefaultTestDomains)

	// Create scanner config (uses ENV defaults for advanced settings)
	scannerConfig := scanner.Config{
		Workers:         workers,
		DNSConcurrency:  config.Scanner.DefaultDNSConcurrency, // From ENV: LIGHTNING_DEFAULT_DNS_CONCURRENCY
		Timeout:         timeout,
		RateLimit:       rateLimit,
		EnableUDP:       enableUDP,
		EnableTCP:       enableTCP,
		EnableDoT:       enableDoT,
		EnableDoH:       enableDoH,
		EnableTunnel:    enableTunnel,
		TunnelDNSTT:     enableDNSTT,
		TunnelIodine:    enableIodine,
		TunnelDNScat2:   enableDNScat2,
		TunnelDNS2TCP:   enableDNS2TCP,
		EnablePortScan:  config.Scanner.DefaultScanPorts, // From ENV: LIGHTNING_DEFAULT_SCAN_PORTS
		TunnelDomain:    tunnelDomain,
		TestDomains:     domains, // From ENV: LIGHTNING_DEFAULT_TEST_DOMAINS
		Verbose:         verbose,
		Quiet:           quiet,
	}

	// Create scanner
	s := scanner.NewScanner(scannerConfig)

	// Determine if we should use streaming output for large scans
	// Threshold: 10,000 IPs (avoids keeping ~10MB+ in memory)
	const streamingThreshold = 10000
	useStreaming := len(ips) >= streamingThreshold

	startTime := time.Now()

	if useStreaming {
		slog.Info("using streaming output for large scan", "total_ips", len(ips))
	}

	// Generate output filename prefix
	if outputPrefix == "" {
		timestamp := time.Now().Format("20060102_150405")
		if inputFile != "" {
			baseName := strings.TrimSuffix(inputFile, ".txt")
			baseName = strings.TrimSuffix(baseName, ".list")
			if idx := strings.LastIndex(baseName, "/"); idx >= 0 {
				baseName = baseName[idx+1:]
			}
			outputPrefix = fmt.Sprintf("lightning_%s_%dips_%s", baseName, len(ips), timestamp)
		} else if len(ips) == 1 {
			outputPrefix = fmt.Sprintf("lightning_%s_%s", ips[0].String(), timestamp)
		} else if len(args) > 0 && strings.Contains(args[0], "/") {
			cidr := strings.ReplaceAll(args[0], "/", "-")
			cidr = strings.ReplaceAll(cidr, ".", "_")
			outputPrefix = fmt.Sprintf("lightning_%s_%dips_%s", cidr, len(ips), timestamp)
		} else {
			outputPrefix = fmt.Sprintf("lightning_scan_%dips_%s", len(ips), timestamp)
		}
	}

	// Parse output formats
	writeJSON, writeMarkdown := parseOutputFormats(outputFormat)

	// Run scan with appropriate strategy
	if useStreaming {
		// Streaming approach: write results as they arrive (low memory)
		return runStreamingScan(ctx, s, ips, writeJSON, writeMarkdown, outputPrefix, startTime)
	}

	// Standard approach: collect all results then write (faster for small scans)
	results, err := s.Scan(ctx, ips)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	slog.Info("scan completed",
		"duration", time.Since(startTime).String(),
		"total_results", len(results))

	// Write output files
	if writeJSON {
		jsonFile := outputPrefix + ".json"
		if err := output.WriteJSON(results, jsonFile, startTime); err != nil {
			return fmt.Errorf("failed to write JSON: %w", err)
		}
		slog.Info("JSON report written", "file", jsonFile)
	}

	if writeMarkdown {
		mdFile := outputPrefix + ".md"
		if err := output.WriteMarkdown(results, mdFile, startTime); err != nil {
			return fmt.Errorf("failed to write Markdown: %w", err)
		}
		slog.Info("Markdown report written", "file", mdFile)
	}

	return nil
}

// runStreamingScan performs a scan with streaming output (low memory usage)
func runStreamingScan(ctx context.Context, s *scanner.Scanner, ips []net.IP, writeJSON, writeMarkdown bool, outputPrefix string, startTime time.Time) error {
	// Create streaming writers
	var jsonWriter, mdWriter *output.StreamWriter
	var err error

	if writeJSON {
		jsonFile := outputPrefix + ".json"
		jsonWriter, err = output.NewStreamWriter(jsonFile, "json", startTime, 100)
		if err != nil {
			return fmt.Errorf("failed to create JSON writer: %w", err)
		}
		defer jsonWriter.Close()
	}

	if writeMarkdown {
		mdFile := outputPrefix + ".md"
		mdWriter, err = output.NewStreamWriter(mdFile, "markdown", startTime, 100)
		if err != nil {
			return fmt.Errorf("failed to create markdown writer: %w", err)
		}
		defer mdWriter.Close()
	}

	// Result handler that writes to stream
	resultHandler := func(result *scanner.ScanResult) error {
		if jsonWriter != nil {
			if err := jsonWriter.WriteResult(result); err != nil {
				return err
			}
		}
		if mdWriter != nil {
			if err := mdWriter.WriteResult(result); err != nil {
				return err
			}
		}
		return nil
	}

	// Run streaming scan
	ipSeq := slices.Values(ips)
	resultCount, err := s.ScanStream(ctx, ipSeq, resultHandler)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	slog.Info("scan completed",
		"duration", time.Since(startTime).String(),
		"total_results", resultCount)

	// Close writers (finalizes files)
	if jsonWriter != nil {
		if err := jsonWriter.Close(); err != nil {
			return fmt.Errorf("failed to finalize JSON: %w", err)
		}
		slog.Info("JSON report written", "file", outputPrefix+".json")
	}

	if mdWriter != nil {
		if err := mdWriter.Close(); err != nil {
			return fmt.Errorf("failed to finalize markdown: %w", err)
		}
		slog.Info("Markdown report written", "file", outputPrefix+".md")
	}

	return nil
}

// parseTestDomains parses the test domains string
func parseTestDomains(domains string) []string {
	if domains == "" {
		return []string{"chatgpt.com", "google.com", "microsoft.com"}
	}

	parts := strings.Split(domains, ",")
	result := make([]string, 0, len(parts))
	for _, d := range parts {
		d = strings.TrimSpace(d)
		if d != "" {
			result = append(result, d)
		}
	}

	if len(result) == 0 {
		return []string{"chatgpt.com", "google.com", "microsoft.com"}
	}

	return result
}

// parseOutputFormats parses the output format string and returns which formats to write
func parseOutputFormats(format string) (json, markdown bool) {
	// Default to JSON only if empty
	if format == "" {
		return true, false
	}

	formats := strings.Split(format, ",")
	for _, f := range formats {
		f = strings.TrimSpace(strings.ToLower(f))
		switch f {
		case "json":
			json = true
		case "md", "markdown":
			markdown = true
		}
	}

	// If no valid format found, default to JSON
	if !json && !markdown {
		return true, false
	}

	return json, markdown
}

// parseScannerTypes parses the scanner types string
func parseScannerTypes(types string) (udp, tcp, dot, doh bool) {
	types = strings.TrimSpace(strings.ToLower(types))

	// Handle "all" case
	if types == "" || types == "all" {
		return true, true, true, true
	}

	// Handle "none" case
	if types == "none" {
		return false, false, false, false
	}

	// Parse comma-separated types
	scanners := strings.Split(types, ",")
	validCount := 0
	for _, s := range scanners {
		s = strings.TrimSpace(s)
		switch s {
		case "udp":
			udp = true
			validCount++
		case "tcp":
			tcp = true
			validCount++
		case "dot":
			dot = true
			validCount++
		case "doh":
			doh = true
			validCount++
		default:
			if s != "" {
				slog.Warn("unknown scanner type ignored", "type", s, "valid_types", "udp,tcp,dot,doh")
			}
		}
	}

	// If no valid scanners specified, default to all
	if validCount == 0 {
		slog.Warn("no valid scanner types specified, using all scanners")
		return true, true, true, true
	}

	return udp, tcp, dot, doh
}

// parseDetectorTypes parses the detector types string
func parseDetectorTypes(types string) (enabled, dnstt, iodine, dnscat2, dns2tcp bool) {
	types = strings.TrimSpace(strings.ToLower(types))

	// Handle empty or "none" case - tunnel detection disabled by default
	if types == "" || types == "none" {
		return false, false, false, false, false
	}

	// Handle "all" case
	if types == "all" {
		return true, true, true, true, true
	}

	// Parse comma-separated types
	detectors := strings.Split(types, ",")
	validCount := 0
	for _, d := range detectors {
		d = strings.TrimSpace(d)
		switch d {
		case "dnstt":
			dnstt = true
			validCount++
		case "iodine":
			iodine = true
			validCount++
		case "dnscat2":
			dnscat2 = true
			validCount++
		case "dns2tcp":
			dns2tcp = true
			validCount++
		default:
			if d != "" {
				slog.Warn("unknown detector type ignored", "type", d, "valid_types", "dnstt,iodine,dnscat2,dns2tcp")
			}
		}
	}

	// If no valid detectors specified, disable tunnel detection
	if validCount == 0 {
		slog.Warn("no valid detector types specified, disabling tunnel detection")
		return false, false, false, false, false
	}

	// Enable tunnel detection if any valid detector was specified
	enabled = true
	return enabled, dnstt, iodine, dnscat2, dns2tcp
}

func main() {
	// Initialize configuration from environment variables
	config.Init()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
