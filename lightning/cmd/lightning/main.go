package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/velemoonkon/lightning/pkg/input"
	"github.com/velemoonkon/lightning/pkg/output"
	"github.com/velemoonkon/lightning/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
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
	testDomains   string

	// Port scanning
	scanPorts bool

	// Performance
	workers        int
	dnsConcurrency int
	timeout        int
	rateLimit      int
)

var rootCmd = &cobra.Command{
	Use:   "lightning [flags] <target>",
	Short: "Fast DNS scanner with tunnel detection",
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
  lightning 1.1.1.1 --detector all --tunnel-domain tunnel.example.com

  # Use custom test domains for DNS resolution
  lightning 8.8.8.8 --test-domains example.com,test.org`,
	Args: func(cmd *cobra.Command, args []string) error {
		if inputFile == "" && len(args) == 0 {
			return fmt.Errorf("requires either a target argument or --file flag")
		}
		return nil
	},
	RunE: runScan,
}

func init() {
	// Set custom usage template
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
	rootCmd.Flags().StringVar(&testDomains, "test-domains", "chatgpt.com,google.com,microsoft.com", "domains to test for resolution (comma-separated)")

	// Port scanning
	rootCmd.Flags().BoolVar(&scanPorts, "scan-ports", true, "scan common DNS-related ports")

	// Performance tuning
	rootCmd.Flags().IntVarP(&workers, "workers", "w", 100, "number of concurrent IP workers")
	rootCmd.Flags().IntVar(&dnsConcurrency, "dns-concurrency", 4, "max concurrent DNS tests per IP (udp,tcp,dot,doh run in parallel)")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "t", 5, "timeout per IP in seconds")
	rootCmd.Flags().IntVar(&rateLimit, "rate-limit", 1000, "max IPs per second")
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n\nInterrupt received, stopping scan...")
		cancel()
	}()

	// Parse targets
	var ips []net.IP
	var err error

	if inputFile != "" {
		if !quiet {
			fmt.Printf("Reading targets from file: %s\n", inputFile)
		}
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

	if !quiet {
		fmt.Printf("Starting scan of %d IPs...\n\n", len(ips))
	}

	// Parse scanner and detector types
	enableUDP, enableTCP, enableDoT, enableDoH := parseScannerTypes(scannerTypes)
	enableTunnel, enableDNSTT, enableIodine, enableDNScat2, enableDNS2TCP := parseDetectorTypes(detectorTypes)

	// Parse test domains
	domains := parseTestDomains(testDomains)

	// Create scanner config
	config := scanner.Config{
		Workers:         workers,
		DNSConcurrency:  dnsConcurrency,
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
		EnablePortScan:  scanPorts,
		TunnelDomain:    tunnelDomain,
		TestDomains:     domains,
		Verbose:         verbose,
		Quiet:           quiet,
	}

	// Create scanner
	s := scanner.NewScanner(config)

	// Run scan
	startTime := time.Now()
	results, err := s.Scan(ctx, ips)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if !quiet {
		fmt.Printf("\nScan completed in %s\n", time.Since(startTime))
		fmt.Printf("Scanned %d IPs\n\n", len(results))
	}

	// Generate output filename prefix if not specified
	if outputPrefix == "" {
		timestamp := time.Now().Format("20060102_150405")
		if inputFile != "" {
			// Extract base name from file path
			baseName := strings.TrimSuffix(inputFile, ".txt")
			baseName = strings.TrimSuffix(baseName, ".list")
			if idx := strings.LastIndex(baseName, "/"); idx >= 0 {
				baseName = baseName[idx+1:]
			}
			outputPrefix = fmt.Sprintf("lightning_%s_%dips_%s", baseName, len(ips), timestamp)
		} else if len(ips) == 1 {
			// Single IP
			outputPrefix = fmt.Sprintf("lightning_%s_%s", ips[0].String(), timestamp)
		} else if len(args) > 0 && strings.Contains(args[0], "/") {
			// CIDR range
			cidr := strings.ReplaceAll(args[0], "/", "-")
			cidr = strings.ReplaceAll(cidr, ".", "_")
			outputPrefix = fmt.Sprintf("lightning_%s_%dips_%s", cidr, len(ips), timestamp)
		} else {
			// Multiple IPs or other
			outputPrefix = fmt.Sprintf("lightning_scan_%dips_%s", len(ips), timestamp)
		}
	}

	// Parse output formats
	writeJSON, writeMarkdown := parseOutputFormats(outputFormat)

	// Write JSON output
	if writeJSON {
		jsonFile := outputPrefix + ".json"
		if err := output.WriteJSON(results, jsonFile, startTime); err != nil {
			return fmt.Errorf("failed to write JSON: %w", err)
		}
		fmt.Printf("JSON report written to: %s\n", jsonFile)
	}

	// Write Markdown output
	if writeMarkdown {
		mdFile := outputPrefix + ".md"
		if err := output.WriteMarkdown(results, mdFile, startTime); err != nil {
			return fmt.Errorf("failed to write Markdown: %w", err)
		}
		fmt.Printf("Markdown report written to: %s\n", mdFile)
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
	for _, s := range scanners {
		s = strings.TrimSpace(s)
		switch s {
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

	// If any specific detector is mentioned, enable tunnel detection
	enabled = true

	// Parse comma-separated types
	detectors := strings.Split(types, ",")
	for _, d := range detectors {
		d = strings.TrimSpace(d)
		switch d {
		case "dnstt":
			dnstt = true
		case "iodine":
			iodine = true
		case "dnscat2":
			dnscat2 = true
		case "dns2tcp":
			dns2tcp = true
		}
	}

	return enabled, dnstt, iodine, dnscat2, dns2tcp
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
