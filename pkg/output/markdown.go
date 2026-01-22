package output

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/velemoonkon/lightning/pkg/scanner"
)

// WriteMarkdown writes scan results to a Markdown file
func WriteMarkdown(results []*scanner.ScanResult, filename string, startTime time.Time) error {
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	var md strings.Builder

	// Header
	md.WriteString("# Lightning Report\n\n")
	md.WriteString(fmt.Sprintf("**Scan Date:** %s\n\n", startTime.Format(time.RFC3339)))
	md.WriteString(fmt.Sprintf("**Duration:** %s\n\n", duration))
	md.WriteString(fmt.Sprintf("**Total IPs Scanned:** %d\n\n", len(results)))

	// Summary
	summary := calculateSummary(results)
	md.WriteString("## Summary\n\n")
	md.WriteString(fmt.Sprintf("- **DNS Responders:** %d\n", summary.DNSResponders))
	md.WriteString(fmt.Sprintf("- **Recursive Servers:** %d\n", summary.RecursiveServers))
	md.WriteString(fmt.Sprintf("- **DoT Servers:** %d\n", summary.DoTServers))
	md.WriteString(fmt.Sprintf("- **DoH Servers:** %d\n", summary.DoHServers))
	md.WriteString(fmt.Sprintf("- **Tunnels Detected:** %d\n", summary.TunnelsDetected))
	if summary.TunnelsDetected > 0 {
		md.WriteString(fmt.Sprintf("  - DNSTT: %d\n", summary.DNSTTCount))
		md.WriteString(fmt.Sprintf("  - Iodine: %d\n", summary.IodineCount))
		md.WriteString(fmt.Sprintf("  - DNScat2: %d\n", summary.DNScat2Count))
		md.WriteString(fmt.Sprintf("  - DNS2TCP: %d\n", summary.DNS2TCPCount))
	}
	md.WriteString("\n")

	// DNS Responders
	md.WriteString("## DNS Responders\n\n")
	md.WriteString("| IP | Type | UDP | TCP | DoT | DoH | Endpoint |\n")
	md.WriteString("|---|------|-----|-----|-----|-----|----------|\n")

	for _, result := range results {
		if result.DNSResult != nil && result.DNSResult.RespondsToQueries {
			ip := result.IP
			serverType := result.DNSResult.DNSServerType
			udp := boolToSymbol(result.DNSResult.UDPPortOpen)
			tcp := boolToSymbol(result.DNSResult.SupportsTCP)
			dot := boolToSymbol(result.DNSResult.SupportsDoT)
			doh := boolToSymbol(result.DNSResult.SupportsDoH)
			endpoint := result.DNSResult.DoHEndpoint
			if endpoint == "" {
				endpoint = "-"
			}

			md.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s |\n",
				ip, serverType, udp, tcp, dot, doh, endpoint))
		}
	}
	md.WriteString("\n")

	// Tunnel Detections
	if summary.TunnelsDetected > 0 {
		md.WriteString("## Detected Tunnels\n\n")
		md.WriteString("| IP | Tunnel Type | Confidence | Indicators |\n")
		md.WriteString("|---|-------------|------------|------------|\n")

		for _, result := range results {
			if result.TunnelResult != nil && result.TunnelResult.IsTunnel {
				ip := result.IP
				tunnelType := result.TunnelResult.TunnelType
				confidence := result.TunnelResult.Confidence
				indicators := strings.Join(result.TunnelResult.AllIndicators, ", ")

				md.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
					ip, tunnelType, confidence, indicators))
			}
		}
		md.WriteString("\n")
	}

	// DoT Servers Detail
	if summary.DoTServers > 0 {
		md.WriteString("## DNS over TLS (DoT) Servers\n\n")
		md.WriteString("| IP | Response Time | Status |\n")
		md.WriteString("|---|---------------|--------|\n")

		for _, result := range results {
			if result.DNSResult != nil && result.DNSResult.SupportsDoT {
				ip := result.IP
				rtt := fmt.Sprintf("%d ms", result.DNSResult.DoTResponseTime.Milliseconds())
				status := "✓ Working"
				if result.DNSResult.DoTError != "" {
					status = result.DNSResult.DoTError
				}

				md.WriteString(fmt.Sprintf("| %s | %s | %s |\n", ip, rtt, status))
			}
		}
		md.WriteString("\n")
	}

	// DoH Servers Detail
	if summary.DoHServers > 0 {
		md.WriteString("## DNS over HTTPS (DoH) Servers\n\n")
		md.WriteString("| IP | Endpoint | Response Time | Status |\n")
		md.WriteString("|---|----------|---------------|--------|\n")

		for _, result := range results {
			if result.DNSResult != nil && result.DNSResult.SupportsDoH {
				ip := result.IP
				endpoint := result.DNSResult.DoHEndpoint
				rtt := fmt.Sprintf("%d ms", result.DNSResult.DoHResponseTime.Milliseconds())
				status := "✓ Working"
				if result.DNSResult.DoHError != "" {
					status = result.DNSResult.DoHError
				}

				md.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", ip, endpoint, rtt, status))
			}
		}
		md.WriteString("\n")
	}

	// Write to file
	if err := os.WriteFile(filename, []byte(md.String()), 0644); err != nil {
		return fmt.Errorf("failed to write Markdown file: %w", err)
	}

	return nil
}

// boolToSymbol converts boolean to checkmark/cross symbol
func boolToSymbol(b bool) string {
	if b {
		return "✓"
	}
	return "✗"
}
