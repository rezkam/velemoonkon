package output

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/velemoonkon/lightning/pkg/scanner"
)

// JSONReport contains the full scan results in JSON format
type JSONReport struct {
	ScanInfo ScanInfo               `json:"scan_info"`
	Results  []*scanner.ScanResult  `json:"results"`
	Summary  Summary                `json:"summary"`
}

// ScanInfo contains metadata about the scan
type ScanInfo struct {
	StartTime   string `json:"start_time"`
	EndTime     string `json:"end_time"`
	TotalIPs    int    `json:"total_ips"`
	Duration    string `json:"duration"`
	ScannerVersion string `json:"scanner_version"`
}

// Summary contains summary statistics
type Summary struct {
	TotalScanned      int `json:"total_scanned"`
	DNSResponders     int `json:"dns_responders"`
	RecursiveServers  int `json:"recursive_servers"`
	DoTServers        int `json:"dot_servers"`
	DoHServers        int `json:"doh_servers"`
	TunnelsDetected   int `json:"tunnels_detected"`
	DNSTTCount        int `json:"dnstt_count"`
	IodineCount       int `json:"iodine_count"`
	DNScat2Count      int `json:"dnscat2_count"`
	DNS2TCPCount      int `json:"dns2tcp_count"`
}

// WriteJSON writes scan results to a JSON file
func WriteJSON(results []*scanner.ScanResult, filename string, startTime time.Time) error {
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	// Calculate summary
	summary := calculateSummary(results)

	report := JSONReport{
		ScanInfo: ScanInfo{
			StartTime:   startTime.Format(time.RFC3339),
			EndTime:     endTime.Format(time.RFC3339),
			TotalIPs:    len(results),
			Duration:    duration.String(),
			ScannerVersion: "1.0.0",
		},
		Results: results,
		Summary: summary,
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	return nil
}

// calculateSummary generates summary statistics from results
func calculateSummary(results []*scanner.ScanResult) Summary {
	summary := Summary{
		TotalScanned: len(results),
	}

	for _, result := range results {
		if result.DNSResult != nil {
			if result.DNSResult.RespondsToQueries {
				summary.DNSResponders++
			}
			if result.DNSResult.SupportsRecursion {
				summary.RecursiveServers++
			}
			if result.DNSResult.SupportsDoT {
				summary.DoTServers++
			}
			if result.DNSResult.SupportsDoH {
				summary.DoHServers++
			}
		}

		if result.TunnelResult != nil && result.TunnelResult.IsTunnel {
			summary.TunnelsDetected++
			switch result.TunnelResult.TunnelType {
			case "dnstt":
				summary.DNSTTCount++
			case "iodine":
				summary.IodineCount++
			case "dnscat2":
				summary.DNScat2Count++
			case "dns2tcp":
				summary.DNS2TCPCount++
			}
		}
	}

	return summary
}
