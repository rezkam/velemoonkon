package output

import (
	"fmt"
	"os"
	"strings"

	"github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/compress/zstd"
	"github.com/velemoonkon/lightning/pkg/scanner"
)

// ParquetRow is a flattened representation of ScanResult for Parquet storage
// Parquet works best with flat schemas, so we denormalize the nested structures
type ParquetRow struct {
	// Core
	IP         string `parquet:"ip,zstd"`
	ScanTimeMs int64  `parquet:"scan_time_ms"`

	// ICMP results
	ICMPReachable   bool    `parquet:"icmp_reachable"`
	ICMPRttMs       float64 `parquet:"icmp_rtt_ms"`
	ICMPPacketLoss  float64 `parquet:"icmp_packet_loss"`
	ICMPIsIPv6      bool    `parquet:"icmp_is_ipv6"`

	// DNS results
	DNSResponds      bool   `parquet:"dns_responds"`
	DNSServerType    string `parquet:"dns_server_type,zstd,dict"`
	DNSUDPOpen       bool   `parquet:"dns_udp_open"`
	DNSTCPOpen       bool   `parquet:"dns_tcp_open"`
	DNSSupportsDoT   bool   `parquet:"dns_supports_dot"`
	DNSSupportsDoH   bool   `parquet:"dns_supports_doh"`
	DNSDoHEndpoint   string `parquet:"dns_doh_endpoint,zstd"`
	DNSSupportsEDNS  bool   `parquet:"dns_supports_edns"`
	DNSRecursive     bool   `parquet:"dns_recursive"`
	DNSDoTRttMs      int64  `parquet:"dns_dot_rtt_ms"`
	DNSDoHRttMs      int64  `parquet:"dns_doh_rtt_ms"`

	// Tunnel results
	TunnelDetected   bool   `parquet:"tunnel_detected"`
	TunnelType       string `parquet:"tunnel_type,zstd,dict"`
	TunnelConfidence string `parquet:"tunnel_confidence,zstd,dict"`

	// Open ports (stored as comma-separated for simplicity)
	OpenPorts string `parquet:"open_ports,zstd"`

	// Errors
	HasErrors  bool   `parquet:"has_errors"`
	ScanErrors string `parquet:"scan_errors,zstd"`
}

// ParquetWriter writes scan results to a Parquet file
type ParquetWriter struct {
	file   *os.File
	writer *parquet.GenericWriter[ParquetRow]
	count  int
}

// NewParquetWriter creates a Parquet writer with optimized settings
func NewParquetWriter(filename string) (*ParquetWriter, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create parquet file: %w", err)
	}

	// Configure Parquet writer with compression and optimizations
	writer := parquet.NewGenericWriter[ParquetRow](file,
		parquet.Compression(&zstd.Codec{Level: zstd.SpeedDefault}),
		parquet.CreatedBy("lightning", "1.0.0", "go"),
	)

	return &ParquetWriter{
		file:   file,
		writer: writer,
	}, nil
}

// Write converts a ScanResult to a flat ParquetRow and writes it
func (w *ParquetWriter) Write(result *scanner.ScanResult) error {
	row := scanResultToParquetRow(result)

	if _, err := w.writer.Write([]ParquetRow{row}); err != nil {
		return fmt.Errorf("failed to write parquet row: %w", err)
	}

	w.count++
	return nil
}

// Flush forces buffered data to be written
func (w *ParquetWriter) Flush() error {
	return w.writer.Flush()
}

// Close finalizes and closes the Parquet file
func (w *ParquetWriter) Close() error {
	if err := w.writer.Close(); err != nil {
		w.file.Close()
		return fmt.Errorf("failed to close parquet writer: %w", err)
	}
	return w.file.Close()
}

// Count returns the number of rows written
func (w *ParquetWriter) Count() int {
	return w.count
}

// scanResultToParquetRow flattens a ScanResult into a ParquetRow
func scanResultToParquetRow(r *scanner.ScanResult) ParquetRow {
	row := ParquetRow{
		IP:         r.IP,
		ScanTimeMs: r.ScanTime,
	}

	// ICMP
	if r.ICMPResult != nil {
		row.ICMPReachable = r.ICMPResult.Reachable
		row.ICMPRttMs = r.ICMPResult.RTTMs
		row.ICMPPacketLoss = r.ICMPResult.PacketLoss
		row.ICMPIsIPv6 = r.ICMPResult.IsIPv6
	}

	// DNS
	if r.DNSResult != nil {
		row.DNSResponds = r.DNSResult.RespondsToQueries
		row.DNSServerType = r.DNSResult.DNSServerType
		row.DNSUDPOpen = r.DNSResult.UDPPortOpen
		row.DNSTCPOpen = r.DNSResult.TCPPortOpen
		row.DNSSupportsDoT = r.DNSResult.SupportsDoT
		row.DNSSupportsDoH = r.DNSResult.SupportsDoH
		row.DNSDoHEndpoint = r.DNSResult.DoHEndpoint
		row.DNSSupportsEDNS = r.DNSResult.SupportsEDNS
		row.DNSRecursive = r.DNSResult.SupportsRecursion
		row.DNSDoTRttMs = r.DNSResult.DoTResponseTime.Milliseconds()
		row.DNSDoHRttMs = r.DNSResult.DoHResponseTime.Milliseconds()
	}

	// Tunnel
	if r.TunnelResult != nil {
		row.TunnelDetected = r.TunnelResult.IsTunnel
		row.TunnelType = r.TunnelResult.TunnelType
		row.TunnelConfidence = r.TunnelResult.Confidence
	}

	// Open ports as comma-separated string
	if len(r.OpenPorts) > 0 {
		ports := make([]string, len(r.OpenPorts))
		for i, p := range r.OpenPorts {
			ports[i] = fmt.Sprintf("%d", p)
		}
		row.OpenPorts = strings.Join(ports, ",")
	}

	// Errors
	if len(r.ScanErrors) > 0 {
		row.HasErrors = true
		row.ScanErrors = strings.Join(r.ScanErrors, "; ")
	}

	return row
}
