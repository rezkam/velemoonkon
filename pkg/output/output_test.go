package output

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/velemoonkon/lightning/pkg/scanner"
)

func TestNewWriter(t *testing.T) {
	// Test stdout
	w, err := NewWriter("-")
	if err != nil {
		t.Fatalf("Failed to create stdout writer: %v", err)
	}
	w.Close()

	// Test empty string (should be stdout)
	w, err = NewWriter("")
	if err != nil {
		t.Fatalf("Failed to create writer with empty string: %v", err)
	}
	w.Close()
}

func TestNewWriterFile(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.jsonl")

	w, err := NewWriter(tmpFile)
	if err != nil {
		t.Fatalf("Failed to create file writer: %v", err)
	}
	defer w.Close()

	// Verify file was created
	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Error("Expected file to be created")
	}
}

func TestWriterWrite(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriterFromWriter(&buf)

	result := &scanner.ScanResult{
		IP:       "1.2.3.4",
		ScanTime: 100,
	}

	err := w.Write(result)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	err = w.Flush()
	if err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "1.2.3.4") {
		t.Errorf("Expected output to contain IP, got: %s", output)
	}
	if !strings.HasSuffix(output, "\n") {
		t.Error("Expected output to end with newline")
	}

	// Verify it's valid JSON
	var parsed scanner.ScanResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}
	if parsed.IP != "1.2.3.4" {
		t.Errorf("Parsed IP mismatch: got %s", parsed.IP)
	}
}

func TestWriterMultipleWrites(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriterFromWriter(&buf)

	for i := 0; i < 5; i++ {
		result := &scanner.ScanResult{
			IP:       "10.0.0.1",
			ScanTime: int64(i * 100),
		}
		if err := w.Write(result); err != nil {
			t.Fatalf("Write %d failed: %v", i, err)
		}
	}

	w.Flush()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 5 {
		t.Errorf("Expected 5 lines, got %d", len(lines))
	}

	// Verify each line is valid JSON
	for i, line := range lines {
		var parsed scanner.ScanResult
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			t.Errorf("Line %d is not valid JSON: %v", i, err)
		}
	}
}

func TestWriterCount(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriterFromWriter(&buf)

	if w.Count() != 0 {
		t.Errorf("Expected initial count 0, got %d", w.Count())
	}

	for i := 0; i < 10; i++ {
		w.Write(&scanner.ScanResult{IP: "10.0.0.1"})
	}

	if w.Count() != 10 {
		t.Errorf("Expected count 10, got %d", w.Count())
	}
}

func TestParquetWriter(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.parquet")

	pw, err := NewParquetWriter(tmpFile)
	if err != nil {
		t.Fatalf("Failed to create parquet writer: %v", err)
	}

	result := &scanner.ScanResult{
		IP:       "8.8.8.8",
		ScanTime: 500,
	}

	err = pw.Write(result)
	if err != nil {
		t.Fatalf("Parquet write failed: %v", err)
	}

	err = pw.Close()
	if err != nil {
		t.Fatalf("Parquet close failed: %v", err)
	}

	// Verify file was created and has content
	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("Failed to stat parquet file: %v", err)
	}
	if info.Size() == 0 {
		t.Error("Parquet file is empty")
	}

	// Verify it's a valid parquet file (magic bytes)
	data, _ := os.ReadFile(tmpFile)
	if len(data) < 4 || string(data[:4]) != "PAR1" {
		t.Error("File does not have Parquet magic bytes")
	}
}

func TestParquetWriterMultiple(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "multi.parquet")

	pw, err := NewParquetWriter(tmpFile)
	if err != nil {
		t.Fatalf("Failed to create parquet writer: %v", err)
	}

	// Write multiple results
	for i := 0; i < 100; i++ {
		result := &scanner.ScanResult{
			IP:        "10.0.0.1",
			ScanTime:  int64(i * 10),
			OpenPorts: []int{53, 443},
		}
		if err := pw.Write(result); err != nil {
			t.Fatalf("Write %d failed: %v", i, err)
		}
	}

	if pw.Count() != 100 {
		t.Errorf("Expected count 100, got %d", pw.Count())
	}

	pw.Close()

	// Verify file has reasonable size (should be compressed)
	info, _ := os.Stat(tmpFile)
	t.Logf("Parquet file size for 100 rows: %d bytes", info.Size())
}

func TestScanResultToParquetRow(t *testing.T) {
	result := &scanner.ScanResult{
		IP:         "192.168.1.1",
		ScanTime:   1234,
		OpenPorts:  []int{53, 443, 853},
		ScanErrors: []string{"error1", "error2"},
	}

	row := scanResultToParquetRow(result)

	if row.IP != "192.168.1.1" {
		t.Errorf("Expected IP 192.168.1.1, got %s", row.IP)
	}
	if row.ScanTimeMs != 1234 {
		t.Errorf("Expected ScanTimeMs 1234, got %d", row.ScanTimeMs)
	}
	if row.OpenPorts != "53,443,853" {
		t.Errorf("Expected OpenPorts '53,443,853', got '%s'", row.OpenPorts)
	}
	if !row.HasErrors {
		t.Error("Expected HasErrors to be true")
	}
	if row.ScanErrors != "error1; error2" {
		t.Errorf("Expected ScanErrors 'error1; error2', got '%s'", row.ScanErrors)
	}
}

func TestScanResultToParquetRowEmpty(t *testing.T) {
	result := &scanner.ScanResult{
		IP: "10.0.0.1",
	}

	row := scanResultToParquetRow(result)

	if row.IP != "10.0.0.1" {
		t.Errorf("Expected IP 10.0.0.1, got %s", row.IP)
	}
	if row.OpenPorts != "" {
		t.Errorf("Expected empty OpenPorts, got '%s'", row.OpenPorts)
	}
	if row.HasErrors {
		t.Error("Expected HasErrors to be false")
	}
}
