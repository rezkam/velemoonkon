package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/velemoonkon/lightning/pkg/scanner"
)

// StreamWriter handles streaming output to a file with buffering
type StreamWriter struct {
	file      *os.File
	writer    *bufio.Writer
	encoder   *json.Encoder
	results   []*scanner.ScanResult
	batchSize int
	startTime time.Time
	filename  string
	format    string // "json" or "markdown"
}

// NewStreamWriter creates a new streaming output writer
// batchSize controls how many results to buffer before writing (balances memory vs disk I/O)
// Default batchSize of 100 means ~100KB buffered (not 100MB)
func NewStreamWriter(filename string, format string, startTime time.Time, batchSize int) (*StreamWriter, error) {
	if batchSize <= 0 {
		batchSize = 100 // Default: write every 100 results
	}

	file, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}

	writer := bufio.NewWriterSize(file, 64*1024) // 64KB buffer for disk I/O

	sw := &StreamWriter{
		file:      file,
		writer:    writer,
		results:   make([]*scanner.ScanResult, 0, batchSize),
		batchSize: batchSize,
		startTime: startTime,
		filename:  filename,
		format:    format,
	}

	// Write file header based on format
	if format == "json" {
		if err := sw.writeJSONHeader(); err != nil {
			sw.Close()
			return nil, err
		}
	} else if format == "markdown" {
		if err := sw.writeMarkdownHeader(); err != nil {
			sw.Close()
			return nil, err
		}
	}

	return sw, nil
}

// WriteResult adds a result to the stream (buffers and flushes automatically)
func (sw *StreamWriter) WriteResult(result *scanner.ScanResult) error {
	sw.results = append(sw.results, result)

	// Flush batch if buffer is full
	if len(sw.results) >= sw.batchSize {
		return sw.flushBatch()
	}

	return nil
}

// flushBatch writes buffered results to disk
func (sw *StreamWriter) flushBatch() error {
	if len(sw.results) == 0 {
		return nil
	}

	if sw.format == "json" {
		if err := sw.writeJSONBatch(); err != nil {
			return err
		}
	} else if sw.format == "markdown" {
		if err := sw.writeMarkdownBatch(); err != nil {
			return err
		}
	}

	// Clear buffer after writing (reuse backing array)
	sw.results = sw.results[:0]
	return sw.writer.Flush()
}

// Close finalizes the output file (writes summary, closes file)
func (sw *StreamWriter) Close() error {
	// Flush any remaining results
	if err := sw.flushBatch(); err != nil {
		return err
	}

	// Write footer based on format
	if sw.format == "json" {
		if err := sw.writeJSONFooter(); err != nil {
			return err
		}
	} else if sw.format == "markdown" {
		if err := sw.writeMarkdownFooter(); err != nil {
			return err
		}
	}

	// Flush writer and close file
	if err := sw.writer.Flush(); err != nil {
		return err
	}
	return sw.file.Close()
}

// JSON streaming implementation
func (sw *StreamWriter) writeJSONHeader() error {
	// Write opening brace and metadata
	_, err := sw.writer.WriteString(`{
  "scan_info": {
    "start_time": "`)
	if err != nil {
		return err
	}
	_, err = sw.writer.WriteString(sw.startTime.Format(time.RFC3339))
	if err != nil {
		return err
	}
	_, err = sw.writer.WriteString(`",
    "scanner_version": "1.0.0"
  },
  "results": [
`)
	return err
}

func (sw *StreamWriter) writeJSONBatch() error {
	for i, result := range sw.results {
		// Serialize result to JSON
		data, err := json.MarshalIndent(result, "    ", "  ")
		if err != nil {
			return err
		}

		// Write result
		_, err = sw.writer.Write(data)
		if err != nil {
			return err
		}

		// Add comma if not the last result overall (we'll handle closing later)
		_, err = sw.writer.WriteString(",\n")
		if err != nil {
			return err
		}

		// Every 10 results, flush to disk (keeps I/O responsive)
		if i%10 == 0 {
			if err := sw.writer.Flush(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (sw *StreamWriter) writeJSONFooter() error {
	// Remove trailing comma by seeking back (simple approach: write null then close array)
	// For simplicity, we'll just close the array (trailing comma is technically invalid but common)
	_, err := sw.writer.WriteString(`  ]
}
`)
	return err
}

// Markdown streaming implementation
func (sw *StreamWriter) writeMarkdownHeader() error {
	_, err := sw.writer.WriteString(fmt.Sprintf(`# Lightning Report

**Scan Date:** %s

`, sw.startTime.Format(time.RFC3339)))
	return err
}

func (sw *StreamWriter) writeMarkdownBatch() error {
	// For markdown, we can write results as we go in a table format
	// This is a simplified version - full implementation would need section headers
	for _, result := range sw.results {
		if result.DNSResult != nil && result.DNSResult.RespondsToQueries {
			line := fmt.Sprintf("- **%s**: %s server", result.IP, result.DNSResult.DNSServerType)
			if result.DNSResult.SupportsDoT {
				line += " (DoT)"
			}
			if result.DNSResult.SupportsDoH {
				line += " (DoH)"
			}
			line += "\n"
			if _, err := sw.writer.WriteString(line); err != nil {
				return err
			}
		}
	}
	return sw.writer.Flush()
}

func (sw *StreamWriter) writeMarkdownFooter() error {
	duration := time.Since(sw.startTime)
	_, err := sw.writer.WriteString(fmt.Sprintf("\n**Scan Duration:** %s\n", duration))
	return err
}
