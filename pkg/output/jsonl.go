package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/velemoonkon/lightning/pkg/scanner"
)

// Writer writes scan results as JSONL (JSON Lines) - one JSON object per line
// This format is ideal for streaming, piping to jq, and processing large datasets
type Writer struct {
	file   *os.File
	writer *bufio.Writer
	count  int
}

// NewWriter creates a JSONL writer to the specified file
// Use "-" for stdout
func NewWriter(filename string) (*Writer, error) {
	var file *os.File
	var err error

	if filename == "-" || filename == "" {
		file = os.Stdout
	} else {
		file, err = os.Create(filename)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
	}

	return &Writer{
		file:   file,
		writer: bufio.NewWriterSize(file, 64*1024), // 64KB buffer
	}, nil
}

// NewWriterFromWriter creates a JSONL writer from an existing io.Writer
// Useful for testing or custom output destinations
func NewWriterFromWriter(w io.Writer) *Writer {
	return &Writer{
		writer: bufio.NewWriterSize(w, 64*1024),
	}
}

// Write writes a single scan result as a JSON line
func (w *Writer) Write(result *scanner.ScanResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	if _, err := w.writer.Write(data); err != nil {
		return err
	}
	if err := w.writer.WriteByte('\n'); err != nil {
		return err
	}

	w.count++

	// Flush every 100 results for responsive output
	if w.count%100 == 0 {
		return w.writer.Flush()
	}

	return nil
}

// Flush forces any buffered data to be written
func (w *Writer) Flush() error {
	return w.writer.Flush()
}

// Close flushes and closes the writer
func (w *Writer) Close() error {
	if err := w.writer.Flush(); err != nil {
		return err
	}

	// Don't close stdout
	if w.file != nil && w.file != os.Stdout {
		return w.file.Close()
	}

	return nil
}

// Count returns the number of results written
func (w *Writer) Count() int {
	return w.count
}
