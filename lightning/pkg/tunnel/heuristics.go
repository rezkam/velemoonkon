package tunnel

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"math"
	"regexp"
	"strings"
)

// CalculateEntropy calculates Shannon entropy of data
func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	entropy := 0.0
	length := float64(len(data))
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// IsHighEntropy checks if data has entropy above threshold
func IsHighEntropy(data []byte, threshold float64) bool {
	return CalculateEntropy(data) > threshold
}

// DetectEncoding attempts to detect encoding type
func DetectEncoding(data string) string {
	data = strings.TrimSpace(data)
	if data == "" {
		return "none"
	}

	// Check for base32 (A-Z, 2-7, padding =)
	if isBase32(data) {
		if _, err := base32.StdEncoding.DecodeString(data); err == nil {
			return "base32"
		}
	}

	// Check for base64 (A-Z, a-z, 0-9, +, /, padding =)
	if isBase64(data) {
		if _, err := base64.StdEncoding.DecodeString(data); err == nil {
			return "base64"
		}
	}

	// Check for hex (0-9, a-f, A-F)
	if isHex(data) {
		if _, err := hex.DecodeString(data); err == nil {
			return "hex"
		}
	}

	return "unknown"
}

// isBase32 checks if string matches base32 pattern
func isBase32(s string) bool {
	// Base32 uses A-Z and 2-7, with optional = padding
	matched, _ := regexp.MatchString(`^[A-Z2-7]+=*$`, s)
	return matched && len(s) >= 8
}

// isBase64 checks if string matches base64 pattern
func isBase64(s string) bool {
	// Base64 uses A-Z, a-z, 0-9, +, /, with optional = padding
	matched, _ := regexp.MatchString(`^[A-Za-z0-9+/]+=*$`, s)
	return matched && len(s) >= 4 && len(s)%4 == 0
}

// isHex checks if string matches hex pattern
func isHex(s string) bool {
	// Hex uses 0-9, a-f, A-F
	matched, _ := regexp.MatchString(`^[0-9a-fA-F]+$`, s)
	return matched && len(s)%2 == 0
}

// HasBinaryData checks if data contains non-printable binary data
func HasBinaryData(data []byte) bool {
	nonPrintable := 0
	for _, b := range data {
		// Count non-printable characters (excluding common whitespace)
		if b < 32 && b != 9 && b != 10 && b != 13 {
			nonPrintable++
		} else if b > 126 {
			nonPrintable++
		}
	}

	// If more than 10% is non-printable, consider it binary
	return float64(nonPrintable)/float64(len(data)) > 0.1
}

// GenerateRandomSubdomain generates a random-looking subdomain for testing
func GenerateRandomSubdomain(length int) string {
	// Generate base32-like random string
	const charset = "abcdefghijklmnopqrstuvwxyz234567"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[i%len(charset)] // Pseudo-random for testing
	}
	return string(result)
}

// IsBase128 checks if data might be base128 encoded (Iodine)
func IsBase128(data []byte) bool {
	// Base128 uses mostly printable ASCII characters
	for _, b := range data {
		if b < 32 || b > 126 {
			return false
		}
	}
	// Should have high entropy if it's encoded data
	return CalculateEntropy(data) > 4.5
}
