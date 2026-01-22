package tunnel

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		minEntropy float64
		maxEntropy float64
	}{
		{
			name:     "Empty data",
			data:     []byte{},
			minEntropy: 0,
			maxEntropy: 0,
		},
		{
			name:     "Single repeated byte",
			data:     []byte{0x41, 0x41, 0x41, 0x41},
			minEntropy: 0,
			maxEntropy: 0,
		},
		{
			name:     "Random-like data",
			data:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			minEntropy: 2.5,
			maxEntropy: 3.5,
		},
		{
			name:     "High entropy data",
			data:     []byte("aAbBcCdDeEfFgGhH1234567890!@#$%^"),
			minEntropy: 4.5,
			maxEntropy: 6.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := CalculateEntropy(tt.data)
			assert.GreaterOrEqual(t, entropy, tt.minEntropy)
			assert.LessOrEqual(t, entropy, tt.maxEntropy)
		})
	}
}

func TestIsHighEntropy(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		threshold float64
		want      bool
	}{
		{
			name:      "Low entropy data below threshold",
			data:      []byte("aaaaaaaaaa"),
			threshold: 1.0,
			want:      false,
		},
		{
			name:      "High entropy data above threshold",
			data:      []byte("aAbBcCdDeEfF1234!@#$"),
			threshold: 3.0,
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsHighEntropy(tt.data, tt.threshold)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestDetectEncoding(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "Base32 encoded",
			data: "JBSWY3DPEBLW64TMMQ======",
			want: "base32",
		},
		{
			name: "Base64 encoded",
			data: "SGVsbG8gV29ybGQ=",
			want: "base64",
		},
		{
			name: "Hex encoded",
			data: "48656c6c6f",
			want: "hex",
		},
		{
			name: "Plain text",
			data: "Hello World",
			want: "unknown",
		},
		{
			name: "Empty string",
			data: "",
			want: "none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectEncoding(tt.data)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestHasBinaryData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "Plain ASCII text",
			data: []byte("Hello World"),
			want: false,
		},
		{
			name: "Binary data with null bytes",
			data: []byte{0x00, 0x01, 0x02, 0x03, 0x04},
			want: true,
		},
		{
			name: "Mixed text and binary",
			data: []byte("Hello\x00\x01\x02World"),
			want: true,
		},
		{
			name: "High ASCII characters",
			data: []byte{0x80, 0x90, 0xA0, 0xB0},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasBinaryData(tt.data)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestIsBase128(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "High entropy mixed case",
			data: []byte("aAbBcCdDeEfFgGhHiIjJkKlLmM"),
			want: true,
		},
		{
			name: "Low entropy printable",
			data: []byte("aaaaaaaaaaaaaaaa"),
			want: false,
		},
		{
			name: "Contains non-printable",
			data: []byte{0x00, 0x01, 0x41, 0x42},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsBase128(tt.data)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestGenerateRandomSubdomain(t *testing.T) {
	lengths := []int{8, 16, 32, 64}

	for _, length := range lengths {
		t.Run(string(rune(length)), func(t *testing.T) {
			subdomain := GenerateRandomSubdomain(length)
			assert.Equal(t, length, len(subdomain))
			// Should only contain base32 characters
			for _, ch := range subdomain {
				assert.Contains(t, "abcdefghijklmnopqrstuvwxyz234567", string(ch))
			}
		})
	}
}
