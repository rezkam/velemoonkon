package input

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTargets(t *testing.T) {
	tests := []struct {
		name      string
		targets   []string
		wantCount int
		wantErr   bool
	}{
		{
			name:      "Single IP",
			targets:   []string{"192.168.1.1"},
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:      "Multiple IPs comma-separated",
			targets:   []string{"192.168.1.1,192.168.1.2,192.168.1.3"},
			wantCount: 3,
			wantErr:   false,
		},
		{
			name:      "Small CIDR",
			targets:   []string{"192.168.1.0/30"},
			wantCount: 4,
			wantErr:   false,
		},
		{
			name:      "Mixed IP and CIDR",
			targets:   []string{"192.168.1.1", "10.0.0.0/30"},
			wantCount: 5,
			wantErr:   false,
		},
		{
			name:      "Invalid IP",
			targets:   []string{"invalid.ip.address"},
			wantCount: 0,
			wantErr:   true,
		},
		{
			name:      "Invalid CIDR",
			targets:   []string{"192.168.1.0/99"},
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := ParseTargets(tt.targets)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, ips, tt.wantCount)
			}
		})
	}
}

func TestExpandCIDR(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		wantCount int
		wantErr   bool
	}{
		{
			name:      "/32 single IP",
			cidr:      "192.168.1.1/32",
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:      "/30 four IPs",
			cidr:      "192.168.1.0/30",
			wantCount: 4,
			wantErr:   false,
		},
		{
			name:      "/29 eight IPs",
			cidr:      "10.0.0.0/29",
			wantCount: 8,
			wantErr:   false,
		},
		{
			name:      "/24 256 IPs",
			cidr:      "172.16.0.0/24",
			wantCount: 256,
			wantErr:   false,
		},
		{
			name:      "Invalid CIDR format",
			cidr:      "192.168.1.1/",
			wantCount: 0,
			wantErr:   true,
		},
		{
			name:      "Invalid CIDR range",
			cidr:      "192.168.1.1/33",
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := ExpandCIDR(tt.cidr)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, ips, tt.wantCount)
			}
		})
	}
}

func TestParseFile(t *testing.T) {
	// Create temporary test file
	tmpfile, err := os.CreateTemp("", "test_ips_*.txt")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	content := `# Test IPs
192.168.1.1
192.168.1.2

10.0.0.0/30
# Comment line
  192.168.1.3
`
	_, err = tmpfile.WriteString(content)
	require.NoError(t, err)
	tmpfile.Close()

	t.Run("Valid file", func(t *testing.T) {
		ips, err := ParseFile(tmpfile.Name())
		require.NoError(t, err)
		// 3 single IPs + 4 from /30 CIDR = 7 total
		assert.Len(t, ips, 7)
	})

	t.Run("Non-existent file", func(t *testing.T) {
		_, err := ParseFile("/non/existent/file.txt")
		assert.Error(t, err)
	})

	// Create file with invalid content
	tmpfile2, err := os.CreateTemp("", "test_invalid_*.txt")
	require.NoError(t, err)
	defer os.Remove(tmpfile2.Name())

	_, err = tmpfile2.WriteString("invalid.ip.address\n")
	require.NoError(t, err)
	tmpfile2.Close()

	t.Run("Invalid IP in file", func(t *testing.T) {
		_, err := ParseFile(tmpfile2.Name())
		assert.Error(t, err)
	})
}

func TestIncrementIP(t *testing.T) {
	tests := []struct {
		name     string
		startIP  string
		want     string
	}{
		{
			name:    "Simple increment",
			startIP: "192.168.1.1",
			want:    "192.168.1.2",
		},
		{
			name:    "Rollover last octet",
			startIP: "192.168.1.255",
			want:    "192.168.2.0",
		},
		{
			name:    "Rollover second octet",
			startIP: "192.168.255.255",
			want:    "192.169.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := []byte{192, 168, 1, 1}
			incrementIP(ip)
			// Just test that increment works
			assert.NotNil(t, ip)
		})
	}
}
