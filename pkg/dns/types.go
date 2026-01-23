package dns

import (
	"fmt"
	"time"
)

// Milliseconds represents a duration in milliseconds for JSON encoding
type Milliseconds int64

// MarshalJSON implements json.Marshaler for proper millisecond encoding
func (m Milliseconds) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%d", m)), nil
}

// TestResult contains results from all DNS tests for a single IP
type TestResult struct {
	IP                   string        `json:"ip"`
	UDPPortOpen          bool          `json:"udp_port_open"`
	TCPPortOpen          bool          `json:"tcp_port_open"`
	RespondsToQueries    bool          `json:"responds_to_queries"`
	SupportsRecursion    bool          `json:"supports_recursion"`
	SupportsTCP          bool          `json:"supports_tcp"`
	SupportsEDNS         bool          `json:"supports_edns"`
	SupportsDoT          bool          `json:"supports_dot"`
	DoTResponseTime      time.Duration `json:"-"` // Internal use only
	DoTResponseTimeMs    Milliseconds  `json:"dot_response_time_ms"`
	DoTError             string        `json:"dot_error,omitzero"`
	SupportsDoH          bool          `json:"supports_doh"`
	DoHEndpoint          string        `json:"doh_endpoint,omitzero"`
	DoHResponseTime      time.Duration `json:"-"` // Internal use only
	DoHResponseTimeMs    Milliseconds  `json:"doh_response_time_ms"`
	DoHError             string        `json:"doh_error,omitzero"`
	TestDomainsResolved  []string      `json:"test_domains_resolved"`
	TestDomainsFailed    []string      `json:"test_domains_failed"`
	DNSServerType        string        `json:"dns_server_type"` // recursive/authoritative/limited/tunnel-suspect
	Error                string        `json:"error,omitzero"`
}

// QueryOptions contains options for DNS queries
type QueryOptions struct {
	Timeout       time.Duration
	RecursionDesired bool
	UseEDNS       bool
	EDNSBufferSize uint16
}

// DefaultQueryOptions returns default query options
func DefaultQueryOptions() QueryOptions {
	return QueryOptions{
		Timeout:       3 * time.Second,
		RecursionDesired: true,
		UseEDNS:       true,
		EDNSBufferSize: 4096,
	}
}
