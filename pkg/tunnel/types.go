package tunnel

// Result contains DNS tunnel detection results
type Result struct {
	IP              string      `json:"ip"`
	IsTunnel        bool        `json:"is_tunnel"`
	TunnelType      string      `json:"tunnel_type,omitzero"`      // dnstt/iodine/dnscat2/dns2tcp
	Confidence      string      `json:"confidence,omitzero"`       // high/medium/low
	RespondsToDNS   bool        `json:"responds_to_dns"`
	IsRecursive     bool        `json:"is_recursive"`
	DNSTTIndicators *DNSTTIndicators `json:"dnstt_indicators,omitzero"`
	IodineIndicators *IodineIndicators `json:"iodine_indicators,omitzero"`
	DNScat2Indicators *DNScat2Indicators `json:"dnscat2_indicators,omitzero"`
	DNS2TCPIndicators *DNS2TCPIndicators `json:"dns2tcp_indicators,omitzero"`
	AllIndicators   []string    `json:"all_indicators,omitzero"`
	Error           string      `json:"error,omitzero"`
}

// DNSTTIndicators contains DNSTT-specific detection indicators
type DNSTTIndicators struct {
	HasAuthoritativeAnswer bool    `json:"has_authoritative_answer"`
	RespondsToBase32       bool    `json:"responds_to_base32"`
	TXTRecordFound         bool    `json:"txt_record_found"`
	HasBinaryData          bool    `json:"has_binary_data"`
	TTLEquals60            bool    `json:"ttl_equals_60"`
	UsesEDNS               bool    `json:"uses_edns"`
	Entropy                float64 `json:"entropy"`
}

// IodineIndicators contains Iodine-specific detection indicators
type IodineIndicators struct {
	RespondsToNULL         bool    `json:"responds_to_null"`
	HasVersionHandshake    bool    `json:"has_version_handshake"`
	Base128Detected        bool    `json:"base128_detected"`
	HighEntropy            bool    `json:"high_entropy"`
	Entropy                float64 `json:"entropy"`
	HasAuthoritativeAnswer bool    `json:"has_authoritative_answer"`
}

// DNScat2Indicators contains DNScat2-specific detection indicators
type DNScat2Indicators struct {
	MultiTypeResponses     bool    `json:"multi_type_responses"`
	HexEncodedData         bool    `json:"hex_encoded_data"`
	HighEntropy            bool    `json:"high_entropy"`
	Entropy                float64 `json:"entropy"`
	HasAuthoritativeAnswer bool    `json:"has_authoritative_answer"`
	ConsistentResponses    bool    `json:"consistent_responses"`
}

// DNS2TCPIndicators contains DNS2TCP-specific detection indicators
type DNS2TCPIndicators struct {
	TXTRecordFound bool `json:"txt_record_found"`
	KEYRecordFound bool `json:"key_record_found"`
	RespondsToTXT  bool `json:"responds_to_txt"`
	RespondsToKEY  bool `json:"responds_to_key"`
}

// DetectionOptions contains options for tunnel detection
type DetectionOptions struct {
	TestDNSTT   bool
	TestIodine  bool
	TestDNScat2 bool
	TestDNS2TCP bool
	Domain      string // Optional: specific domain to test
}

// DefaultDetectionOptions returns default detection options
func DefaultDetectionOptions() DetectionOptions {
	return DetectionOptions{
		TestDNSTT:   true,
		TestIodine:  true,
		TestDNScat2: true,
		TestDNS2TCP: true,
		Domain:      "",
	}
}
