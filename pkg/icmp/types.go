package icmp

import "time"

// Result contains ICMP ping results for a single IP
type Result struct {
	IP          string        `json:"ip"`
	Reachable   bool          `json:"reachable"`
	RTT         time.Duration `json:"-"`
	RTTMs       float64       `json:"rtt_ms,omitzero"`
	PacketsSent int           `json:"packets_sent"`
	PacketsRecv int           `json:"packets_recv"`
	PacketLoss  float64       `json:"packet_loss_percent"`
	MinRTT      time.Duration `json:"-"`
	MinRTTMs    float64       `json:"min_rtt_ms,omitzero"`
	MaxRTT      time.Duration `json:"-"`
	MaxRTTMs    float64       `json:"max_rtt_ms,omitzero"`
	AvgRTT      time.Duration `json:"-"`
	AvgRTTMs    float64       `json:"avg_rtt_ms,omitzero"`
	IsIPv6      bool          `json:"is_ipv6"`
	Error       string        `json:"error,omitzero"`
}

// Config contains ICMP scanner configuration
type Config struct {
	Timeout     time.Duration // Timeout per ping attempt
	Count       int           // Number of pings per IP (default 1 for speed)
	Interval    time.Duration // Interval between pings to same IP
	PayloadSize int           // ICMP payload size in bytes
	Privileged  bool          // Use privileged raw sockets (requires root)
}

// DefaultConfig returns default ICMP configuration optimized for speed
func DefaultConfig() Config {
	return Config{
		Timeout:     2 * time.Second,
		Count:       1, // Single ping for maximum speed
		Interval:    0, // No interval for single ping
		PayloadSize: 56,
		Privileged:  true, // Raw sockets for best performance
	}
}

// pingResponse represents an internal ping response
type pingResponse struct {
	ip     string
	rtt    time.Duration
	seq    int
	err    error
	isIPv6 bool
}

// pendingPing tracks an outstanding ping request
type pendingPing struct {
	ip       string
	sentAt   time.Time
	seq      int
	isIPv6   bool
	respChan chan pingResponse
}
