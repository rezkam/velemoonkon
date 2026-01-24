package icmp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	protocolICMP   = 1
	protocolICMPv6 = 58
)

// Scanner performs high-performance concurrent ICMP scanning
type Scanner struct {
	config   Config
	id       int // ICMP identifier (process-unique)
	seqNum   atomic.Uint32
	mu       sync.Mutex
	pending  map[string]*pendingPing // key: "ip:seq"
	conn4    *icmp.PacketConn
	conn6    *icmp.PacketConn
	closed   atomic.Bool
}

// NewScanner creates a new ICMP scanner
func NewScanner(cfg Config) *Scanner {
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.Count == 0 {
		cfg.Count = 1
	}
	if cfg.PayloadSize == 0 {
		cfg.PayloadSize = 56
	}

	return &Scanner{
		config:  cfg,
		id:      int(time.Now().UnixNano() & 0xffff),
		pending: make(map[string]*pendingPing),
	}
}

// Start initializes the ICMP listener sockets
func (s *Scanner) Start() error {
	var err error

	// IPv4 listener
	network4 := "ip4:icmp"
	if !s.config.Privileged {
		network4 = "udp4"
	}
	s.conn4, err = icmp.ListenPacket(network4, "0.0.0.0")
	if err != nil {
		return fmt.Errorf("failed to listen on IPv4: %w", err)
	}

	// IPv6 listener
	network6 := "ip6:ipv6-icmp"
	if !s.config.Privileged {
		network6 = "udp6"
	}
	s.conn6, err = icmp.ListenPacket(network6, "::")
	if err != nil {
		// IPv6 may not be available, continue with IPv4 only
		s.conn6 = nil
	}

	// Start receiver goroutines
	go s.receiveLoop(s.conn4, false)
	if s.conn6 != nil {
		go s.receiveLoop(s.conn6, true)
	}

	return nil
}

// Stop closes the scanner and releases resources
func (s *Scanner) Stop() {
	if s.closed.Swap(true) {
		return
	}
	if s.conn4 != nil {
		s.conn4.Close()
	}
	if s.conn6 != nil {
		s.conn6.Close()
	}
}

// Ping sends ICMP echo request and waits for reply
func (s *Scanner) Ping(ctx context.Context, ip string) (*Result, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	isIPv6 := parsedIP.To4() == nil
	result := &Result{
		IP:     ip,
		IsIPv6: isIPv6,
	}

	var rtts []time.Duration
	for i := range s.config.Count {
		select {
		case <-ctx.Done():
			result.Error = ctx.Err().Error()
			return result, nil
		default:
		}

		rtt, err := s.sendPing(ctx, ip, isIPv6)
		result.PacketsSent++

		if err == nil {
			result.PacketsRecv++
			rtts = append(rtts, rtt)
		}

		// Wait interval before next ping (if multiple pings)
		if i < s.config.Count-1 && s.config.Interval > 0 {
			select {
			case <-ctx.Done():
				break
			case <-time.After(s.config.Interval):
			}
		}
	}

	// Calculate statistics
	if len(rtts) > 0 {
		result.Reachable = true
		var total time.Duration
		result.MinRTT = rtts[0]
		result.MaxRTT = rtts[0]

		for _, rtt := range rtts {
			total += rtt
			if rtt < result.MinRTT {
				result.MinRTT = rtt
			}
			if rtt > result.MaxRTT {
				result.MaxRTT = rtt
			}
		}

		result.AvgRTT = total / time.Duration(len(rtts))
		result.RTT = result.AvgRTT

		// Set millisecond values for JSON
		result.RTTMs = float64(result.RTT.Microseconds()) / 1000.0
		result.MinRTTMs = float64(result.MinRTT.Microseconds()) / 1000.0
		result.MaxRTTMs = float64(result.MaxRTT.Microseconds()) / 1000.0
		result.AvgRTTMs = float64(result.AvgRTT.Microseconds()) / 1000.0
	}

	if result.PacketsSent > 0 {
		result.PacketLoss = float64(result.PacketsSent-result.PacketsRecv) / float64(result.PacketsSent) * 100
	}

	return result, nil
}

// sendPing sends a single ICMP echo request and waits for reply
func (s *Scanner) sendPing(ctx context.Context, ip string, isIPv6 bool) (time.Duration, error) {
	seq := int(s.seqNum.Add(1) & 0xffff)
	respChan := make(chan pingResponse, 1)

	// Register pending ping
	key := fmt.Sprintf("%s:%d", ip, seq)
	s.mu.Lock()
	s.pending[key] = &pendingPing{
		ip:       ip,
		sentAt:   time.Now(),
		seq:      seq,
		isIPv6:   isIPv6,
		respChan: respChan,
	}
	s.mu.Unlock()

	// Cleanup on return
	defer func() {
		s.mu.Lock()
		delete(s.pending, key)
		s.mu.Unlock()
	}()

	// Build ICMP message
	var msgType icmp.Type
	if isIPv6 {
		msgType = ipv6.ICMPTypeEchoRequest
	} else {
		msgType = ipv4.ICMPTypeEcho
	}

	// Create payload with timestamp
	payload := make([]byte, s.config.PayloadSize)
	binary.BigEndian.PutUint64(payload, uint64(time.Now().UnixNano()))

	msg := &icmp.Message{
		Type: msgType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   s.id,
			Seq:  seq,
			Data: payload,
		},
	}

	var proto int
	if isIPv6 {
		proto = protocolICMPv6
	} else {
		proto = protocolICMP
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	// Select connection
	conn := s.conn4
	if isIPv6 {
		if s.conn6 == nil {
			return 0, fmt.Errorf("IPv6 not available")
		}
		conn = s.conn6
	}

	// Resolve address
	var dst net.Addr
	if s.config.Privileged {
		dst = &net.IPAddr{IP: net.ParseIP(ip)}
	} else {
		dst = &net.UDPAddr{IP: net.ParseIP(ip), Port: proto}
	}

	// Send ping
	_, err = conn.WriteTo(msgBytes, dst)
	if err != nil {
		return 0, fmt.Errorf("failed to send ICMP: %w", err)
	}

	// Wait for response with timeout
	timeout := s.config.Timeout
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case resp := <-respChan:
		if resp.err != nil {
			return 0, resp.err
		}
		return resp.rtt, nil
	case <-time.After(timeout):
		return 0, fmt.Errorf("timeout waiting for reply from %s", ip)
	}
}

// receiveLoop continuously receives ICMP responses
func (s *Scanner) receiveLoop(conn *icmp.PacketConn, isIPv6 bool) {
	buf := make([]byte, 1500)

	var proto int
	if isIPv6 {
		proto = protocolICMPv6
	} else {
		proto = protocolICMP
	}

	for !s.closed.Load() {
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if s.closed.Load() {
				return
			}
			continue
		}

		recvTime := time.Now()

		// Parse ICMP message
		msg, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil {
			continue
		}

		// Check if it's an echo reply
		var isReply bool
		if isIPv6 {
			isReply = msg.Type == ipv6.ICMPTypeEchoReply
		} else {
			isReply = msg.Type == ipv4.ICMPTypeEchoReply
		}

		if !isReply {
			continue
		}

		// Extract echo data
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok || echo.ID != s.id {
			continue
		}

		// Get peer IP
		var peerIP string
		switch addr := peer.(type) {
		case *net.IPAddr:
			peerIP = addr.IP.String()
		case *net.UDPAddr:
			peerIP = addr.IP.String()
		default:
			continue
		}

		// Find pending request
		key := fmt.Sprintf("%s:%d", peerIP, echo.Seq)
		s.mu.Lock()
		pending, ok := s.pending[key]
		s.mu.Unlock()

		if ok && pending.respChan != nil {
			rtt := recvTime.Sub(pending.sentAt)
			select {
			case pending.respChan <- pingResponse{
				ip:     peerIP,
				rtt:    rtt,
				seq:    echo.Seq,
				isIPv6: isIPv6,
			}:
			default:
			}
		}
	}
}

// PingBatch pings multiple IPs concurrently for maximum throughput
// Uses sync.WaitGroup.Go (Go 1.25) for cleaner worker spawning
func (s *Scanner) PingBatch(ctx context.Context, ips []string, workers int) []*Result {
	if workers <= 0 {
		workers = 100
	}

	results := make([]*Result, len(ips))
	var wg sync.WaitGroup
	ipChan := make(chan int, len(ips))

	// Start workers using Go 1.25 pattern
	for range workers {
		wg.Go(func() {
			for idx := range ipChan {
				result, _ := s.Ping(ctx, ips[idx])
				if result == nil {
					result = &Result{IP: ips[idx], Error: "ping failed"}
				}
				results[idx] = result
			}
		})
	}

	// Send work
	for i := range ips {
		select {
		case <-ctx.Done():
			break
		case ipChan <- i:
		}
	}
	close(ipChan)

	wg.Wait()
	return results
}
