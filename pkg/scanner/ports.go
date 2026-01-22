package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// Common DNS-related ports
var DNSPorts = []int{
	53,   // DNS (UDP/TCP)
	853,  // DNS over TLS (DoT)
	443,  // DNS over HTTPS (DoH) / HTTPS
	5353, // mDNS
	8053, // Alternative DNS port
}

// ScanPort checks if a TCP port is open
func ScanPort(ctx context.Context, ip string, port int, timeout time.Duration) bool {
	address := fmt.Sprintf("%s:%d", ip, port)

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

// ScanPorts scans multiple ports concurrently
func ScanPorts(ctx context.Context, ip string, ports []int, timeout time.Duration) []int {
	var (
		openPorts []int
		mu        sync.Mutex
		wg        sync.WaitGroup
	)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			if ScanPort(ctx, ip, p, timeout) {
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return openPorts
}

// ScanDNSPorts scans common DNS-related ports
func ScanDNSPorts(ctx context.Context, ip string) []int {
	return ScanPorts(ctx, ip, DNSPorts, 2*time.Second)
}
