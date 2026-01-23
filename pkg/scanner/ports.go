package scanner

import (
	"context"
	"fmt"
	"iter"
	"net"
	"slices"
	"time"

	"golang.org/x/sync/errgroup"
)

// Common DNS-related ports
var DNSPorts = []int{
	53,   // DNS (UDP/TCP)
	853,  // DNS over TLS (DoT)
	443,  // DNS over HTTPS (DoH) / HTTPS
	5353, // mDNS
	8053, // Alternative DNS port
}

// chanToSeq converts a channel to an iterator for use with slices.Collect
func chanToSeq[T any](ch <-chan T) iter.Seq[T] {
	return func(yield func(T) bool) {
		for v := range ch {
			if !yield(v) {
				return
			}
		}
	}
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

// ScanPorts scans multiple ports concurrently with bounded concurrency
func ScanPorts(ctx context.Context, ip string, ports []int, timeout time.Duration) []int {
	// Use errgroup with limited concurrency to prevent unbounded goroutine fan-out
	g, ctx := errgroup.WithContext(ctx)

	// Limit concurrency to 5 (reasonable for port scanning)
	// This prevents issues if DNSPorts list grows larger
	g.SetLimit(min(5, len(ports)))

	// Channel to collect open ports
	openPortsChan := make(chan int, len(ports))

	for _, port := range ports {
		g.Go(func() error {
			if ScanPort(ctx, ip, port, timeout) {
				openPortsChan <- port
			}
			return nil
		})
	}

	// Wait for all scans to complete
	g.Wait()
	close(openPortsChan)

	// Collect results using slices.Collect with channel iterator
	return slices.Collect(chanToSeq(openPortsChan))
}

// ScanDNSPorts scans common DNS-related ports
func ScanDNSPorts(ctx context.Context, ip string) []int {
	return ScanPorts(ctx, ip, DNSPorts, 2*time.Second)
}
