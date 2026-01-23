package input

import (
	"bufio"
	"fmt"
	"iter"
	"net"
	"os"
	"slices"
	"strings"
)

// ParseTargets parses command-line targets (IPs, CIDRs, comma-separated)
func ParseTargets(targets []string) ([]net.IP, error) {
	var ips []net.IP

	for _, target := range targets {
		// Handle comma-separated values
		parts := strings.Split(target, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}

			// Try parsing as CIDR
			if strings.Contains(part, "/") {
				cidrIPs, err := ExpandCIDR(part)
				if err != nil {
					return nil, fmt.Errorf("invalid CIDR %s: %w", part, err)
				}
				ips = append(ips, cidrIPs...)
			} else {
				// Parse as single IP
				ip := net.ParseIP(part)
				if ip == nil {
					return nil, fmt.Errorf("invalid IP address: %s", part)
				}
				ips = append(ips, ip)
			}
		}
	}

	return ips, nil
}

// ParseFile reads IPs and CIDRs from a file (one per line)
func ParseFile(filename string) ([]net.IP, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var ips []net.IP
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Try parsing as CIDR
		if strings.Contains(line, "/") {
			cidrIPs, err := ExpandCIDR(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid CIDR %s: %w", lineNum, line, err)
			}
			ips = append(ips, cidrIPs...)
		} else {
			// Parse as single IP
			ip := net.ParseIP(line)
			if ip == nil {
				return nil, fmt.Errorf("line %d: invalid IP address: %s", lineNum, line)
			}
			ips = append(ips, ip)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return ips, nil
}

// IPRange returns an iterator over IPs in a CIDR range
// This enables lazy evaluation and streaming without allocating the full slice
// Example: for ip := range IPRange("192.168.1.0/24") { process(ip) }
func IPRange(cidr string) (iter.Seq[net.IP], error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	return func(yield func(net.IP) bool) {
		// Start from the first IP in the range
		for currentIP := ip.Mask(ipnet.Mask); ipnet.Contains(currentIP); incrementIP(currentIP) {
			// Make a copy of the IP since we're mutating the original
			newIP := make(net.IP, len(currentIP))
			copy(newIP, currentIP)

			// Yield the IP to the consumer
			// If yield returns false, consumer wants to stop
			if !yield(newIP) {
				return
			}
		}
	}, nil
}

// ExpandCIDR expands a CIDR range into individual IPs
// For streaming use cases, prefer IPRange() to avoid allocating the full slice
func ExpandCIDR(cidr string) ([]net.IP, error) {
	seq, err := IPRange(cidr)
	if err != nil {
		return nil, err
	}
	// slices.Collect efficiently converts iterator to slice with proper preallocation
	return slices.Collect(seq), nil
}

// incrementIP increments an IP address by one
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
