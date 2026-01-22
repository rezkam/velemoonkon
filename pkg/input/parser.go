package input

import (
	"bufio"
	"fmt"
	"net"
	"os"
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

// ExpandCIDR expands a CIDR range into individual IPs
func ExpandCIDR(cidr string) ([]net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		// Make a copy of the IP
		newIP := make(net.IP, len(ip))
		copy(newIP, ip)
		ips = append(ips, newIP)
	}

	return ips, nil
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
