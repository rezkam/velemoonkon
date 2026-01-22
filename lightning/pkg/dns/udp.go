package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// QueryUDP performs a UDP DNS query
func QueryUDP(ctx context.Context, server string, domain string, qtype uint16, opts QueryOptions) (*dns.Msg, time.Duration, error) {
	// Construct DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.RecursionDesired = opts.RecursionDesired

	// Add EDNS if requested
	if opts.UseEDNS {
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(opts.EDNSBufferSize)
		msg.Extra = append(msg.Extra, opt)
	}

	// Create DNS client
	client := &dns.Client{
		Net:     "udp",
		Timeout: opts.Timeout,
	}

	// Ensure server has port
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}

	// Perform query with context
	start := time.Now()
	resp, rtt, err := client.ExchangeContext(ctx, msg, server)
	if err != nil {
		return nil, 0, fmt.Errorf("UDP query failed: %w", err)
	}

	if resp == nil {
		return nil, 0, fmt.Errorf("empty response")
	}

	_ = start // For potential fallback timing
	return resp, rtt, nil
}

// TestUDPDNS tests UDP DNS functionality for a server
func TestUDPDNS(ctx context.Context, server string) (*TestResult, error) {
	result := &TestResult{
		IP:                server,
		TestDomainsResolved: []string{},
		TestDomainsFailed:   []string{},
	}

	opts := DefaultQueryOptions()
	testDomains := []string{"google.com", "cloudflare.com", "example.com"}

	// Test UDP port 53
	conn, err := net.DialTimeout("udp", net.JoinHostPort(server, "53"), 3*time.Second)
	if err != nil {
		result.UDPPortOpen = false
		result.RespondsToQueries = false
		return result, nil
	}
	conn.Close()
	result.UDPPortOpen = true

	// Test basic query
	for _, domain := range testDomains {
		resp, _, err := QueryUDP(ctx, server, domain, dns.TypeA, opts)
		if err != nil {
			result.TestDomainsFailed = append(result.TestDomainsFailed, domain)
			continue
		}

		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			result.RespondsToQueries = true
			result.TestDomainsResolved = append(result.TestDomainsResolved, domain)

			// Check recursion available
			if resp.RecursionAvailable {
				result.SupportsRecursion = true
			}

			// Check EDNS support
			if resp.IsEdns0() != nil {
				result.SupportsEDNS = true
			}
		}
	}

	// Determine server type
	if result.SupportsRecursion && len(result.TestDomainsResolved) > 0 {
		result.DNSServerType = "recursive"
	} else if result.RespondsToQueries {
		result.DNSServerType = "authoritative"
	} else {
		result.DNSServerType = "limited"
	}

	return result, nil
}

// QueryUDPRaw performs a raw UDP DNS query with custom message
func QueryUDPRaw(ctx context.Context, server string, msg *dns.Msg, timeout time.Duration) (*dns.Msg, time.Duration, error) {
	client := &dns.Client{
		Net:     "udp",
		Timeout: timeout,
	}

	// Ensure server has port
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}

	resp, rtt, err := client.ExchangeContext(ctx, msg, server)
	if err != nil {
		return nil, 0, err
	}

	return resp, rtt, nil
}
