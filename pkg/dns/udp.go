package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/velemoonkon/lightning/pkg/config"
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

	// Optional: Validate response ID matches request ID (disabled by default for speed)
	// Enable with LIGHTNING_DNS_VALIDATE_RESPONSE_ID=true for security-focused scanning
	if config.DNS.ValidateResponseID && resp.Id != msg.Id {
		return nil, 0, fmt.Errorf("DNS response ID mismatch: expected %d, got %d (possible spoofing)", msg.Id, resp.Id)
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

	// Test basic queries (connection is tested implicitly via QueryUDP timeout)
	for _, domain := range testDomains {
		resp, _, err := QueryUDP(ctx, server, domain, dns.TypeA, opts)
		if err != nil {
			result.TestDomainsFailed = append(result.TestDomainsFailed, domain)
			continue
		}

		if resp.Rcode == dns.RcodeSuccess {
			result.UDPPortOpen = true // Port is open if we got a valid DNS response
			result.RespondsToQueries = true
			if len(resp.Answer) > 0 {
				result.TestDomainsResolved = append(result.TestDomainsResolved, domain)
			}

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

	// Determine server type based on recursion support
	if result.RespondsToQueries {
		if result.SupportsRecursion {
			result.DNSServerType = "recursive"
		} else {
			result.DNSServerType = "authoritative"
		}
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

	// Optional: Validate response ID (same as QueryUDP)
	if config.DNS.ValidateResponseID && resp != nil && resp.Id != msg.Id {
		return nil, 0, fmt.Errorf("DNS response ID mismatch: expected %d, got %d (possible spoofing)", msg.Id, resp.Id)
	}

	return resp, rtt, nil
}
