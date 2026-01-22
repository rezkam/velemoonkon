package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// QueryTCP performs a TCP DNS query
func QueryTCP(ctx context.Context, server string, domain string, qtype uint16, opts QueryOptions) (*dns.Msg, time.Duration, error) {
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

	// Create DNS client with TCP
	client := &dns.Client{
		Net:     "tcp",
		Timeout: opts.Timeout,
	}

	// Ensure server has port
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}

	// Perform query with context
	resp, rtt, err := client.ExchangeContext(ctx, msg, server)
	if err != nil {
		return nil, 0, fmt.Errorf("TCP query failed: %w", err)
	}

	if resp == nil {
		return nil, 0, fmt.Errorf("empty response")
	}

	return resp, rtt, nil
}

// TestTCPDNS tests TCP DNS functionality for a server
func TestTCPDNS(ctx context.Context, server string) (bool, error) {
	// Test TCP port 53
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(server, "53"), 3*time.Second)
	if err != nil {
		return false, nil
	}
	defer conn.Close()

	// Try a simple query
	opts := DefaultQueryOptions()
	resp, _, err := QueryTCP(ctx, server, "google.com", dns.TypeA, opts)
	if err != nil {
		return false, nil
	}

	return resp.Rcode == dns.RcodeSuccess, nil
}

// QueryTCPRaw performs a raw TCP DNS query with custom message
func QueryTCPRaw(ctx context.Context, server string, msg *dns.Msg, timeout time.Duration) (*dns.Msg, time.Duration, error) {
	client := &dns.Client{
		Net:     "tcp",
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
